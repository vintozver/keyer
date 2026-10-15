import datetime
import importlib.util
from pathlib import Path
import ssl
import unittest
from unittest import mock

import jwt
import yaml
import yarl
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa


CONFIG = {
    'title1': 'Premises',
    'title2': 'Access control',
    'control': {
        'unit_id': '0123456789abcdef01234567',
        'kid': 'primary',
        'endpoint': 'control.example.com',
        'certificate': '/etc/keyer/unit.crt',
        'privatekey': '/etc/keyer/unit.key',
    },
}

with mock.patch('builtins.open', mock.mock_open(read_data=yaml.safe_dump(CONFIG))):
    from src import storage


class ConfigTests(unittest.TestCase):
    def load_config(self, config):
        path = Path(__file__).resolve().parents[1] / 'src' / 'config.py'
        spec = importlib.util.spec_from_file_location('test_config', path)
        module = importlib.util.module_from_spec(spec)
        with mock.patch('builtins.open', mock.mock_open(read_data=config)) as open_file:
            spec.loader.exec_module(module)
        open_file.assert_called_once_with('config.yaml', 'rt', encoding='utf-8')
        return module

    def test_yaml_settings_and_defaults(self):
        config = self.load_config(yaml.safe_dump(CONFIG))
        self.assertEqual(config.title1, 'Premises')
        self.assertEqual(config.title2, 'Access control')
        self.assertFalse(config.local_storage)
        self.assertFalse(config.validate_sig_mifare_classic_ev1)
        self.assertEqual(config.unit_id, CONFIG['control']['unit_id'])
        self.assertEqual(config.kid, CONFIG['control']['kid'])
        self.assertEqual(config.control_endpoint, CONFIG['control']['endpoint'])
        self.assertEqual(config.control_certificate, CONFIG['control']['certificate'])
        self.assertEqual(config.control_privatekey, CONFIG['control']['privatekey'])

    def test_explicit_boolean_options(self):
        config = self.load_config(yaml.safe_dump({
            **CONFIG, 'local_storage': True, 'validate_sig_mifare_classic_ev1': True,
        }))
        self.assertTrue(config.local_storage)
        self.assertTrue(config.validate_sig_mifare_classic_ev1)

    def test_quoted_booleans_are_rejected(self):
        for name in ('local_storage', 'validate_sig_mifare_classic_ev1'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.load_config(yaml.safe_dump({**CONFIG, name: 'false'}))

    def test_identity_headers_must_be_strings(self):
        for name in ('unit_id', 'kid'):
            for value in (None, '', 123):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    self.load_config(yaml.safe_dump({
                        **CONFIG, 'control': {**CONFIG['control'], name: value},
                    }))

    def test_identity_settings_are_required_under_control(self):
        for name in ('unit_id', 'kid'):
            config = {**CONFIG, name: CONFIG['control'][name], 'control': dict(CONFIG['control'])}
            del config['control'][name]
            with self.subTest(name=name), self.assertRaises(KeyError):
                self.load_config(yaml.safe_dump(config))

    def test_unsafe_yaml_is_rejected(self):
        with self.assertRaises(yaml.constructor.ConstructorError):
            self.load_config('!!python/object/apply:builtins.dict []')


class CertificateAlgorithmTests(unittest.TestCase):
    @staticmethod
    def certificate(key, issuer_key=None):
        issuer_key = issuer_key or key
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'keyer test')])
        now = datetime.datetime.now(tz=datetime.UTC)
        algorithm = None if isinstance(
            issuer_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey),
        ) else hashes.SHA256()
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(issuer_key, algorithm)
            .public_bytes(serialization.Encoding.PEM)
        )

    def test_supported_certificate_keys_produce_verifiable_tokens(self):
        cases = (
            (rsa.generate_private_key(public_exponent=65537, key_size=2048), 'RS256'),
            (ec.generate_private_key(ec.SECP256R1()), 'ES256'),
            (ec.generate_private_key(ec.SECP384R1()), 'ES384'),
            (ec.generate_private_key(ec.SECP521R1()), 'ES512'),
            (ed25519.Ed25519PrivateKey.generate(), 'EdDSA'),
            (ed448.Ed448PrivateKey.generate(), 'EdDSA'),
        )
        for key, expected in cases:
            with self.subTest(key=type(key).__name__, algorithm=expected):
                algorithm = storage._certificate_algorithm(self.certificate(key))
                self.assertEqual(algorithm, expected)
                token = jwt.encode({}, key, algorithm=algorithm)
                self.assertEqual(jwt.decode(token, key.public_key(), algorithms=[expected]), {})

    def test_certificate_subject_key_not_issuer_signature_determines_algorithm(self):
        key = ec.generate_private_key(ec.SECP384R1())
        issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assertEqual(storage._certificate_algorithm(self.certificate(key, issuer)), 'ES384')

    def test_unsupported_keys_and_curves_are_rejected(self):
        for key in (
            dsa.generate_private_key(key_size=2048),
            ec.generate_private_key(ec.SECP256K1()),
        ):
            with self.subTest(key=type(key).__name__), self.assertRaises(ValueError):
                storage._certificate_algorithm(self.certificate(key))

    def test_invalid_certificate_is_rejected(self):
        with self.assertRaises(ValueError):
            storage._certificate_algorithm(b'not a certificate')


class RemoteHttpTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private_key = cls.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def setUp(self):
        self.remote = object.__new__(storage.RemoteHttp)
        self.remote._private_key = self.private_key
        self.remote._algorithm = 'RS256'
        self.session = mock.MagicMock()
        self.response = mock.AsyncMock()
        self.response.status = 200
        self.response.read.return_value = b'{"users": {}, "issued_cards": {}, "revoked_cards": {}}'
        self.session.request.return_value.__aenter__.return_value = self.response
        self.url = yarl.URL('https://control.example.com/config')
        self.ssl_ctx = ssl.create_default_context()

    async def fetch(self):
        return await self.remote._fetch_once(self.session, self.url, self.ssl_ctx)

    async def test_signed_bearer_token_matches_server_contract(self):
        before = datetime.datetime.now(tz=datetime.UTC)
        result = await self.fetch()
        after = datetime.datetime.now(tz=datetime.UTC)
        self.assertEqual(result, self.response.read.return_value)
        args, kwargs = self.session.request.call_args
        self.assertEqual(args, ('GET', self.url))
        self.assertIs(kwargs['ssl'], self.ssl_ctx)
        self.assertFalse(kwargs['allow_redirects'])
        scheme, token = kwargs['headers']['Authorization'].split(' ')
        self.assertEqual(scheme, 'Bearer')
        self.assertEqual(jwt.decode(token, self.key.public_key(), algorithms=['RS256']), {})
        headers = jwt.get_unverified_header(token)
        self.assertEqual(headers['alg'], 'RS256')
        self.assertEqual(headers['unit_id'], CONFIG['control']['unit_id'])
        self.assertEqual(headers['kid'], CONFIG['control']['kid'])
        timestamp = datetime.datetime.fromisoformat(headers['dt'])
        self.assertGreaterEqual(timestamp, before)
        self.assertLessEqual(timestamp, after)

    async def test_each_request_gets_a_fresh_token(self):
        now = datetime.datetime.now(tz=datetime.UTC)
        later = now + datetime.timedelta(minutes=5)
        with mock.patch.object(storage.datetime, 'datetime') as clock:
            clock.now.side_effect = (now, later)
            await self.fetch()
            await self.fetch()
        tokens = [
            call.kwargs['headers']['Authorization'].split(' ')[1]
            for call in self.session.request.call_args_list
        ]
        self.assertNotEqual(tokens[0], tokens[1])
        self.assertEqual(jwt.get_unverified_header(tokens[1])['dt'], later.isoformat())

    async def test_non_success_responses_are_not_consumed(self):
        for status in (302, 401, 500):
            with self.subTest(status=status):
                self.response.status = status
                self.assertIsNone(await self.fetch())
                self.response.read.assert_not_awaited()

    async def test_network_error_preserves_retry_behavior(self):
        self.session.request.side_effect = OSError('unavailable')
        self.assertIsNone(await self.fetch())

    def test_missing_private_key_fails_before_starting_thread(self):
        with mock.patch('builtins.open', side_effect=FileNotFoundError), \
                mock.patch.object(storage.threading, 'Thread') as thread:
            with self.assertRaises(FileNotFoundError):
                storage.RemoteHttp()
        thread.assert_not_called()

    def test_algorithm_is_loaded_from_configured_certificate_before_startup(self):
        certificate = CertificateAlgorithmTests.certificate(self.key)
        files = [
            mock.mock_open(read_data=self.private_key).return_value,
            mock.mock_open(read_data=certificate).return_value,
        ]
        with mock.patch('builtins.open', side_effect=files) as open_file, \
                mock.patch.object(storage.threading, 'Thread'), \
                mock.patch.object(storage.asyncio.events, 'new_event_loop'), \
                mock.patch.object(storage.asyncio, 'Task'), \
                mock.patch.object(storage.RemoteHttp, '_fetch', new=mock.Mock()):
            remote = storage.RemoteHttp()
        self.assertEqual(remote._algorithm, 'RS256')
        self.assertEqual(remote._private_key, self.private_key)
        self.assertEqual(open_file.call_args_list, [
            mock.call(CONFIG['control']['privatekey'], 'rb'),
            mock.call(CONFIG['control']['certificate'], 'rb'),
        ])
