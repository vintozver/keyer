import datetime
import importlib.util
from pathlib import Path
import ssl
import unittest
from unittest import mock

import jwt
import yaml
import yarl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


CONFIG = {
    'title1': 'Premises',
    'title2': 'Access control',
    'unit_id': '0123456789abcdef01234567',
    'kid': 'primary',
    'control': {
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
        self.assertEqual(config.unit_id, CONFIG['unit_id'])
        self.assertEqual(config.kid, CONFIG['kid'])
        self.assertEqual(config.control_endpoint, CONFIG['control']['endpoint'])
        self.assertEqual(config.control_certificate, CONFIG['control']['certificate'])
        self.assertEqual(config.control_privatekey, CONFIG['control']['privatekey'])
        self.assertEqual(config.control_algorithm, 'RS256')

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
                    self.load_config(yaml.safe_dump({**CONFIG, name: value}))

    def test_asymmetric_algorithm_can_be_selected(self):
        config = self.load_config(yaml.safe_dump({
            **CONFIG, 'control': {**CONFIG['control'], 'algorithm': 'ES256'},
        }))
        self.assertEqual(config.control_algorithm, 'ES256')

    def test_insecure_algorithms_are_rejected(self):
        for algorithm in ('none', 'HS256', 'unknown'):
            with self.subTest(algorithm=algorithm), self.assertRaises(ValueError):
                self.load_config(yaml.safe_dump({
                    **CONFIG, 'control': {**CONFIG['control'], 'algorithm': algorithm},
                }))

    def test_unsafe_yaml_is_rejected(self):
        with self.assertRaises(yaml.constructor.ConstructorError):
            self.load_config('!!python/object/apply:builtins.dict []')


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
        self.assertEqual(headers['unit_id'], CONFIG['unit_id'])
        self.assertEqual(headers['kid'], CONFIG['kid'])
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
