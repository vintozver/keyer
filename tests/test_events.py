import asyncio
import datetime
import json
import queue
import threading
import time
import unittest
import uuid
from unittest import mock

import aiohttp
from bson import ObjectId
import jwt
import yarl

import test_control as control

storage = control.storage


class EventQueueTests(unittest.TestCase):
    def setUp(self):
        self.store = storage.Base()
        self.card_id = uuid.uuid4()

    def test_event_id_and_card_uuid_are_captured_at_collection_time(self):
        before = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
        self.store.enqueue_event('card_tap', self.card_id)
        self.store.issued_cards.clear()
        event = json.loads(self.store._event_batch()[0])
        self.assertEqual(set(event), {'oid', 'event', 'card_id'})
        self.assertGreaterEqual(ObjectId(event['oid']).generation_time, before)
        self.assertEqual(event['card_id'], str(self.card_id))
        self.store.enqueue_event('card_tap', self.card_id)
        self.assertNotEqual(event['oid'], json.loads(self.store._events[-1])['oid'])

    def test_missing_or_invalid_card_uuid_is_rejected(self):
        for value in (None, 'resident@example.com', str(self.card_id), b'bad'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.store.enqueue_event('card_tap', value)
        self.assertFalse(self.store._events)

    def test_count_boundary(self):
        for _ in range(1001):
            self.store.enqueue_event('card_tap', self.card_id)
        self.assertEqual(len(self.store._event_batch()), 1000)
        self.assertEqual(len(self.store._events), 1001)

    def test_exact_byte_boundary_and_oversized_event(self):
        self.store.enqueue_event('card_tap', self.card_id)
        record = self.store._events[0]
        self.store.EVENT_BATCH_BYTES = len(b'[]') + len(record)
        self.store.enqueue_event('card_tap', self.card_id)
        self.assertEqual(len(self.store._event_batch()), 1)
        self.store.EVENT_BATCH_BYTES -= 1
        with self.assertRaisesRegex(ValueError, 'size limit'):
            self.store.enqueue_event('card_tap', self.card_id)
        self.assertEqual(len(self.store._events), 2)

    def test_real_one_mib_boundary(self):
        self.store.EVENT_BATCH_LIMIT = self.store.EVENT_QUEUE_LIMIT
        for _ in range(10000):
            self.store.enqueue_event('card_personalize', self.card_id)
        batch = self.store._event_batch()
        body = b'[' + b','.join(batch) + b']'
        self.assertLessEqual(len(body), 1024 * 1024)
        self.assertGreater(len(body) + 1 + len(self.store._events[len(batch)]), 1024 * 1024)

    def test_overflow_is_explicit_and_does_not_evict(self):
        self.store.EVENT_QUEUE_LIMIT = 1
        self.store.enqueue_event('card_tap', self.card_id)
        original = tuple(self.store._events)
        with self.assertRaises(queue.Full):
            self.store.enqueue_event('card_tap', self.card_id)
        self.assertEqual(tuple(self.store._events), original)

    def test_controller_only_events_are_rejected(self):
        for event in ('remote_unlock', 'revocation'):
            with self.assertRaises(ValueError):
                self.store.enqueue_event(event, self.card_id)

    def test_local_file_mode_does_not_buffer_or_upload(self):
        local = object.__new__(storage.LocalFile)
        storage.Base.__init__(local)
        local.enqueue_event('card_tap', self.card_id)
        self.assertFalse(local._events)


class EventUploadTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        control.RemoteHttpTests.setUpClass()
        cls.key = control.RemoteHttpTests.key

    def setUp(self):
        self.remote = object.__new__(storage.RemoteHttp)
        storage.Base.__init__(self.remote)
        self.remote._private_key = control.RemoteHttpTests.private_key
        self.remote._algorithm = 'RS256'
        self.remote._shutdown_event = asyncio.Event()
        self.remote._last_config_dt = datetime.datetime.now(datetime.UTC)
        self.session = mock.MagicMock()
        self.response = mock.AsyncMock()
        self.response.status = 200
        self.session.request.return_value.__aenter__.return_value = self.response
        self.url = yarl.URL('https://control.example.com/log')
        self.ssl_ctx = mock.sentinel.ssl_context
        self.card_id = uuid.uuid4()
        self.remote.enqueue_event('card_tap', self.card_id)

    def acknowledge(self):
        return {'accepted': [json.loads(record)['oid'] for record in self.remote._event_batch()]}

    async def upload(self):
        return await self.remote._upload_once(self.session, self.url, self.ssl_ctx)

    async def test_authenticated_upload_and_exact_body(self):
        self.response.json.return_value = self.acknowledge()
        self.assertTrue(await self.upload())
        args, kwargs = self.session.request.call_args
        self.assertEqual(args, ('POST', self.url))
        self.assertIs(kwargs['ssl'], self.ssl_ctx)
        self.assertFalse(kwargs['allow_redirects'])
        self.assertEqual(kwargs['headers']['Content-Type'], 'application/json')
        token = kwargs['headers']['Authorization'].split(' ')[1]
        self.assertEqual(jwt.decode(token, self.key.public_key(), algorithms=['RS256']), {})
        header = jwt.get_unverified_header(token)
        self.assertEqual(header['unit_id'], control.CONFIG['control']['unit_id'])
        self.assertEqual(header['kid'], control.CONFIG['control']['kid'])
        self.assertIsNotNone(datetime.datetime.fromisoformat(header['dt']).tzinfo)
        payload = json.loads(kwargs['data'])
        self.assertIsInstance(payload, list)
        self.assertEqual(len(payload), 1)
        self.assertEqual(set(payload[0]), {'oid', 'event', 'card_id'})
        self.assertTrue(ObjectId.is_valid(payload[0]['oid']))
        self.assertEqual(payload[0]['event'], 'card_tap')
        self.assertEqual(uuid.UUID(payload[0]['card_id']), self.card_id)
        self.assertFalse(self.remote._events)

    async def test_only_exact_acknowledgements_remove_events(self):
        self.remote.enqueue_event('card_format', self.card_id)
        expected = self.acknowledge()['accepted']
        for accepted in (None, [], expected[:1], expected + ['extra'],
                         [expected[0]] * 2, 'not a list', [{}], [1, 2]):
            with self.subTest(accepted=accepted):
                self.response.json.return_value = {'accepted': accepted}
                self.assertFalse(await self.upload())
                self.assertEqual(len(self.remote._events), 2)
        for value in ([], None, {}, 'invalid'):
            self.response.json.return_value = value
            self.assertFalse(await self.upload())
        self.response.json.return_value = {'accepted': list(reversed(expected))}
        self.assertTrue(await self.upload())
        self.assertFalse(self.remote._events)

    async def test_all_non_200_responses_keep_batch(self):
        original = self.remote._event_batch()
        for status in (201, 204, 302, 400, 401, 409, 500, 503):
            self.response.status = status
            self.assertFalse(await self.upload())
            self.assertEqual(self.remote._event_batch(), original)
        self.response.json.assert_not_awaited()

    async def test_lost_committed_response_retries_identical_batch(self):
        committed = self.acknowledge()
        self.response.json.side_effect = aiohttp.ClientPayloadError('response lost after commit')
        self.assertFalse(await self.upload())
        original_body = self.session.request.call_args.kwargs['data']
        original_token = self.session.request.call_args.kwargs['headers']['Authorization']
        self.remote.enqueue_event('card_format', uuid.uuid4())
        self.remote.issued_cards.clear()
        self.response.json.side_effect = None
        self.response.json.return_value = committed
        self.assertTrue(await self.upload())
        self.assertEqual(self.session.request.call_args.kwargs['data'], original_body)
        self.assertNotEqual(self.session.request.call_args.kwargs['headers']['Authorization'], original_token)
        self.assertEqual(len(self.remote._events), 1)
        self.assertEqual(json.loads(self.remote._events[0])['event'], 'card_format')

    async def test_offline_and_malformed_json_recover(self):
        original = self.remote._event_batch()
        for error in (OSError('offline'), asyncio.TimeoutError(), aiohttp.ClientConnectionError()):
            self.session.request.side_effect = error
            self.assertFalse(await self.upload())
            self.assertEqual(self.remote._event_batch(), original)
        self.session.request.side_effect = None
        self.response.json.side_effect = ValueError('bad JSON')
        self.assertFalse(await self.upload())
        self.response.json.side_effect = None
        self.response.json.return_value = self.acknowledge()
        self.assertTrue(await self.upload())

    async def test_concurrent_append_while_upload_is_in_flight(self):
        started = threading.Event()
        appended = threading.Event()
        expected = self.acknowledge()

        def produce():
            started.wait(timeout=2)
            for _ in range(100):
                self.remote.enqueue_event('card_format', self.card_id)
            appended.set()

        async def response():
            started.set()
            self.assertTrue(await asyncio.to_thread(appended.wait, 2))
            return expected

        producer = threading.Thread(target=produce)
        producer.start()
        self.response.json.side_effect = response
        self.assertTrue(await self.upload())
        producer.join(timeout=2)
        self.assertEqual(len(self.remote._events), 100)
        self.assertEqual(len({json.loads(record)['oid'] for record in self.remote._events}), 100)
        self.response.json.side_effect = None
        self.response.json.return_value = self.acknowledge()
        self.assertTrue(await self.upload())
        self.assertFalse(self.remote._events)

    async def test_periodic_uploader_backs_off_and_resets_independently_of_config(self):
        delays = []

        async def wait(seconds):
            delays.append(seconds)
            if len(delays) == 6:
                self.remote._shutdown_event.set()

        with mock.patch.object(self.remote, '_wait_interval', side_effect=wait), \
                mock.patch.object(self.remote, '_upload_once', new=mock.AsyncMock(
                    side_effect=[False, False, False, True, True])) as upload:
            await self.remote._upload(self.session, self.ssl_ctx)
        self.assertEqual(delays, [5, 10, 20, 40, 5, 5])
        self.assertEqual(upload.await_count, 5)
        self.assertFalse(self.remote.ready_event.is_set())

    async def test_config_outage_and_invalid_config_do_not_stop_fetching(self):
        conf = {
            'users': {'resident@example.com': ['Resident', 'R*', '2026-01-01T00:00:00+00:00']},
            'issued_cards': {}, 'revoked_cards': {},
        }
        waits = []

        async def wait(seconds):
            waits.append(seconds)
            if len(waits) == 3:
                self.remote._shutdown_event.set()

        with mock.patch.object(self.remote, '_fetch_once', new=mock.AsyncMock(
                side_effect=[None, b'invalid JSON', json.dumps(conf).encode()])), \
                mock.patch.object(self.remote, '_wait_interval', side_effect=wait):
            await self.remote._fetch_config(self.session, self.ssl_ctx)
        self.assertEqual(waits, [10, 60, 300])
        self.assertTrue(self.remote.ready_event.is_set())
        self.remote.enqueue_event('card_tap', self.card_id)
        event = json.loads(self.remote._events[-1])
        self.assertEqual(event['card_id'], str(self.card_id))
        self.assertEqual(self.remote.users['resident@example.com'][0], 'Resident')

    async def test_final_flush_drains_multiple_batches(self):
        self.remote.EVENT_BATCH_LIMIT = 1
        self.remote.enqueue_event('card_format', self.card_id)
        self.response.json.side_effect = lambda: self.acknowledge()
        await self.remote._final_flush(self.session, self.ssl_ctx)
        self.assertEqual(self.session.request.call_count, 2)
        self.assertFalse(self.remote._events)

    async def test_shutdown_flush_has_an_overall_deadline(self):
        self.remote.SHUTDOWN_TIMEOUT = 0.02
        self.remote._shutdown_event.set()
        client = mock.MagicMock()
        client.return_value.__aenter__.return_value = self.session

        async def stalled_flush(*args):
            await asyncio.sleep(10)

        start = time.monotonic()
        with mock.patch.object(storage.ssl, 'create_default_context'), \
                mock.patch.object(storage.aiohttp, 'ClientSession', client), \
                mock.patch.object(self.remote, '_final_flush', side_effect=stalled_flush):
            await self.remote._fetch()
        self.assertLess(time.monotonic() - start, 0.5)
        self.assertEqual(len(self.remote._events), 1)
        self.assertEqual(client.call_args.kwargs['timeout'].total, 5.0)

    async def test_shutdown_signals_thread_safely_and_joins_with_bound(self):
        self.remote._thread = mock.Mock()
        self.remote._event_loop = mock.Mock()
        self.remote.shutdown()
        self.remote._event_loop.call_soon_threadsafe.assert_called_once_with(self.remote._shutdown_event.set)
        self.remote._thread.join.assert_called_once_with(timeout=self.remote.SHUTDOWN_TIMEOUT + 1)


class ThreadedShutdownTests(unittest.TestCase):
    def test_worker_flushes_and_stops_and_repeated_shutdown_is_safe(self):
        control.RemoteHttpTests.setUpClass()
        key = control.RemoteHttpTests.key
        certificate = control.CertificateAlgorithmTests.certificate(key)
        files = [
            mock.mock_open(read_data=control.RemoteHttpTests.private_key).return_value,
            mock.mock_open(read_data=certificate).return_value,
        ]
        entered = threading.Event()
        flushed = threading.Event()

        async def fetch(remote):
            entered.set()
            await remote._shutdown_event.wait()
            flushed.set()

        with mock.patch('builtins.open', side_effect=files), \
                mock.patch.object(storage.RemoteHttp, '_fetch', fetch):
            remote = storage.RemoteHttp()
            self.assertTrue(entered.wait(timeout=2))
            remote.shutdown()
            remote.shutdown()
        self.assertTrue(flushed.is_set())
        self.assertFalse(remote._thread.is_alive())
        self.assertTrue(remote._event_loop.is_closed())
