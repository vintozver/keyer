# -*- coding: utf-8 -*-

import aiohttp
import asyncio
import asyncio.events
import base64
import binascii
import collections
import datetime
import http.client
import json
import jwt
import pprint
import queue
import ssl
import sys
import threading
import typing
import uuid
import yarl

from bson import ObjectId
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

from . import config as _config


def _certificate_algorithm(certificate: bytes) -> str:
    public_key = x509.load_pem_x509_certificate(certificate).public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return 'RS256'
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        algorithms = {'secp256r1': 'ES256', 'secp384r1': 'ES384', 'secp521r1': 'ES512'}
        if public_key.curve.name in algorithms:
            return algorithms[public_key.curve.name]
    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return 'EdDSA'
    raise ValueError("Certificate public key is not supported for JWT signing")


class Base(object):
    EVENT_QUEUE_LIMIT = 10000
    EVENT_BATCH_LIMIT = 1000
    EVENT_BATCH_BYTES = 1024 * 1024

    def __init__(self):
        self.ready_event = threading.Event()
        self._events_lock = threading.Lock()
        self._events = collections.deque()
        self._pending_batch = ()
        self.user_ids = {}

        self.issued_cards = {
            # uuid.UUID -> access_key_B(6-byte), email, dt-created(UTC)
        }
        self.revoked_cards = {
            # uuid.UUID -> access_key_B(6-byte), email, dt-created(UTC), dt-revoked(UTC)
        }
        self.users = {
            # email -> name, flags, dt-created(UTC)
            # flags (one byte per line)
            #   O(owner), R(resident)
            #   *(unlimited access), S(scheduled access, 2 bytes scheduler identifier follow)
        }

    def enqueue_event(self, event: str, email: typing.Optional[str] = None):
        if event not in ('card_tap', 'card_personalize', 'card_format'):
            raise ValueError("Unsupported unit event")
        with self._events_lock:
            user = self.users.get(email)
            user_id = self.user_ids.get(email) if user is not None else None
            record = json.dumps({
                'oid': str(ObjectId()),
                'user_id': user_id,
                'name': user[0] if user_id is not None else '',
                'event': event,
            }, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
            if len(record) + len(b'{"events":[]}') > self.EVENT_BATCH_BYTES:
                raise ValueError("Card event exceeds upload size limit")
            if len(self._events) >= self.EVENT_QUEUE_LIMIT:
                print("Card event queue full; event could not be recorded", file=sys.stderr)
                raise queue.Full("Card event queue full")
            self._events.append(record)

    def _event_batch(self):
        with self._events_lock:
            if not self._pending_batch:
                batch = []
                size = len(b'{"events":[]}')
                for record in self._events:
                    extra = len(record) + bool(batch)
                    if len(batch) == self.EVENT_BATCH_LIMIT or size + extra > self.EVENT_BATCH_BYTES:
                        break
                    batch.append(record)
                    size += extra
                self._pending_batch = tuple(batch)
            return self._pending_batch

    def save_issued_cards(self):
        raise NotImplementedError

    def save_revoked_cards(self):
        pass

    def shutdown(self):
        pass


class LocalFile(Base):
    def enqueue_event(self, event: str, email: typing.Optional[str] = None):
        pass  # local-file mode has no controller identity mapping or uploader

    def __init__(self):
        super(LocalFile, self).__init__()

        try:
            with open("users.txt", "rt") as f:
                for line in f.readlines():
                    line = line.strip()
                    if not line:
                        continue
                    items = line.split("\t")
                    if len(items) != 4:
                        raise RuntimeError("Unable to parse users.txt")
                    email = items[0]
                    name = items[1]
                    flags = items[2].encode('ascii')
                    dt = datetime.datetime.fromisoformat(items[3])
                    self.users[email] = (name, flags, dt)
        except FileNotFoundError:
            pass
        print("***users***")
        print(pprint.pformat(self.users, width=320))

        try:
            with open("issued_cards.txt", "rt") as f:
                for line in f.readlines():
                    line = line.strip()
                    if not line:
                        continue
                    items = line.split("\t")
                    if len(items) != 4:
                        raise RuntimeError("Unable to parse users.txt")
                    identifier = uuid.UUID(items[0])
                    key_B = base64.b64decode(items[1])
                    email = items[2]
                    issued = datetime.datetime.fromisoformat(items[3])
                    self.issued_cards[identifier] = (key_B, email, issued)
        except FileNotFoundError:
            pass
        print("***issued cards***")
        print(pprint.pformat(self.issued_cards, width=320))

        try:
            with open("revoked_cards.txt", "rt") as f:
                for line in f.readlines():
                    line = line.strip()
                    if not line:
                        continue
                    items = line.split("\t")
                    if len(items) != 5:
                        raise RuntimeError("Unable to parse users.txt")
                    identifier = uuid.UUID(items[0])
                    key_B = base64.b64decode(items[1])
                    email = items[2]
                    issued = datetime.datetime.fromisoformat(items[3])
                    revoked = datetime.datetime.fromisoformat(items[4])
                    self.revoked_cards[identifier] = (key_B, email, issued, revoked)
        except FileNotFoundError:
            pass
        print("***revoked cards***")
        print(pprint.pformat(self.revoked_cards, width=320))

        self.ready_event.set()

    def save_issued_cards(self):
        print("Saving issued_cards.txt\n" + repr(self.issued_cards))
        with open("issued_cards.txt", "wt") as f:
            for issued_card in self.issued_cards.items():
                f.write("%s\t%s\t%s\t%s\n" % (
                    issued_card[0].hex,
                    base64.b64encode(issued_card[1][0]).decode('ascii'),
                    issued_card[1][1],
                    issued_card[1][2].isoformat(),
                ))
            f.flush()

    def save_revoked_cards(self):
        print("Saving revoked_cards.txt\n" + repr(self.revoked_cards))
        with open("revoked_cards.txt", "wt") as f:
            for revoked_card in self.revoked_cards.items():
                f.write("%s\t%s\t%s\t%s\t%s\n" % (
                    revoked_card[0].hex,
                    base64.b64encode(revoked_card[1][0]).decode('ascii'),
                    revoked_card[1][1],
                    revoked_card[1][2].isoformat(),
                    revoked_card[1][3].isoformat(),
                ))
            f.flush()


class RemoteHttp(Base):
    CONFIG_INVALIDATE = datetime.timedelta(days=1)
    CONFIG_FETCH_INTERVAL = datetime.timedelta(minutes=5)
    LOG_UPLOAD_INTERVAL = 5.0
    RETRY_MAX_INTERVAL = 60.0
    SHUTDOWN_TIMEOUT = 5.0

    def __init__(self):
        super(RemoteHttp, self).__init__()
        with open(_config.control_privatekey, "rb") as f:
            self._private_key = f.read()
        with open(_config.control_certificate, "rb") as f:
            self._algorithm = _certificate_algorithm(f.read())
        self._shutdown_event = asyncio.Event()
        self._last_config_dt = datetime.datetime.min
        self._event_loop = asyncio.events.new_event_loop()
        self._task = asyncio.Task(self._fetch(), loop=self._event_loop)
        self._thread = threading.Thread(target=self._fetch_thread, name="control_http", daemon=True)
        self._thread.start()

    def _authorization(self):
        return 'Bearer ' + jwt.encode(
            {},
            self._private_key,
            algorithm=self._algorithm,
            headers={
                'unit_id': _config.unit_id,
                'kid': _config.kid,
                'dt': datetime.datetime.now(tz=datetime.UTC).isoformat(),
            },
        )

    async def _fetch_once(self, http_session: aiohttp.ClientSession, url: yarl.URL, ssl_ctx: ssl.SSLContext) -> typing.Optional[bytes]:
        try:
            async with http_session.request(
                    'GET', url, ssl=ssl_ctx,
                    headers={'Authorization': self._authorization()},
                    allow_redirects=False) as http_resp:
                if http_resp.status == http.client.OK:
                    try:
                        return await http_resp.read()
                    except aiohttp.ClientResponseError as err:
                        print('Config fetch error: %s' % err)
                else:
                    print('Config fetch unexpected response: %s %s' % (http_resp.status, http_resp.reason), file=sys.stderr)
        except (OSError, aiohttp.ClientError, asyncio.TimeoutError) as err:
            print("Config fetch error: %s" % err, file=sys.stderr)

        return None

    async def _upload_once(self, http_session, url, ssl_ctx):
        batch = self._event_batch()
        if not batch:
            return True
        body = b'{"events":[' + b','.join(batch) + b']}'
        try:
            async with http_session.request(
                    'POST', url, ssl=ssl_ctx, data=body,
                    headers={'Authorization': self._authorization(), 'Content-Type': 'application/json'},
                    allow_redirects=False) as response:
                if response.status != http.client.OK:
                    print("Log upload rejected: HTTP %s; batch retained (400/409 require investigation)" %
                          response.status, file=sys.stderr)
                    return False
                acknowledgement = await response.json()
                expected = [json.loads(record)['oid'] for record in batch]
                accepted = acknowledgement.get('accepted') if isinstance(acknowledgement, dict) else None
                if (not isinstance(accepted, list) or
                        not all(isinstance(oid, str) for oid in accepted) or
                        len(accepted) != len(expected) or set(accepted) != set(expected)):
                    print("Log upload invalid acknowledgement; batch retained", file=sys.stderr)
                    return False
        except (OSError, aiohttp.ClientError, asyncio.TimeoutError, ValueError) as err:
            print("Log upload error; batch retained: %s" % err, file=sys.stderr)
            return False

        with self._events_lock:
            for record in batch:
                self._events.popleft()
            self._pending_batch = ()
        return True

    async def _wait_interval(self, seconds):
        try:
            await asyncio.wait_for(self._shutdown_event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    async def _upload(self, http_session, ssl_ctx):
        url = yarl.URL.build(scheme='https', host=_config.control_endpoint, path='/log')
        delay = self.LOG_UPLOAD_INTERVAL
        while not self._shutdown_event.is_set():
            await self._wait_interval(delay)
            if self._shutdown_event.is_set():
                break
            if await self._upload_once(http_session, url, ssl_ctx):
                delay = self.LOG_UPLOAD_INTERVAL
            else:
                delay = min(delay * 2, self.RETRY_MAX_INTERVAL)

    async def _final_flush(self, http_session, ssl_ctx):
        url = yarl.URL.build(scheme='https', host=_config.control_endpoint, path='/log')
        while self._event_batch():
            if not await self._upload_once(http_session, url, ssl_ctx):
                break

    async def _fetch(self):
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.load_cert_chain(_config.control_certificate, _config.control_privatekey)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5.0)) as http_session:
            tasks = [
                asyncio.create_task(self._fetch_config(http_session, ssl_ctx)),
                asyncio.create_task(self._upload(http_session, ssl_ctx)),
            ]
            try:
                await self._shutdown_event.wait()
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                try:
                    await asyncio.wait_for(self._final_flush(http_session, ssl_ctx), self.SHUTDOWN_TIMEOUT)
                except asyncio.TimeoutError:
                    print("Log shutdown flush timed out; pending events remain in memory", file=sys.stderr)
                with self._events_lock:
                    if self._events:
                        print("Shutdown with %s pending card events" % len(self._events), file=sys.stderr)

    async def _fetch_config(self, http_session, ssl_ctx):
        url = yarl.URL.build(scheme='https', host=_config.control_endpoint, path='/config')
        delay = self.LOG_UPLOAD_INTERVAL
        while not self._shutdown_event.is_set():
            try:
                conf_bytes = await self._fetch_once(http_session, url, ssl_ctx)
                if conf_bytes is not None:
                    self._apply_config(json.loads(conf_bytes))
                    self._last_config_dt = datetime.datetime.now(tz=datetime.UTC)
                    self.ready_event.set()
                    delay = self.CONFIG_FETCH_INTERVAL.total_seconds()
                else:
                    delay = min(delay * 2, self.RETRY_MAX_INTERVAL)
            except (ValueError, KeyError, TypeError, AttributeError) as err:
                print("Invalid controller configuration: %s" % err, file=sys.stderr)
                delay = self.RETRY_MAX_INTERVAL
            if (self.ready_event.is_set() and
                    datetime.datetime.now(tz=datetime.UTC) - self._last_config_dt > self.CONFIG_INVALIDATE):
                self.ready_event.clear()
            await self._wait_interval(delay)

    def _apply_config(self, conf):
        users = dict(map(lambda user: (
            user[0],
            (user[1][0], user[1][1].encode('ascii'), datetime.datetime.fromisoformat(user[1][2]))
        ), conf['users'].items()))
        user_ids = dict(conf.get('user_ids', {}))
        if any(not isinstance(oid, str) or not ObjectId.is_valid(oid) for oid in user_ids.values()):
            raise ValueError("Invalid controller user_ids")
        issued_cards = dict(map(lambda card: (
            uuid.UUID(card[0]),
            (binascii.unhexlify(card[1][0]), card[1][1], datetime.datetime.fromisoformat(card[1][2]))
        ), conf['issued_cards'].items()))
        revoked_cards = dict(map(lambda card: (
            uuid.UUID(card[0]),
            (binascii.unhexlify(card[1][0]), card[1][1],
             datetime.datetime.fromisoformat(card[1][2]), datetime.datetime.fromisoformat(card[1][3]))
        ), conf['revoked_cards'].items()))
        with self._events_lock:
            self.users = users
            self.user_ids = user_ids
            self.issued_cards = issued_cards
            self.revoked_cards = revoked_cards

    def _fetch_thread(self):
        asyncio.set_event_loop(self._event_loop)
        try:
            self._event_loop.run_until_complete(self._task)
        except asyncio.CancelledError:
            pass
        finally:
            self._event_loop.close()

    def save_issued_cards(self):
        pass  # not supported/needed

    def save_revoked_cards(self):
        pass  # not supported/needed

    def shutdown(self):
        if self._thread.is_alive():
            self._event_loop.call_soon_threadsafe(self._shutdown_event.set)
            self._thread.join(timeout=self.SHUTDOWN_TIMEOUT + 1)
