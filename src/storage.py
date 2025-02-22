# -*- coding: utf-8 -*-

import aiohttp
import asyncio
import asyncio.events
import base64
import binascii
import datetime
import http.client
import json
import pprint
import ssl
import sys
import threading
import uuid
import yarl

from . import config as _config


class Base(object):
    def __init__(self):
        self.ready_event = threading.Event()

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

    def save_issued_cards(self):
        raise NotImplementedError

    def save_revoked_cards(self):
        pass

    def shutdown(self):
        pass


class LocalFile(Base):
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

    def __init__(self):
        super(RemoteHttp, self).__init__()
        self.last_config_dt = datetime.datetime.min
        self._event_loop = asyncio.events.new_event_loop()
        self.task = asyncio.Task(self._fetch(), loop=self._event_loop)
        config_fetch = threading.Thread(target=self._fetch_thread, name="config_fetch")
        config_fetch.start()

    async def _fetch(self):
        url = yarl.URL.build(scheme='https', host=_config.control_endpoint, path='/callback/config')

        ssl_ctx = ssl.SSLContext()
        ssl_ctx.load_cert_chain(_config.control_certificate, _config.control_privatekey)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5.0)) as http_session:
            while True:
                conf_bytes = None
                try:
                    async with http_session.request('GET', url, ssl=ssl_ctx) as http_resp:
                        if http_resp.status == http.client.OK:
                            try:
                                conf_bytes = await http_resp.read()
                            except aiohttp.ClientResponseError as err:
                                print('Error fetching config %s' % err)
                except asyncio.TimeoutError as err_timeout:
                    print("Config fetch error: %s | %s | %s" % (type(err_timeout), err_timeout.errno, err_timeout.strerror), file=sys.stderr)
                if conf_bytes is not None:
                    conf = json.loads(conf_bytes)
                    self.users = dict(map(lambda user: (
                        user[0],  # email
                        (
                            user[1][0],  # name
                            user[1][1].encode('ascii'),  # flags
                            datetime.datetime.fromisoformat(user[1][2]),  # created-dt
                        )
                    ), conf['users'].items()))
                    self.issued_cards = dict(map(lambda issued_card: (
                        uuid.UUID(issued_card[0]),
                        (
                            binascii.unhexlify(issued_card[1][0]),  # mifare classic access key B
                            issued_card[1][1],  # email
                            datetime.datetime.fromisoformat(issued_card[1][2]),  # created-dt
                        )
                    ), conf['issued_cards'].items()))
                    self.revoked_cards = dict(map(lambda revoked_card: (
                        uuid.UUID(revoked_card[0]),
                        (
                            binascii.unhexlify(revoked_card[1][0]),  # mifare classic access key B
                            revoked_card[1][1],  # email
                            datetime.datetime.fromisoformat(revoked_card[1][2]),  # issued-dt
                            datetime.datetime.fromisoformat(revoked_card[1][3]),  # revoked-dt
                        )
                    ), conf['revoked_cards'].items()))
                    self.last_config_dt = datetime.datetime.now(tz=datetime.UTC)
                    self.ready_event.set()

                if self.ready_event.is_set():
                    await asyncio.sleep(self.CONFIG_FETCH_INTERVAL.total_seconds())
                    if datetime.datetime.now(tz=datetime.UTC) - self.last_config_dt > self.CONFIG_INVALIDATE:
                        self.ready_event.reset()

    def _fetch_thread(self):
        try:
            self._event_loop.run_until_complete(self.task)
        except asyncio.CancelledError:
            pass

    def save_issued_cards(self):
        pass  # not supported/needed

    def save_revoked_cards(self):
        pass  # not supported/needed

    def shutdown(self):
        self.task.cancel()

