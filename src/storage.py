# -*- coding: utf-8 -*-

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
    def __init__(self):
        super(RemoteHttp, self).__init__()
        config_fetch = threading.Thread(target=self._fetch_thread, name="config_fetch")
        config_fetch.start()

    def _fetch_thread(self):
        ssl_ctx = ssl.SSLContext()
        ssl_ctx.load_cert_chain(_config.control_certificate, _config.control_privatekey)
        while True:
            http_conn = http.client.HTTPSConnection(_config.control_endpoint, timeout=5, context=ssl_ctx)
            try:
                http_conn.request('GET', '/callback/config')
                http_resp = None
                try:
                    http_resp = http_conn.getresponse()
                except OSError as err:
                    print("Config fetch error: %s | %s | %s" % (type(err), err.errno, err.strerror), file=sys.stderr)
                if http_resp is not None and http_resp.status == http.client.OK:
                    conf = json.load(http_resp)
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
                    self.revoked_cards = conf['revoked_cards']
                    break
            finally:
                http_conn.close()

        self.ready_event.set()

    def save_issued_cards(self):
        pass  # not supported/needed

    def save_revoked_cards(self):
        pass  # not supported/needed

