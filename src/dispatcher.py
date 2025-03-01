#!/usr/bin/env python3

import binascii
import datetime
import gpiozero
import hashlib
import os
import queue
import threading
import time
import typing
import uuid

from adafruit_character_lcd.character_lcd import Character_LCD_RGB
from adafruit_pn532.adafruit_pn532 import PN532
import ecdsa

from . import config as _config
from . import storage as _storage
from . import utils as _utils


class Box(object):
    def __init__(self, value):
        self.value = value


class Dispatcher(object):
    STATE_IDLE_STANDBY = 0
    STATE_IDLE_DATETIME = 1
    STATE_WAIT_CONFIG = 2

    # https://blog.linuxgemini.space/derive-pk-of-nxp-mifare-classic-ev1-ecdsa-signature
    # https://github.com/MichaelsPlayground/NfcMifareClassicEv1VerifyOriginalitySignature/blob/master/app/src/main/java/de/androidcrypto/nfcmifareclassicev1verifyoriginalitysignature/MainActivity.java#L53
    SIG_PK_NXP_MIFARE_CLASSIC_EV1 = binascii.unhexlify("044F6D3F294DEA5737F0F46FFEE88A356EED95695DD7E0C27A591E6F6F65962BAF")

    # Mifare Classic EV1 personalization layout
    # block 0 (mfg data)
    # block 1 (title1)
    # block 2 (title2)
    # block 3 (sector trailer)
    # block 4 (uuid4 of the card)
    # block 5, 6 (sha256 of the email associated)
    # block 7 (sector trailer)
    # ---
    # blocks 1, 2, 3, 4, 7 - allow read by key_A (default, 0xFFFFFFFFFFFF), allow write by key_B (generated, stored)
    # blocks 5, 6 - allow read/write by key_B only (to allow authN)
    # Program will read blocks 1, 2 - using default key_A, validating titles
    # Then, will read block 4 to obtain the card UUID
    # Then, will go to the database to locate the access record (containing key_B, email, policy)
    # Then, will read blocks 5, 6 authN with key_B, affirming that the card is issued by us
    # Then, will compare the email_hash with the values of block 5, 6 - affirming correct usage
    # Then, will allow/deny access based on the policy

    def __init__(self,
        lcd: Character_LCD_RGB,
        pn532: PN532,
        buzzer: gpiozero.TonalBuzzer,
        relay: gpiozero.LED,
    ):
        self.shutdown_event = threading.Event()
        self.lcd = lcd
        self.pn532 = pn532
        self.buzzer = buzzer
        self.relay = relay
        self.card_sig_validator = ecdsa.VerifyingKey.from_public_point(
            ecdsa.ellipticcurve.Point(
                ecdsa.SECP128r1.curve,
                int.from_bytes(self.SIG_PK_NXP_MIFARE_CLASSIC_EV1[1:17]),
                int.from_bytes(self.SIG_PK_NXP_MIFARE_CLASSIC_EV1[17:]),
            ),
            curve=ecdsa.SECP128r1
        )

        self.queue = queue.Queue(4)

        if _config.local_storage:
            self.storage = _storage.LocalFile()
        else:
            self.storage = _storage.RemoteHttp()

        self.state = self.STATE_WAIT_CONFIG

    def shutdown(self):
        self.storage.shutdown()
        self.shutdown_event.set()

    def render_idle_standby(self):
        self.lcd.message = "ASPGR Game Room \nTAP CARD ...    "
        self.lcd.color = (0, 0, 100)

    def render_idle_datetime(self):
        dt = datetime.datetime.now()
        self.lcd.message = "%04d-%02d-%02d %02d:%02d\nTAP CARD ...    " % (dt.year, dt.month, dt.day, dt.hour, dt.minute)
        self.lcd.color = (0, 0, 100)

    def render_state_wait_config(self):
        self.lcd.message = "waiting for     \nconfig ...      "
        self.lcd.color = (0, 0, 0)

    def render_granted(self, identifier: uuid.UUID, flags: typing.Annotated[str, 16]):
        self.lcd.message = "WELCOME %8s\n%16s" % (identifier.bytes[-4:].hex(), flags)
        self.lcd.color = (0, 100, 0)
        self.relay.blink(on_time=2.0, off_time=1.0, n=1, background=True)
        self.buzzer.play(220)
        time.sleep(1)
        self.buzzer.stop()

    def render_denied(self, reason: typing.Annotated[str, 16]):
        self.lcd.message = "UNAUTHORIZED    \n%16s" % (reason[:16] or "")
        self.lcd.color = (100, 0, 0)
        self.buzzer.play(440)
        time.sleep(1)
        self.buzzer.stop()

    def render_remote_admit(self, flags: typing.Annotated[str, 16]):
        self.lcd.message = "REMOTE UNLOCK   \n%16s" % flags
        self.lcd.color = (100, 100, 0)
        self.relay.blink(on_time=5.0, off_time=1.0, n=1, background=True)
        self.buzzer.play(220)
        time.sleep(1)
        self.buzzer.stop()

    def remote_admit(self, email: str):
        user = self.storage.users.get(email)
        if user is not None:
            flags = user[1]
            if flags[1:2] == b'*':
                self.render_remote_admit(flags.decode('ascii'))
            elif flags[1:2] == b'S':
                if flags[2:4] == b'00':
                    dt = datetime.datetime.now()
                    if dt.hour >= 8 and dt.hour < 20:
                        self.render_remote_admit(flags.decode('ascii'))
                    else:
                        self.render_denied("time limit")
                else:
                    self.render_denied("invalid schedule")
            else:
                self.render_denied("unknown flag")
        else:
            self.render_denied("unknown user")

    def personalize_card(self, email: str) -> typing.Optional[tuple[uuid.UUID, bytes, datetime.datetime]]:
        lcd = self.lcd
        pn532 = self.pn532

        email_hash = hashlib.sha256(email.encode('utf-8')).digest()

        lcd.message = "PERSONALIZING   \nTAP CARD ...    "
        lcd.color = (100, 100, 100)

        card_uid = pn532.read_passive_target(timeout=5)
        if card_uid is None:
            return None

        identifier = uuid.uuid4()
        access_key_B = os.urandom(6)
        dt = datetime.datetime.now(tz=datetime.UTC)

        ok = True
        lcd.message = "CARD %11s\nWRITING ...     " % binascii.hexlify(card_uid).decode('ascii')
        if ok:
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 3, 0x60, b'\xff\xff\xff\xff\xff\xff'):
                acl = _utils.access_bits_to_seq(
                    0, 0, 0,  # block 0 (mfg data)
                    1, 0, 0,  # block 1
                    1, 0, 0,  # block 2
                    0, 1, 1,  # block 3 (sector trailer)
                )
                pn532.mifare_classic_write_block(3, b'\xff\xff\xff\xff\xff\xff' + acl + b'\x00' + access_key_B)
            else:
                lcd.message = "BLOCK3 NOT AUTHN\nERROR           "
                ok = False
        if ok:
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 7, 0x60, b'\xff\xff\xff\xff\xff\xff'):
                acl = _utils.access_bits_to_seq(
                    1, 0, 0,  # block 4
                    0, 1, 1,  # block 5
                    0, 1, 1,  # block 6
                    0, 1, 1,  # block 7 (sector trailer)
                )
                pn532.mifare_classic_write_block(7, b'\xff\xff\xff\xff\xff\xff' + acl + b'\x00' + access_key_B)
            else:
                lcd.message = "BLOCK3 NOT AUTHN\nERROR           "
                ok = False
        if ok:
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 1, 0x61, access_key_B):
                pn532.mifare_classic_write_block(1, _config.title1.strip().ljust(16)[:16].encode('ascii'))
            else:
                lcd.message = "BLOCK1 NOT AUTHN\nERROR           "
                ok = False
        if ok:
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 2, 0x61, access_key_B):
                pn532.mifare_classic_write_block(2, _config.title2.strip().ljust(16)[:16].encode('ascii'))
            else:
                lcd.message = "BLOCK2 NOT AUTHN\nERROR           "
                ok = False
        if ok:
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 4, 0x61, access_key_B):
                pn532.mifare_classic_write_block(4, identifier.bytes)
            else:
                lcd.message = "BLOCK4 NOT AUTHN\nERROR           "
                ok = False
        if ok:
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 5, 0x61, access_key_B):
                pn532.mifare_classic_write_block(5, email_hash[:16])
            else:
                lcd.message = "BLOCK5 NOT AUTHN\nERROR           "
                ok = False
        if ok:
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 6, 0x61, access_key_B):
                pn532.mifare_classic_write_block(6, email_hash[16:])
            else:
                lcd.message = "BLOCK6 NOT AUTHN\nERROR           "
                ok = False

        if ok:
            self.storage.issued_cards[identifier] = (access_key_B, email, dt)
            self.storage.save_issued_cards()

            lcd.message = "PERSONALIZING OK\nREMOVE CARD ... "
            time.sleep(5)
            lcd.color = (0, 0, 0)
            return identifier, access_key_B, dt
        else:
            time.sleep(5)
            lcd.color = (0, 0, 0)
            return None

    def depersonalize_card(self) -> typing.Optional[uuid.UUID]:
        lcd = self.lcd
        pn532 = self.pn532

        lcd.message = "DEPERSONALIZING \nTAP CARD ...    "
        lcd.color = (100, 100, 100)

        card_uid = pn532.read_passive_target(timeout=5)
        if card_uid is not None:
            success = False

            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 4, 0x60, b'\xff\xff\xff\xff\xff\xff'):
                identifier = pn532.mifare_classic_read_block(4)
            else:
                identifier = None

            if identifier is not None:
                identifier = uuid.UUID(bytes=identifier)

                issued_card = self.storage.issued_cards.get(identifier)
                if issued_card is not None:
                    access_key_B = issued_card[0]
                    if self.depersonalize_card_impl(card_uid, access_key_B):
                        del self.storage.issued_cards[identifier]
                        self.storage.save_issued_cards()
                        success = True
                else:
                    revoked_card = self.storage.revoked_cards.get(identifier)
                    if revoked_card is not None:
                        access_key_B = revoked_card[0]
                        if self.depersonalize_card_impl(card_uid, access_key_B):
                            del self.storage.revoked_cards[identifier]
                            self.storage.save_revoked_cards()
                            success = True
                if success:
                    lcd.message = "FORMAT ACK      \nREMOVE CARD ... "
                else:
                    lcd.message = "FORMAT NAK      \nREMOVE CARD ... "
            else:
                lcd.message = "FORMAT NAK      \nREMOVE CARD ... "

            time.sleep(5)
            lcd.color = (0, 0, 0)

            if success:
                return identifier
            else:
                return None

    def depersonalize_card_impl(self, card_uid: bytes, access_key_B: typing.Annotated[bytes, 6]) -> bool:
        pn532 = self.pn532

        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 3, 0x61, access_key_B):
            acl = _utils.access_bits_to_seq(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
            pn532.mifare_classic_write_block(3, b'\xff\xff\xff\xff\xff\xff' + acl + b'\x00' + b'\xff\xff\xff\xff\xff\xff')
        else:
            return False
        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 7, 0x61, access_key_B):
            acl = _utils.access_bits_to_seq(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
            pn532.mifare_classic_write_block(7, b'\xff\xff\xff\xff\xff\xff' + acl + b'\x00' + b'\xff\xff\xff\xff\xff\xff')
        else:
            return False

        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 1, 0x60, b'\xff\xff\xff\xff\xff\xff'):
            pn532.mifare_classic_write_block(1, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 2, 0x60, b'\xff\xff\xff\xff\xff\xff'):
            pn532.mifare_classic_write_block(2, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 4, 0x60, b'\xff\xff\xff\xff\xff\xff'):
            pn532.mifare_classic_write_block(4, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 5, 0x60, b'\xff\xff\xff\xff\xff\xff'):
            pn532.mifare_classic_write_block(5, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 6, 0x60, b'\xff\xff\xff\xff\xff\xff'):
            pn532.mifare_classic_write_block(6, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

        return True

    def wait_tap_cycle(self):
        pn532 = self.pn532

        card_uid = pn532.read_passive_target(timeout=5)
        if card_uid is not None:
            self.idle_card_tap_process(card_uid)

            while pn532.mifare_classic_authenticate_block(card_uid[-4:], 1, 0x60, b'\xff\xff\xff\xff\xff\xff'):
                time.sleep(1)

            self.lcd.color = (0, 0, 0)
            self.state = self.STATE_IDLE_STANDBY
        else:
            self.state = (self.state + 1) % 2

    def wait_config(self):
        if self.storage.ready_event.wait(timeout=5):
            self.state = self.STATE_IDLE_STANDBY

    def check_config(self):
        if not self.storage.ready_event.is_set():
            self.state = self.STATE_WAIT_CONFIG

    def idle_card_tap_process(self, card_uid: bytes):
        pn532 = self.pn532

        if _config.validate_sig_mifare_classic_ev1:
            # NXP originality check
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 69, 0x61, b'\x4b\x79\x1b\xea\x7b\xcc'):
                card_sig_r = pn532.mifare_classic_read_block(69)
            else:
                card_sig_r = None
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 70, 0x61, b'\x4b\x79\x1b\xea\x7b\xcc'):
                card_sig_s = pn532.mifare_classic_read_block(70)
            else:
                card_sig_s = None
            if (card_sig_r is not None) and (card_sig_s is not None):
                try:
                    self.card_sig_validator.verify_digest((card_sig_r, card_sig_s), card_uid, sigdecode=ecdsa.util.sigdecode_strings)
                except ecdsa.keys.BadSignatureError:
                    self.render_denied("fake card (sigX)")
                    return
            else:
                self.render_denied("fake card (sig-)")
                return

        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 1, 0x60, b'\xff\xff\xff\xff\xff\xff'):
            title1 = pn532.mifare_classic_read_block(1)
        else:
            title1 = None
        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 2, 0x60, b'\xff\xff\xff\xff\xff\xff'):
            title2 = pn532.mifare_classic_read_block(2)
        else:
            title2 = None

        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 4, 0x60, b'\xff\xff\xff\xff\xff\xff'):
            identifier = pn532.mifare_classic_read_block(4)
            if identifier is None:
                self.render_denied("uuid -")
                return
        else:
            self.render_denied("uuid X")
            return
        identifier = uuid.UUID(bytes=identifier)

        issued_card = self.storage.issued_cards.get(identifier)
        if issued_card is None:
            self.render_denied("unknown card")
            return

        access_key_B = issued_card[0]
        email = issued_card[1]

        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 5, 0x61, access_key_B):
            email_hash_h = pn532.mifare_classic_read_block(5)
            if email_hash_h is None:
                self.render_denied("email hash H-")
                return
        else:
            self.render_denied("email hash HX")
            return
        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 6, 0x61, access_key_B):
            email_hash_l = pn532.mifare_classic_read_block(6)
            if email_hash_l is None:
                self.render_denied("email hash L-")
                return
        else:
            self.render_denied("email hash LX")
            return

        if (email_hash_h + email_hash_l) != hashlib.sha256(email.encode('utf-8')).digest():
            self.render_denied("email hash !")
            return

        # now check the user from the database
        user = self.storage.users.get(email)
        if user is not None:
            flags = user[1]
            if flags[1:2] == b'*':
                self.render_granted(identifier, flags.decode('ascii'))
            elif flags[1:2] == b'S':
                if flags[2:4] == b'00':
                    dt = datetime.datetime.now()
                    if dt.hour >= 8 and dt.hour < 20:
                        self.render_granted(identifier, flags.decode('ascii'))
                    else:
                        self.render_denied("time limit")
                else:
                    self.render_denied("invalid schedule")
            else:
                self.render_denied("unknown flag")
        else:
            self.render_denied("unknown user")

    def loop(self):
        lcd = self.lcd
        pn532 = self.pn532

        while not self.shutdown_event.is_set():
            if self.state == self.STATE_WAIT_CONFIG:
                self.render_state_wait_config()
                self.wait_config()
                continue

            try:
                queue_item = self.queue.get(block=False)
            except queue.Empty:
                queue_item = None
            if queue_item is not None:
                if queue_item[0] == "personalize":
                    email = queue_item[1]
                    ev = queue_item[2]
                    result_box = queue_item[3]
                    try:
                        user_entry = self.storage.users.get(email)
                        if user_entry is not None:
                            flags = user_entry[1]
                            result = self.personalize_card(email)
                            if result:
                                result_box.value = (True, result)
                            else:
                                result_box.value = (False, "incomplete")
                        else:
                            result_box.value = (False, "user not found")
                    finally:
                        ev.set()
                    self.state = self.STATE_IDLE_STANDBY
                    continue
                elif queue_item[0] == "depersonalize":
                    ev = queue_item[1]
                    result_box = queue_item[2]
                    try:
                        result_box.value = self.depersonalize_card()
                    finally:
                        ev.set()
                    self.state = self.STATE_IDLE_STANDBY
                    continue
                elif queue_item[0] == "remote_admit":
                    email = queue_item[1]
                    ev = queue_item[2]
                    result_box = queue_item[3]
                    try:
                        self.remote_admit(email)
                    finally:
                        ev.set()
                    self.state = self.STATE_IDLE_STANDBY
                    continue

            if self.state == self.STATE_IDLE_STANDBY:
                self.render_idle_standby()
                self.wait_tap_cycle()
                self.check_config()
            elif self.state == self.STATE_IDLE_DATETIME:
                self.render_idle_datetime()
                self.wait_tap_cycle()
                self.check_config()
            else:
                lcd.clear()
                lcd.color = (0, 0, 0)

    def action_personalize(self, email: str) -> typing.Union[
        tuple[True, tuple[uuid.UUID, bytes, datetime.datetime]],
        tuple[False, str],
    ]:
        ev = threading.Event()
        box = Box(None)
        try:
            self.queue.put(("personalize", email, ev, box), block=False)
        except queue.Full:
            return False, "queue full"
        ev.wait()
        return box.value

    def action_depersonalize(self) -> typing.Union[
        tuple[True, uuid.UUID],
        tuple[False, str],
    ]:
        ev = threading.Event()
        box = Box(None)
        try:
            self.queue.put(("depersonalize", ev, box), block=False)
        except queue.Full:
            pass
        ev.wait()
        return box.value

    def action_revoke(self, identifier: uuid.UUID) -> None:
        issued_card = self.storage.issued_cards.get(identifier)
        if issued_card is not None:
            del self.storage.issued_cards[identifier]
            self.storage.revoked_cards[identifier] = issued_card + (datetime.datetime.now(tz=datetime.UTC), )
            
            self.storage.save_issued_cards()
            self.storage.save_revoked_cards()

    def action_remote_admit(self, email: str) -> typing.Tuple[bool, str]:
        ev = threading.Event()
        box = Box(None)
        try:
            self.queue.put(("remote_admit", email, ev, box), block=False)
        except queue.Full:
            return False, "queue_full"

        ev.wait()
        return box.value

