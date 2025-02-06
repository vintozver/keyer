#!/usr/bin/env python3

import binascii
import datetime
import gpiozero
import hashlib
import os
import pickle
import pprint
import queue
import threading
import time
import typing

from adafruit_character_lcd.character_lcd import Character_LCD_RGB
from adafruit_pn532.adafruit_pn532 import PN532
import ecdsa

from . import utils as _utils


class Box(object):
    def __init__(self, value):
        self.value = value


class Dispatcher(object):
    IDLE_STANDBY = 0
    IDLE_DATETIME = 1

    # https://blog.linuxgemini.space/derive-pk-of-nxp-mifare-classic-ev1-ecdsa-signature
    # https://github.com/MichaelsPlayground/NfcMifareClassicEv1VerifyOriginalitySignature/blob/master/app/src/main/java/de/androidcrypto/nfcmifareclassicev1verifyoriginalitysignature/MainActivity.java#L53
    SIG_PK_NXP_MIFARE_CLASSIC_EV1 = binascii.unhexlify("044F6D3F294DEA5737F0F46FFEE88A356EED95695DD7E0C27A591E6F6F65962BAF")

    def __init__(self, lcd: Character_LCD_RGB, pn532: PN532, buzzer: gpiozero.TonalBuzzer, relay: gpiozero.LED):
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

        try:
            with open("authorized_cards.bin", "rb") as f:
                self.authorized_cards = pickle.load(f)
        except FileNotFoundError:
            self.authorized_cards = {
                # email_hash -> email, access_key_B(6-byte), dt-created(UTC)
            }

        print("***authorized cards ***")
        print(pprint.pformat(self.authorized_cards, width=320))

        try:
            with open("revoked_cards.bin", "rb") as f:
                self.revoked_cards = pickle.load(f)
        except FileNotFoundError:
            self.revoked_cards = [
                # email_hash, email, access_key_B(6-byte), dt-created(UTC), dt-revoked(UTC)
            ]

        print("***revoked cards ***")
        print(pprint.pformat(self.revoked_cards, width=320))

        self.users = {
            # email -> name, unit_number, flags, dt-created(UTC)
            # flags (one byte per line)
            #   O(owner), R(resident)
            #   *(unlimited access), S(scheduled access, 2 bytes scheduler identifier follow)
        }

        self.queue = queue.Queue(4)
        self.idle_screen = self.IDLE_STANDBY

    def shutdown(self):
        self.shutdown_event.set()

    def store_authorized_cards(self):
        with open("authorized_cards.bin", "wb") as f:
            pickle.dump(self.authorized_cards, f)
            f.flush()

    def store_revoked_cards(self):
        with open("revoked_cards.bin", "wb") as f:
            pickle.dump(self.revoked_cards, f)
            f.flush()

    def render_idle_standby(self):
        self.lcd.message = "ASPGR Game Room \nTAP CARD ...    "
        self.lcd.color = (0, 0, 100)

    def render_idle_datetime(self):
        dt = datetime.datetime.now()
        self.lcd.message = "%04d-%02d-%02d %02d:%02d\nTAP CARD ...    " % (dt.year, dt.month, dt.day, dt.hour, dt.minute)
        self.lcd.color = (0, 0, 100)

    def render_granted(self, description: typing.Annotated[str, 4], flags: typing.Annotated[str, 16], remote: bool = False):
        if remote:
            self.lcd.message = "REMOTE UNL  %4s\n%16s" % (description, flags)
            self.lcd.color = (100, 100, 0)
            self.relay.blink(on_time=5.0, off_time=1.0, n=1, background=True)
            self.buzzer.play(220)
            time.sleep(1)
            self.buzzer.stop()
        else:
            self.lcd.message = "WELCOME     %4s\n%16s" % (description, flags)
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

    def remote_admit(self, email: str):
        user = self.users.get(email)
        if user is not None:
            unit_number = user[1]
            flags = user[2]
            if flags[1:2] == b'*':
                self.render_granted(unit_number, flags.decode('ascii'), remote=True)
            elif flags[1:2] == b'S':
                if flags[2:4] == b'00':
                    dt = datetime.datetime.now()
                    if dt.hour >= 8 and dt.hour < 20:
                        self.render_granted(unit_number, flags.decode('ascii'), remote=True)
                    else:
                        self.render_denied("time limit")
                else:
                    self.render_denied("invalid schedule")
            else:
                self.render_denied("unknown flag")
        else:
            self.render_denied("unknown user")

    def personalize_card(self, email: str, description: typing.Annotated[str, 16]) -> bool:
        lcd = self.lcd
        pn532 = self.pn532

        lcd.message = "PERSONALIZING   \nTAP CARD ...    "
        lcd.color = (100, 100, 100)
        ok = True
        email_hash = hashlib.sha256(email.encode('utf-8')).digest()
        authorized_card_record = self.authorized_cards.get(email_hash)
        if authorized_card_record is not None:
            if authorized_card_record[0] == email:
                access_key_B = authorized_card_record[1]
            else:
                lcd.message = "email mismatch  \nERROR           "
                time.sleep(5)
                return
        else:
            access_key_B = os.urandom(6)
            self.authorized_cards[email_hash] = (email, access_key_B, datetime.datetime.utcnow())
            self.store_authorized_cards()

        card_uid = pn532.read_passive_target(timeout=5)
        if card_uid is not None:
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
                        0, 1, 1,  # block 4
                        1, 0, 0,  # block 5
                        1, 0, 0,  # block 6
                        0, 1, 1,  # block 7 (sector trailer)
                    )
                    pn532.mifare_classic_write_block(7, b'\xff\xff\xff\xff\xff\xff' + acl + b'\x00' + access_key_B)
                else:
                    lcd.message = "BLOCK3 NOT AUTHN\nERROR           "
                    ok = False
            if ok:
                if pn532.mifare_classic_authenticate_block(card_uid[-4:], 1, 0x61, access_key_B):
                    pn532.mifare_classic_write_block(1, b'Aspen Grove     ')
                else:
                    lcd.message = "BLOCK1 NOT AUTHN\nERROR           "
                    ok = False
            if ok:
                if pn532.mifare_classic_authenticate_block(card_uid[-4:], 2, 0x61, access_key_B):
                    pn532.mifare_classic_write_block(2, b'Game Room       ')
                else:
                    lcd.message = "BLOCK2 NOT AUTHN\nERROR           "
                    ok = False
            if ok:
                if pn532.mifare_classic_authenticate_block(card_uid[-4:], 4, 0x61, access_key_B):
                    pn532.mifare_classic_write_block(4, description.ljust(16)[:16].encode('ascii'))
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

        if (card_uid is not None) and ok:
            lcd.message = "PERSONALIZING OK\nREMOVE CARD ... "
            time.sleep(5)
            lcd.color = (0, 0, 0)
            return True
        else:
            return False

    def depersonalize_card(self):
        lcd = self.lcd
        pn532 = self.pn532

        lcd.message = "DEPERSONALIZING \nTAP CARD ...    "
        lcd.color = (100, 100, 100)

        card_uid = pn532.read_passive_target(timeout=5)
        if card_uid is not None:
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 5, 0x60, b'\xff\xff\xff\xff\xff\xff'):
                email_hash_h = pn532.mifare_classic_read_block(5)
            else:
                email_hash_h = None
            if pn532.mifare_classic_authenticate_block(card_uid[-4:], 6, 0x60, b'\xff\xff\xff\xff\xff\xff'):
                email_hash_l = pn532.mifare_classic_read_block(6)
            else:
                email_hash_l = None

            if (email_hash_l is not None and email_hash_h is not None):
                email_hash = email_hash_h + email_hash_l
            else:
                email_hash = None

            if email_hash is not None:
                success = False
                authorized_card = self.authorized_cards.get(email_hash)
                if authorized_card is not None:  # found authorized card
                    email = authorized_card[0]
                    access_key_B = authorized_card[1]
                    if self.depersonalize_card_by_key(card_uid, access_key_B):
                        success = True
                if not success:
                    # try revoked cards
                    for access_key_B in map(
                        lambda map_item: map_item[2],
                        filter(
                            lambda filter_item: filter_item[0] == email_hash,
                            self.revoked_cards
                        )
                    ):
                        if self.depersonalize_card_by_key(card_uid, access_key_B):
                            success = True
                            break
                if success:
                    lcd.message = "FORMAT ACK      \nREMOVE CARD ... "
                else:
                    lcd.message = "FORMAT NAK      \nREMOVE CARD ... "
            else:
                lcd.message = "FORMAT NAK      \nREMOVE CARD ... "

            time.sleep(5)
            lcd.color = (0, 0, 0)

    def depersonalize_card_by_key(self, card_uid: bytes, access_key_B: typing.Annotated[bytes, 6]) -> bool:
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
            self.idle_screen = self.IDLE_STANDBY
        else:
            self.idle_screen = (self.idle_screen + 1) % 2

    def idle_card_tap_process(self, card_uid: bytes):
        pn532 = self.pn532

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
        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 5, 0x60, b'\xff\xff\xff\xff\xff\xff'):
            email_hash_h = pn532.mifare_classic_read_block(5)
        else:
            email_hash_h = None
        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 6, 0x60, b'\xff\xff\xff\xff\xff\xff'):
            email_hash_l = pn532.mifare_classic_read_block(6)
        else:
            email_hash_l = None

        if (email_hash_l is not None and email_hash_h is not None):
            email_hash = email_hash_h + email_hash_l
        else:
            self.render_denied("invalid card")
            return

        authorized_card = self.authorized_cards.get(email_hash)
        if authorized_card is None:
            # card not authorized properly
            # email_hash must have a match of email & acces_key_B
            self.render_denied("unknown card")
            return

        email = authorized_card[0]
        access_key_B = authorized_card[1]

        # attempt to read block4 with unit_number and flags
        # this is merely an authentication of the card
        # all permissions are enforced by the database
        if pn532.mifare_classic_authenticate_block(card_uid[-4:], 4, 0x61, access_key_B):
            description = pn532.mifare_classic_read_block(4)
            if description is None:
                self.render_denied("card read X")
                return
        else:
            self.render_denied("card authN X")
            return

        # now check the user from the database
        user = self.users.get(email)
        if user is not None:
            unit_number = user[1]
            flags = user[2]
            if flags[1:2] == b'*':
                self.render_granted(unit_number, flags.decode('ascii'))
            elif flags[1:2] == b'S':
                if flags[2:4] == b'00':
                    dt = datetime.datetime.now()
                    if dt.hour >= 8 and dt.hour < 20:
                        self.render_granted(unit_number, flags.decode('ascii'))
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
                        user_entry = self.users.get(email)
                        if user_entry is not None:
                            unit_number = user_entry[1]
                            flags = user_entry[2]
                            if self.personalize_card(email, unit_number + " " + flags.decode("ascii")):
                                result_box.value = (True, "complete")
                            else:
                                result_box.value = (False, "incomplete")
                        else:
                            result_box.value = (False, "user not found")
                    finally:
                        ev.set()
                    self.idle_screen = self.IDLE_STANDBY
                    continue
                elif queue_item[0] == "depersonalize":
                    self.depersonalize_card()
                    self.idle_screen = self.IDLE_STANDBY
                    continue
                elif queue_item[0] == "remote_admit":
                    email = queue_item[1]
                    ev = queue_item[2]
                    result_box = queue_item[3]
                    try:
                        self.remote_admit(email)
                    finally:
                        ev.set()
                    self.idle_screen = self.IDLE_STANDBY
                    continue

            if self.idle_screen == self.IDLE_STANDBY:
                self.render_idle_standby()
                self.wait_tap_cycle()
            elif self.idle_screen == self.IDLE_DATETIME:
                self.render_idle_datetime()
                self.wait_tap_cycle()
            else:
                lcd.clear()
                lcd.color = (0, 0, 0)

    def action_personalize(self, email: str) -> typing.Tuple[bool, str]:
        ev = threading.Event()
        box = Box(None)
        try:
            self.queue.put(("personalize", email, ev, box), block=False)
        except queue.Full:
            return False, "queue full"

        ev.wait()
        return box.value

    def action_depersonalize(self) -> None:
        try:
            self.queue.put(("depersonalize", ), block=False)
        except queue.Full:
            pass

    def action_revoke(self, email: str) -> None:
        email_hash = hashlib.sha256(email.encode('utf-8')).digest()
        authorized_card = self.authorized_cards.get(email_hash)
        if authorized_card is not None:
            self.revoked_cards.append((email_hash, ) + authorized_card + (datetime.datetime.utcnow(), ))
            del self.authorized_cards[email_hash]
            
            self.store_authorized_cards()
            self.store_revoked_cards()

    def action_remote_admit(self, email: str) -> typing.Tuple[bool, str]:
        ev = threading.Event()
        box = Box(None)
        try:
            self.queue.put(("remote_admit", email, ev, box), block=False)
        except queue.Full:
            return False, "queue_full"

        ev.wait()
        return box.value

