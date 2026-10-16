import datetime
import hashlib
import json
import queue
import signal
import sys
import threading
import unittest
import uuid
from unittest import mock

import test_control as control


with mock.patch.dict(sys.modules, {
    name: mock.MagicMock() for name in (
        'board', 'busio', 'serial', 'gpiozero', 'gpiozero.pins', 'gpiozero.pins.pigpio',
        'adafruit_character_lcd', 'adafruit_character_lcd.character_lcd',
        'adafruit_character_lcd.character_lcd_rgb_i2c',
        'adafruit_pn532', 'adafruit_pn532.adafruit_pn532', 'adafruit_pn532.uart', 'ecdsa',
    )
}):
    from src import dispatcher
    from src import worker


class CardEventTests(unittest.TestCase):
    def setUp(self):
        self.dispatcher = object.__new__(dispatcher.Dispatcher)
        self.dispatcher.storage = control.storage.Base()
        self.dispatcher.storage.save_issued_cards = mock.Mock()
        self.dispatcher.storage.save_revoked_cards = mock.Mock()
        self.dispatcher.pn532 = mock.Mock()
        self.dispatcher.lcd = mock.Mock()
        self.dispatcher.render_denied = mock.Mock()
        self.dispatcher.render_granted = mock.Mock()
        self.dispatcher.render_remote_admit = mock.Mock()
        self.dispatcher._present_card_uid = None
        self.dispatcher.state = dispatcher.Dispatcher.STATE_IDLE_STANDBY
        self.dispatcher.shutdown_event = threading.Event()
        self.card_uid = b'\x01\x02\x03\x04'
        self.identifier = uuid.uuid4()
        self.email = 'resident@example.com'
        self.store = self.dispatcher.storage
        self.store.users[self.email] = ('Resident', b'R*', datetime.datetime.now(datetime.UTC))
        self.card = (b'key123', self.email, datetime.datetime.now(datetime.UTC))
        self.store.issued_cards[self.identifier] = self.card
        self.pn532 = self.dispatcher.pn532
        self.pn532.read_passive_target.return_value = self.card_uid
        self.pn532.mifare_classic_authenticate_block.return_value = True
        self.pn532.mifare_classic_write_block.return_value = True
        email_hash = hashlib.sha256(self.email.encode()).digest()
        self.pn532.mifare_classic_read_block.side_effect = lambda block: {
            1: b'title1', 2: b'title2', 4: self.identifier.bytes,
            5: email_hash[:16], 6: email_hash[16:],
        }.get(block)
        self.sleep = mock.patch.object(dispatcher.time, 'sleep')
        self.sleep.start()
        self.addCleanup(self.sleep.stop)

    def events(self):
        return [json.loads(record) for record in self.store._events]

    def tap(self):
        self.dispatcher.idle_card_tap_process(self.card_uid)

    def assert_event(self, event, identifier=None):
        self.assertEqual(len(self.events()), 1)
        record = self.events()[0]
        self.assertEqual(record['event'], event)
        self.assertEqual(set(record), {'oid', 'event', 'card_id'})
        self.assertEqual(record['card_id'], str(identifier or self.identifier))

    def test_verified_granted_tap(self):
        self.tap()
        self.assert_event('card_tap')
        self.dispatcher.render_granted.assert_called_once()

    def test_verified_but_denied_tap_keeps_card_uuid(self):
        self.store.users[self.email] = ('Resident', b'R?', None)
        self.tap()
        self.assert_event('card_tap')
        self.dispatcher.render_denied.assert_called_once_with('unknown flag')

    def test_unknown_card_tap_sends_card_uuid(self):
        self.store.issued_cards.clear()
        self.tap()
        self.assert_event('card_tap')

    def test_failed_ownership_verification_still_sends_card_uuid(self):
        self.pn532.mifare_classic_authenticate_block.side_effect = (
            lambda uid, block, *args: block != 5)
        self.tap()
        self.assert_event('card_tap')
        self.dispatcher.render_denied.assert_called_once_with('email hash HX')

    def test_forged_email_hash_still_sends_card_uuid_without_granting_access(self):
        self.pn532.mifare_classic_read_block.side_effect = lambda block: (
            self.identifier.bytes if block == 4 else b'\x00' * 16)
        self.tap()
        self.assert_event('card_tap')
        self.dispatcher.render_granted.assert_not_called()
        self.dispatcher.render_denied.assert_called_once_with('email hash !')

    def test_missing_user_still_sends_card_uuid(self):
        self.store.users.clear()
        self.tap()
        self.assert_event('card_tap')

    def test_same_denied_presentation_is_logged_only_once_until_removed(self):
        self.store.issued_cards.clear()
        self.dispatcher.wait_tap_cycle()
        self.dispatcher.wait_tap_cycle()
        self.assert_event('card_tap')
        self.pn532.read_passive_target.return_value = None
        self.dispatcher.wait_tap_cycle()
        self.pn532.read_passive_target.return_value = self.card_uid
        self.dispatcher.wait_tap_cycle()
        self.assertEqual(len(self.events()), 2)
        self.assertNotEqual(self.events()[0]['oid'], self.events()[1]['oid'])

    def test_unreadable_or_invalid_uuid_is_reported_without_fabricating_an_event(self):
        for identifier in (None, b'short'):
            with self.subTest(identifier=identifier):
                self.dispatcher._present_card_uid = None
                self.pn532.mifare_classic_read_block.side_effect = None
                self.pn532.mifare_classic_read_block.return_value = identifier
                with mock.patch.object(dispatcher.sys, 'stderr') as stderr:
                    self.tap()
                self.assertTrue(stderr.write.called)
                self.assertFalse(self.events())
        self.dispatcher._present_card_uid = None
        self.pn532.mifare_classic_authenticate_block.return_value = False
        self.tap()
        self.assertFalse(self.events())

    def test_different_card_is_a_new_presentation(self):
        self.tap()
        self.dispatcher.idle_card_tap_process(b'\x05\x06\x07\x08')
        self.assertEqual(len(self.events()), 2)

    def test_personalization_success_and_no_duplicate_idle_tap(self):
        result = self.dispatcher.personalize_card(self.email)
        self.assertIsNotNone(result)
        self.assert_event('card_personalize', result[0])
        self.tap()
        self.assert_event('card_personalize', result[0])

    def test_personalization_failure_does_not_log_success(self):
        for failed_write in range(7):
            with self.subTest(failed_write=failed_write):
                self.pn532.mifare_classic_write_block.side_effect = [True] * failed_write + [False]
                self.assertIsNone(self.dispatcher.personalize_card(self.email))
                self.assertFalse(self.events())
        self.pn532.mifare_classic_write_block.side_effect = None
        self.pn532.mifare_classic_authenticate_block.return_value = False
        self.assertIsNone(self.dispatcher.personalize_card(self.email))
        self.assertFalse(self.events())

    def test_no_card_does_not_log_personalization_or_formatting(self):
        self.pn532.read_passive_target.return_value = None
        self.assertIsNone(self.dispatcher.personalize_card(self.email))
        self.assertIsNone(self.dispatcher.depersonalize_card())
        self.assertFalse(self.events())

    def test_formatting_captures_issued_and_revoked_uuid_before_deletion(self):
        for revoked in (False, True):
            with self.subTest(revoked=revoked):
                self.store._events.clear()
                self.store.issued_cards.clear()
                self.store.revoked_cards.clear()
                cards = self.store.revoked_cards if revoked else self.store.issued_cards
                cards[self.identifier] = self.card + ((datetime.datetime.now(datetime.UTC),) if revoked else ())
                original = self.store.enqueue_event

                def enqueue(event, card_id):
                    self.assertIn(self.identifier, cards)
                    self.assertEqual(card_id, self.identifier)
                    original(event, card_id)

                with mock.patch.object(self.store, 'enqueue_event', side_effect=enqueue):
                    self.assertEqual(self.dispatcher.depersonalize_card(), self.identifier)
                self.assertNotIn(self.identifier, cards)
                self.assert_event('card_format')
                self.tap()
                self.assert_event('card_format')

    def test_formatting_failure_does_not_log_or_delete_card(self):
        for failed_write in range(7):
            with self.subTest(failed_write=failed_write):
                self.pn532.mifare_classic_write_block.side_effect = [True] * failed_write + [False]
                self.assertIsNone(self.dispatcher.depersonalize_card())
                self.assertIn(self.identifier, self.store.issued_cards)
                self.assertFalse(self.events())
        self.pn532.mifare_classic_write_block.side_effect = None
        self.pn532.mifare_classic_authenticate_block.return_value = False
        self.assertIsNone(self.dispatcher.depersonalize_card())
        self.assertFalse(self.events())

    def test_controller_only_operations_do_not_enqueue(self):
        self.dispatcher.remote_admit(self.email)
        self.dispatcher.action_revoke(self.identifier)
        self.assertFalse(self.events())

    def test_overflow_is_not_swallowed_by_dispatcher(self):
        self.store.EVENT_QUEUE_LIMIT = 0
        with self.assertRaises(queue.Full):
            self.tap()

    def test_signal_waits_for_active_card_operation_before_final_flush(self):
        handlers = {}
        self.store.shutdown = mock.Mock()

        def active_operation():
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            self.assertTrue(self.dispatcher.shutdown_event.is_set())
            self.store.shutdown.assert_not_called()
            self.store.enqueue_event('card_personalize', self.identifier)

        def flush():
            self.assert_event('card_personalize')

        self.store.shutdown.side_effect = flush
        self.dispatcher.loop = active_operation
        with mock.patch.object(worker._dispatcher, 'Dispatcher', return_value=self.dispatcher), \
                mock.patch.object(worker, 'HttpServer'), \
                mock.patch.object(worker.threading, 'Thread'), \
                mock.patch.object(worker.os, 'unlink'), \
                mock.patch.object(worker.os, 'umask'), \
                mock.patch.object(worker.signal, 'signal',
                                  side_effect=lambda sig, handler: handlers.update({sig: handler})):
            worker.main()
        self.store.shutdown.assert_called_once()
