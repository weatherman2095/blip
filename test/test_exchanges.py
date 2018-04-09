import unittest
from blip import blip
from blip.constants import EXCHANGES

class TestExchanges(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_empty_exchange(self):
        exchange = ''
        ex = blip.try_get_exchange(exchange)
        self.assertIsNone(ex)

    def test_invalid_exchange(self):
        exchange = '/notanexchange/endpoint'
        ex = blip.try_get_exchange(exchange)
        self.assertIsNone(ex)

    def test_valid_exchange(self):
        exchange = 'REDACTED'
        ex = blip.try_get_exchange(exchange)
        self.assertEqual(ex, EXCHANGES[exchange])

    def test_rest_exchange(self):
        exchange = 'REDACTED/1' # Any appends should be ignored
        ex = blip.try_get_exchange(exchange)
        self.assertEqual(ex, EXCHANGES["REDACTED"])

    def test_ignore_null_get(self):
        exchange = 'REDACTED?' # Any appends should be ignored
        ex = blip.try_get_exchange(exchange)
        self.assertEqual(ex, EXCHANGES["REDACTED"])

    def test_ignore_get(self):
        exchange = 'REDACTED?first=hello&second=world'
        ex = blip.try_get_exchange(exchange)
        self.assertEqual(ex, EXCHANGES["REDACTED"])

