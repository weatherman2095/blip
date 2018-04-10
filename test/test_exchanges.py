import configparser
import unittest
from blip import blip

class TestExchanges(unittest.TestCase):
    cparser = None

    def setUp(self):
        global __configparser__
        __configparser__ = configparser.ConfigParser()
        __configparser__['EXCHANGES'] = {
            '/requests/whatever': '1'
        }

    def tearDown(self):
        global __configparser__
        __configparser__ = None

    def test_empty_exchange(self):
        exchange = ''
        ex = blip.try_get_exchange(exchange, configparse=__configparser__)
        self.assertIsNone(ex)

    def test_invalid_exchange(self):
        exchange = '/notanexchange/endpoint'
        ex = blip.try_get_exchange(exchange, configparse=__configparser__)
        self.assertIsNone(ex)

    def test_valid_exchange(self):
        exchange = '/requests/whatever'
        ex = blip.try_get_exchange(exchange, configparse=__configparser__)
        self.assertEqual(ex, 1)

    def test_rest_exchange(self):
        exchange = '/requests/whatever/1' # Any appends should be ignored
        ex = blip.try_get_exchange(exchange, configparse=__configparser__)
        self.assertEqual(ex, 1)

    def test_ignore_null_get(self):
        exchange = '/requests/whatever?' # Any appends should be ignored
        ex = blip.try_get_exchange(exchange, configparse=__configparser__)
        self.assertEqual(ex, 1)

    def test_ignore_get(self):
        exchange = '/requests/whatever?first=hello&second=world'
        ex = blip.try_get_exchange(exchange, configparse=__configparser__)
        self.assertEqual(ex, 1)
