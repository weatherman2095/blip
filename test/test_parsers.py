from test import httprequests
from blip import blip
import unittest
import json

class TestParsers(unittest.TestCase):
    example_request = b''
    def setUp(self):
        global example_request
        example_request = httprequests.request

    def tearDown(self):
        global example_request
        example_request = b''

    def test_empty_json(self):
        js = blip.try_parse_json(b'')
        self.assertIsNone(js)

    def test_empty_protobuf(self):
        pb = blip.try_parse_protobuf(b'')
        self.assertTrue(pb == None or pb == 1)

    def test_garbage_protobuf(self):
        pb = blip.try_parse_protobuf(b'111111111111111111111')
        self.assertIsNone(pb)
