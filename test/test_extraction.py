from blip import blip
from test import httprequests
import unittest
import dpkt

class TestExtractors(unittest.TestCase):
    example_request = b''
    def setUp(self):
        global example_request
        example_request = httprequests.request

    def tearDown(self):
        global example_request
        example_request = b''

    def test_empty_extractors(self):
        payload = b''

        with self.assertRaises((dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError)):
            tcp = blip.try_extract_tcp(payload)
            http = blip.try_extract_http(payload)

            self.assertIsNone(tcp)
            self.assertIsNone(http)

    def test_tcp_garbage(self):
        payload = b'11111111111111111111111111'
        tcp = blip.try_extract_tcp(payload)

        self.assertIsNone(tcp)

    def test_tcp_extractor(self):
        tcp = blip.try_extract_tcp(example_request)

        self.assertIsNotNone(tcp)
        self.assertTrue(len(tcp.data) > 0)
        self.assertIsInstance(tcp, dpkt.tcp.TCP)

    def test_http_extract_req(self):
        tcp = blip.try_extract_tcp(example_request)
        http = blip.try_extract_http(tcp.data)

        self.assertIsNotNone(http)
        self.assertIsInstance(http, dpkt.http.Message)
        self.assertIsInstance(http, dpkt.http.Request)

    def test_http_garbage(self):
        payload = b'11111111111111111111111111'
        http = blip.try_extract_http(payload)

        self.assertIsNone(http)
