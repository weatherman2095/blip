from struct import error as struct_error
import unittest
import re
import io

import blip.encoding as be
import blip.constants as bc

class TestDecoder(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_empty_content(self):
        byte_file = io.BytesIO()
        with self.assertRaises(be.IncorrectLengthException):
            record = be.read_record(byte_file)

    def test_invalid_longcontent(self):
        byte_file = io.BytesIO(bytes(12))
        with self.assertRaises(be.IncorrectMagicException):
            record = be.read_record(byte_file)

    def test_invalid_content(self):
        byte_file = io.BytesIO(bytes(10))
        with self.assertRaises(be.IncorrectMagicException):
            record = be.read_record(byte_file)

    def test_valid_content(self):
        byte_file = io.BytesIO()
        # "4sBIB"+? = <MAGIC><ID><Length><Type><Payload> :: MAGIC -> BLIP
        binary_record = b'BLIP\x01\x00\x00\x00\x04\x00\xff\xff\xff\xff'
        byte_file.write(binary_record)
        byte_file.seek(0)
        record = be.read_record(byte_file)

        self.assertEqual(record.exchange, 1)
        self.assertEqual(record.payload_type, bc.JSON)
        self.assertEqual(len(record.payload), 4)

class TestEncoder(unittest.TestCase):
    def test_fails_without_file(self):
        record = be.BlipRecord(1,0,b'Hello World')
        with self.assertRaisesRegex(AttributeError, "object has no attribute 'write'"):
            be.write_record(record, None)

    def test_with_file(self):
        record = be.BlipRecord(1,0,b'Hello World')
        byte_file = io.BytesIO()

        be.write_record(record, byte_file)
        byte_file.seek(0)

        binary_content = byte_file.read()
        bytelength = 4 + 1 + 4 + 1 + len(b'Hello World')

        self.assertEqual(bytelength, len(binary_content))

    def test_null_values(self):
        pattern = "(required argument is not a. .+|object of type 'NoneType' has no len())"
        exception_match = re.compile(pattern)
        with self.assertRaisesRegex((struct_error, TypeError), exception_match):
            record = be.BlipRecord(None, None, None)
            byte_file = io.BytesIO()

            be.write_record(record, byte_file)
            byte_file.seek(0)

            binary_content = byte_file.read()
            bytelength = 4 + 1 + 4 + 1 + len(None) # Expected Error, Payloads should not be None

            self.assertEqual(bytelength, len(binary_content))

    def test_empty_payload(self):
        record = be.BlipRecord(0, 0, b'')
        byte_file = io.BytesIO()

        be.write_record(record, byte_file)
        byte_file.seek(0)

        binary_content = byte_file.read()
        bytelength = 4 + 1 + 4 + 1 + len(b'')

        self.assertEqual(bytelength, len(binary_content))


class TestGenerator(unittest.TestCase):
    def test_working(self):
        binary_records = io.BytesIO()
        words = [b'Hello', b'World', b'I', b'Exist']
        be.write_record(be.BlipRecord(1,0,words[0]), binary_records)
        be.write_record(be.BlipRecord(2,1,words[1]), binary_records)
        be.write_record(be.BlipRecord(1,0,words[2]), binary_records)
        be.write_record(be.BlipRecord(2,1,words[3]), binary_records)
        binary_records.seek(0)

        count = 0
        for record in be.records_from_fd(binary_records):
            self.assertEqual(words[count], record.payload)
            count += 1

        self.assertEqual(4, count)


# The old test pollutes the filesystem, therefore manual-use only.
def manual_test():
    recs = [be.BlipRecord(3, 0, b"{CASALE JSON}"),
            be.BlipRecord(6, 0, b"{ADGEAR JSON}")]

    with open("records.bin", "wb") as fd:
        for record in recs:
            be.write_record(record, fd)
            print("Wrote: {}".format(record.__repr__()))

    with open("records.bin", "rb") as fd:
        while True:
            try:
                record = be.read_record(fd)
                print("Read: {}".format(record))
            except (be.IncorrectMagicException, be.IncorrectLengthException) as e:
                break

    print("Now testing generator")
    with open("records.bin", 'rb') as f:
        for item in be.records_from_fd(f):
            print("Iterated on: {}".format(item))

    print("Now testing contextmanager")
    with be.read_record_file("records.bin") as reader:
        for item in reader:
            print("Reader said: {}".format(item))

    print("\nRemember to delete 'records.bin' once you are done.")


if __name__ == '__main__':
    unittest.main()
