"""
Format
------
    File   ::= Record*
    Record ::= <Magic: 4> <Exchange Id: 1> <Length: 4> <Type: 1> <Payload: N>

Invariants
----------
    Magic  = "BLIP"
    Length = N
"""

from struct import Struct, error as struct_error
from blip.constants import MAGIC
from contextlib import contextmanager

class IncorrectMagicException(Exception): pass
class IncorrectLengthException(Exception): pass

class BlipRecord():
    """Container class for blip record metadata.

Fields:

    exchange -- Numerical exchange ID (uint8)
    payload_type -- Numerical payload type (uint8)
    payload -- Binary payload, typed according to payload_type"""
    converter = Struct("!4sBIB")

    def __init__(self, exchange, payload_type, payload):
        self.exchange = exchange
        self.payload_type = payload_type
        self.payload = payload

    def __repr__(self):
        return "<Record: exchange={}, type={}, length={}, payload={}..>".format(
            self.exchange, self.payload_type, len(self.payload), self.payload)

def read_record(fd):
    """
    Read a Record from a file handle.
    """
    header = fd.read(10)
    try:
        rheader = BlipRecord.converter.unpack(header)
    except struct_error:
        raise IncorrectLengthException()

    magic = rheader[0]
    if magic != MAGIC:
        raise IncorrectMagicException()

    exchange = rheader[1]
    length = rheader[2]
    payload_type = rheader[3]
    payload = fd.read(length)
    return BlipRecord(exchange, payload_type, payload)

def write_record(record, fd):
    """
    Write a Record to a file handle.
    """
    output_b = BlipRecord.converter.pack(MAGIC, record.exchange,
                                       len(record.payload), record.payload_type)
    final_out = output_b + record.payload
    fd.write(final_out)

@contextmanager
def read_record_file(filename):
    """Return a generator for all records in `filename` as the context value.

Properly disposes of the file context as required."""
    with open(filename, "rb") as f:
        yield records_from_fd(f)

def records_from_fd(fd):
    """Yield all records from the provided file handle."""
    while True:
        try:
            res = read_record(fd)
        except (IncorrectMagicException, IncorrectLengthException):
            raise StopIteration

        yield res

def test():
    recs = [BlipRecord(3, 0, b"{CASALE JSON}"),
            BlipRecord(6, 0, b"{ADGEAR JSON}")]

    with open("records.bin", "wb") as fd:
        for r in recs:
            write_record(r, fd)
            print("Wrote: {}".format(r.__repr__()))

    with open("records.bin", "rb") as fd:
        while True:
            try:
                r = read_record(fd)
                print("Read: %r" % r)
            except (IncorrectMagicException, IncorrectLengthException) as e:
                break

    print("Now testing generator")
    with open("records.bin", 'rb') as f:
        for item in records_from_fd(f):
            print("Iterated on: {}".format(item))

    print("Now testing contextmanager")
    with read_record_file("records.bin") as reader:
        for item in reader:
            print("Reader said: {}".format(item))

if __name__ == "__main__":
     test()
