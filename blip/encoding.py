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
from sys import stderr, exit as sys_exit
from contextlib import contextmanager
from traceback import print_exc
from blip.constants import MAGIC

# Proper Signal Handling
from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE, SIG_DFL)

class IncorrectMagicException(Exception): pass
class IncorrectLengthException(Exception): pass
class PayloadTooShortException(Exception): pass

class BlipRecord():
    """Container class for blip record metadata."""
    converter = Struct(
        "!"  # network order
        "4s" # 4-char string: magic number
        "B"  # byte: exchange id
        "I"  # uint32: length of the payload
        "B"  # byte: type (JSON or Protobuf)
    )

    def __init__(self, exchange, payload_type, payload):
        self.exchange = exchange
        self.payload_type = payload_type
        self.payload = payload

    def __repr__(self):
        return "<Record: Exchange={}, Type={}, Length={}, Payload={}>".format(
            self.exchange, self.payload_type, len(self.payload), self.payload)

def read_record(fd):
    """
    Read a Record from a file handle.
    """
    header = fd.read(BlipRecord.converter.size)
    try:
        (magic, exchange, length, payload_type) = BlipRecord.converter.unpack(header)
    except struct_error:
        raise IncorrectLengthException()

    if magic != MAGIC:
        raise IncorrectMagicException()

    payload = fd.read(length)
    if len(payload) < length:
        raise PayloadTooShortException()
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
    """Yield all BlipRecords from the provided file handle."""
    while True:
        try:
            res = read_record(fd)
        except (IncorrectMagicException, IncorrectLengthException):
            return

        yield res

def print_contents_cli():
    """Reads the content of a provided input and writes a string
representation of all BlipRecord objects found to output

Input -- is stdin by default unless changed by arguments
Ouptut -- is stdout by default unless changed by arguments

---
Program entry_point for blip_showdb"""
    try:
        parsed = parse_args_cli()
        with parsed.input as fd:
            for item in records_from_fd(fd):
                out_bytes = format_output_bytes(item, parsed.truncate)
                parsed.output.write(out_bytes)
    except KeyboardInterrupt:
        pass
    except Exception:
        print_exc(file=stderr)
        sys_exit(1)
    sys_exit(0)

def format_output_bytes(record, truncate):
    """Return a byte-string representation of a BlipRecord.
    If `truncate` is True, the payload is replaced with the
    string "..."

    Keyword Arguments:
    record -- BlipRecord object
    truncate -- Boolean argument which causes truncation on True
    """
    fmt_string = "<Record: Exchange={}, Type={}, Length={}, Payload={}>\n"
    payload = "..." if truncate else record.payload
    return bytes(fmt_string.format(
        record.exchange, record.payload_type, len(record.payload), payload), 'utf-8')

def parse_args_cli(args=None):
    """Parse arguments parsed to the function and return parsed argparse object.

Keyword Arguments:
    args -- An array of string arguments, much like sys.argv passes"""
    from sys import stdout, stderr, stdin
    import argparse

    # Imports are run once and cached. This function should only run
    # in CLI, importing them globably is wasteful.

    argparser = argparse.ArgumentParser(prog="blip_showdb", description="Pretty print the contents of a blip binary file to stdout.")

    argparser.add_argument('input', type=argparse.FileType('rb'), metavar="SOURCE", nargs='?', help="Source from which to obtain binary contents.",
                           default=stdin.buffer)
    argparser.add_argument('--output', '-o',
                           type=argparse.FileType('wb'),
                           metavar='FILE', help="Write binary output to FILE instead of stdout",
                           default=stdout.buffer)
    argparser.add_argument("--truncate", "-t", help="Indicate payload output should be truncated.", action='store_true')

    parsed = argparser.parse_args(args) if args is not None else argparser.parse_args() # Allow REPL debugging with arg lists
    if parsed.output.name == stdout.name:
        parsed.output = stdout.buffer # Prevent stdout with 'w' rather than 'wb' permission issues
    if parsed.input.name == stdin.name:
        parsed.input = stdin.buffer
    return parsed
