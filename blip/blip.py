#!/usr/bin/env python3

# External Libraries imports
from google.protobuf.message import DecodeError
import pcapy
import dpkt

# Standard Library imports
from json import loads as json_loads
from sys import argv, stdout, stderr
from functools import partial
import pkg_resources  # part of setuptools
import argparse
import struct

# Project Imports
from blip.constants import MAGIC, JSON, EXCHANGES, PROTOBUF
from blip.protobuf.doubleclick_proto_pb2 import BidRequest
from blip.encoding import BlipRecord, write_record

# Retrocompatiblity fix
try:
    from json.decoder import JSONDecodeError
except:
     # Python 3.4 doesn't have JSONDecodeError, instead use ValueError
    JSONDecodeError = ValueError

__version__ = pkg_resources.require("blip")[0].version

def parse_args(args=None):
    """Parse arguments parsed to the function and return parsed argparse object.

Keyword Arguments:
    args -- An array of string arguments, much like sys.argv passes"""
    argparser = argparse.ArgumentParser(prog="blip", description="Packet sniffing and pcap-reading utility to extract bid-request info and output either to stdout or to a file.")

    device_group = argparser.add_mutually_exclusive_group(required=True)
    device_group.add_argument('--device', '-d', type=str, metavar="DEV", default=None, help="Device from which to capture input")
    device_group.add_argument('--pcap-input', '-p', type=str, metavar="CAPFILE", default=None, help="PCAP file from which to read input")

    argparser.add_argument('--filter', '-f', type=str, default="", help="Berkeley Packet Filter string to optionally apply on all sniffing")
    argparser.add_argument('--output', '-o',
                           type=argparse.FileType('wb'),
                           metavar='FILE', help="Write binary output to FILE instead of stdout",
                           default=stdout.buffer)
    argparser.add_argument('--limit', '-l', type=int, metavar="NUM", help="Only capture NUM packets", default=0)
    argparser.add_argument('--version', '-v', action='version', version="{} {}".format('%(prog)s', __version__))

    parsed = argparser.parse_args(args) if args is not None else argparser.parse_args() # Allow REPL debugging with arg lists
    if parsed.output.name == stdout.name:
        parsed.output = stdout.buffer # Prevent stdout with 'w' rather than 'wb' permission issues
    return parsed

def capture_callback(destination, header, content):
    """Function which will be called on each packet capture which matches the filters.

    It is meant to call other processing functions to transform
    packets into the right binary datastructures before writing them
    to output.

    Keyword Arguments:

    destination -- File-like object to which the output is written
    header -- pcap capture header
    content -- pcap capture data

    """

    tcp_pkt = try_extract_tcp(content)
    if tcp_pkt is None:
        return

    http_pkt = try_extract_http(tcp_pkt.data)
    if http_pkt is None:
        return

    path = http_pkt.uri
    if path == '/':
        return # All valid BidRequests have a path

    req_body = http_pkt.body
    if len(req_body) <= 0:
        return # Improper request

    payload_type = try_parse_protobuf(req_body) or try_parse_json(req_body)
    if payload_type is None:
        return # Invalid payload

    write_output(path, payload_type, req_body, destination)

def write_output(path, payload_type, payload, fd):
    exchange = EXCHANGES[path]
    record = BlipRecord(exchange, payload_type, payload)
    write_record(record, fd)

def prepare_output(path, raw_load, load_type, builder=struct.Struct("!4sBIB")):
    """Take the request path, raw payload and loadtime, return as binary-packed structure

Keyword Arguments:
    load -- Decoded payload, can be any format defined in /docs
    raw_load -- Raw binary payload, can be any format defined in /docs
    load_type -- Integer which determines the payload format, as define in /docs
    builder -- Auto-instantiated builder for structures

Returns:
    bytes -- A binary structure containing all the passed information.

"""
    exchange = EXCHANGES[path]
    length = len(raw_load)

    out = builder.pack(MAGIC, exchange, length, load_type) + raw_load

    return out

def try_parse_json(http_body):
    """Attempt to parse as JSON and return the type id.
Return None on failure.

Keyword Arguments:
    http_body -- The raw body of an http request or response

    """
    raw_json = http_body
    try:
        json_out = json_loads(raw_json.decode())
        return JSON
    except (JSONDecodeError, UnicodeDecodeError, TypeError, AttributeError):
        return None

def try_parse_protobuf(http_body):
    """Attempt to parse as protobuf as return the type id.
Return None on failure.

Keyword Arguments:
    http_body -- The raw body of an http request or response

    """
    try:
        protobuf = BidRequest.FromString(http_body)
        return PROTOBUF # Protobuf output = 1
    except (DecodeError, TypeError):
        return None


def try_extract_tcp(eth_payload):
    """Attempt to extract a TCP dictionary from raw bytes.
Return None on failure."""

    try:
        eth = dpkt.ethernet.Ethernet(eth_payload)
        ip = eth.ip
        tcp = ip.tcp
    except AttributeError:
        return None

    return tcp

def try_extract_http(data):
    """Attempt to extract an HTTP request or response from raw bytes.
Return None on failure."""

    value = try_extract_request(data) or try_extract_response(data)
    return value

def try_extract_request(data):
    """Attempt to extract an HTTP request from raw bytes.
Return None on failure."""

    try:
        req = dpkt.http.Request(data)
    except dpkt.dpkt.UnpackError:
        return None

    return req

def try_extract_response(data):
    """Attempt to extract an HTTP response from raw bytes.
Return None on failure."""

    try:
        req = dpkt.http.Response(data)
    except dpkt.dpkt.UnpackError:
        return None

    return req

def capture_traffic(pargs):
    """Initiate capture of data from a device or pcap file"""
    is_dev = pargs.device is not None
    with pargs.output as out: # Ensure proper resource disposal
        callback = partial(capture_callback, out) # This may or may not lead to more context-switching than closures depending on internal implementation.

        reader = pcapy.open_live(pargs.device) if is_dev else pcapy.open_offline(pargs.pcap_input)
        reader.setfilter(pargs.filter)
        reader.loop(pargs.limit, callback)

def main(args=None):
    """blip main entry point, provides all functionality"""
    pargs = parse_args(args)
    capture_traffic(pargs)

if __name__ == '__main__':
    main()
