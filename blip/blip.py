#!/usr/bin/env python3

# External Libraries imports
from scapy_http.http import HTTP, HTTPRequest, HTTPResponse
from google.protobuf.message import DecodeError
import scapy.all as s

# Standard Library imports
from json.decoder import JSONDecodeError
from json import loads as json_loads
from sys import argv, stdout, stderr
from functools import partial
import pkg_resources  # part of setuptools
import argparse
import struct

# Project Imports
from blip.constants import MAGIC, JSON, EXCHANGES, PROTOBUF
from blip.protobuf.doubleclick_proto_pb2 import BidRequest
from blip.protobuf.blip_record_pb2 import BlipRecord

__version__ = pkg_resources.require("blip")[0].version

def parse_args(args=None):
    """Parse arguments parsed to the function and return parsed argparse object.

Keyword Arguments:
    args -- An array of string arguments, much like sys.argv passes"""
    argparser = argparse.ArgumentParser(prog="blip", description="Packet sniffing and pcap-reading utility to extract bid-request info and output either to stdout or to a file.")

    device_group = argparser.add_mutually_exclusive_group(required=True)
    device_group.add_argument('--device', '-d', type=str, metavar="DEV", default=None, help="Device from which to capture input")
    device_group.add_argument('--pcap-input', '-p', type=str, metavar="CAPFILE", default=None, help="PCAP file from which to read input")

    argparser.add_argument('--filter', '-f', type=str, default=None, help="Berkeley Packet Filter string to optionally apply on all sniffing")
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

def capture_callback(destination, content):
    """Function which will be called on each packet capture which matches the filters.

    It is meant to call other processing functions to transform
    packets into the right binary datastructures before writing them
    to output.

    Keyword Arguments:

    destination -- File-like object to which the output is written
    content -- Scapy capture object (likely a packet)

    """

    payload = extract_http_req(content)

    if payload is None:
        return

    http_item = payload.getlayer(HTTPRequest) or payload.getlayer(HTTPResponse)

    if http_item is None:
        return

    try:
        raw_path = http_item.fields["Path"]
        if raw_path is not None:
            path = raw_path.decode('utf-8')
        else:
            return
    except KeyError:
        return

    payload_type = try_parse_protobuf(http_item) or try_parse_json(http_item)

    if payload_type is None:
        return

    prepared_output = prepare_output(path, http_item.payload.raw_packet_cache, payload_type)
    destination.write(prepared_output)

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

def try_parse_json(http_item):
    """Attempt to parse as JSON and return the type id.
Return None on failure.

Keyword Arguments:
    http_item -- An HTTPResponse or HTTPRequest object

    """
    raw_json = http_item.payload.raw_packet_cache
    try:
        json_out = json_loads(raw_json.decode())
        return JSON
    except (JSONDecodeError, TypeError, AttributeError):
        return None

def try_parse_protobuf(http_item):
    """Attempt to parse as protobuf as return the type id.
Return None on failure.

Keyword Arguments:
    http_item -- An HTTPResponse or HTTPRequest object

    """
    try:
        protobuf = BidRequest.FromString(http_item.payload.raw_packet_cache)
        return PROTOBUF # Protobuf output = 1
    except (DecodeError, TypeError):
        return None

def extract_http_req(packet):
    """Attempts to extracts an HTTP payload from a raw packet and returns it"""
    http = HTTP()
    ll_pkt = packet.lastlayer()
    http.dissect(ll_pkt.raw_packet_cache) # Setting the object from the input
    return http

def http_req_filter(packet):
    """Checks if the passed packet contains HTTPRequest content

    Keyword Arguments:

    packet -- Any packet object
    """

    last_layer = packet.lastlayer()
    http = HTTP()
    res_class = http.guess_payload_class(last_layer.raw_packet_cache)
    return res_class == HTTPRequest

def capture_traffic(pargs):
    """Initiate capture of data from a device or pcap file"""
    is_dev = pargs.device is not None
    with pargs.output as out: # Ensure proper resource disposal
        callback = partial(capture_callback, out) # This may or may not lead to more context-switching than closures depending on internal implementation.

        if is_dev:
            s.sniff(prn=callback, count=pargs.limit, iface=pargs.device, lfilter=http_req_filter, filter=pargs.filter, store=False)
        else:
            s.sniff(prn=callback, count=pargs.limit, offline=pargs.pcap_input, lfilter=http_req_filter, filter=pargs.filter, store=False)

def main(args=None):
    """blip main entry point, provides all functionality"""
    pargs = parse_args(args)
    capture_traffic(pargs)

if __name__ == '__main__':
    main()
