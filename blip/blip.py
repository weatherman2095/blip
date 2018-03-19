#!/usr/bin/env python3

from sys import argv, stdout, stderr
from functools import partial

import pkg_resources  # part of setuptools
import argparse

try: # Original comments may or may not be accurate depending on setuptools environment
    # This import works from the project directory
    from  scapy_http.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http
import scapy.all as s

__version__ = pkg_resources.require("blip")[0].version

def parse_args(args=None):
    """Parse arguments parsed to the function and return parsed argparse object

Keyword Arguments:
    args -- An array of string arguments, much like sys.argv passes"""
    argparser = argparse.ArgumentParser(prog="blip", description="Packet sniffing and pcap-reading utility to extract bid-request info and output either to stdout or to a file.")

    device_group = argparser.add_mutually_exclusive_group(required=True)
    device_group.add_argument('--device', '-d', type=str, metavar="DEV", default=None, help="Device from which to capture input")
    device_group.add_argument('--pcap-input', '-p', type=str, metavar="CAPFILE", default=None, help="PCAP file from which to read input")

    argparser.add_argument('--filter','-f', type=str, default=None, help="Berkeley Packet Filter string to optionally apply on all sniffing")
    argparser.add_argument('--output','-o',
                           type=argparse.FileType('wb'),
                           metavar='FILE', help="Write binary output to FILE instead of stdout",
                           default=stdout.buffer)
    argparser.add_argument('--limit', '-l', type=int, metavar="NUM", help="Only capture NUM packets", default=0)
    argparser.add_argument('--version', '-v', action='version', version="{} {}".format('%(prog)s', __version__))

    parsed = argparser.parse_args(args) if args is not None else argparser.parse_args() # Allow REPL debugging with arg lists
    if parsed.output.name == stdout.name:
        parsed.output = stdout.buffer # Prevent stdout with 'w' permission issues
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

    destination.write(bytes(content.payload))

def extract_http_req(packet):
    """Attempts to extracts an HTTP payload from a raw packet and returns it"""
    http = HTTP()
    ll_pkt = packet.last_layer()
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
    is_dev = pargs.device is not None
    with pargs.output as out: # Ensure proper resource disposal
        callback = partial(capture_callback, out) # This may or may not lead to more context-switching than closures depending on internal implementation.

        if is_dev:
            s.sniff(prn=callback, count=pargs.limit, iface=pargs.device, lfilter=http_req_filter, filter=pargs.filter)
        else:
            s.sniff(prn=callback, count=pargs.limit, offline=pargs.pcap_input, lfilter=http_req_filter, filter=pargs.filter)

def main(args=None):
    pargs = parse_args(args)
    capture_traffic(pargs)

if __name__ == '__main__':
    main()
