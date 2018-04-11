#!/usr/bin/env python3

# External Libraries imports
from google.protobuf.message import DecodeError
import pcapy
import dpkt

# Standard Library imports
from sys import argv, stdout, stderr, exit as sys_exit
from tempfile import NamedTemporaryFile
from os.path import isfile as os_isfile
from re import compile as re_compile
from traceback import print_exc
from functools import partial
import pkg_resources  # part of setuptools
import configparser
import argparse
import logging
import struct

# Project Imports
from blip.constants import MAGIC, JSON, PROTOBUF
from blip.protobuf.doubleclick_proto_pb2 import BidRequest
from blip.encoding import BlipRecord, write_record

# Retrocompatiblity fix
try:
    from json.decoder import JSONDecodeError
    from json import loads as json_loads
except ImportError:
     # Python 3.4 doesn't have JSONDecodeError
    from simplejson.decoder import JSONDecodeError
    from simplejson import loads as json_loads

# Proper Signal Handling
from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE, SIG_DFL)

__logger__ = logging.getLogger(__name__)
__version__ = pkg_resources.require("blip")[0].version
__configparser__ = configparser.ConfigParser()

def parse_args(args=None):
    """Parse arguments parsed to the function and return parsed argparse object.

Keyword Arguments:
    args -- An array of string arguments, much like sys.argv passes"""
    argparser = argparse.ArgumentParser(prog="blip", description="Packet sniffing and pcap-reading utility to extract bid-request info and output either to stdout or to a file.")

    device_group = argparser.add_mutually_exclusive_group(required=True)
    device_group.add_argument('--device', '-d', type=str, metavar="DEV", default=None, help="Device from which to capture input")
    device_group.add_argument('--pcap-input', '-p', type=str, metavar="CAPFILE", default=None, help="PCAP file from which to read input")

    argparser.add_argument('--filter', '-f', type=str, default="", help="Berkeley Packet Filter string to optionally apply on all sniffing")
    argparser.add_argument('--output', '-O',
                           type=argparse.FileType('wb'),
                           metavar='FILE', help="Write binary output to FILE instead of stdout",
                           default=stdout.buffer)
    argparser.add_argument('--limit', '-l', type=int, metavar="NUM", help="Only capture NUM packets", default=0)
    argparser.add_argument('--log-level', '-L', type=str, metavar='LEVEL', choices=['debug', 'info', 'warning', 'error', 'critical'],
                           help="Log level to filter to from program logging output.", default="warning")
    argparser.add_argument('--log-output', '-o', type=str)
    argparser.add_argument('--config','-c', type=str, nargs="+", metavar="FILE", help="Configuration file(s) to use.", required=True)
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
        __logger__.debug("Dropping packet with '/' path.")
        return # All valid BidRequests have a path

    req_body = http_pkt.body
    if len(req_body) <= 0:
        __logger__.debug("Dropping http packet with empty body.")
        return # Improper request

    payload_type = try_parse_json(req_body)

    if payload_type is None:
        payload_type = try_parse_protobuf(req_body)

    if payload_type is None:
        return # Invalid payload

    write_output(path, payload_type, req_body, destination)

def write_output(path, payload_type, payload, fd):
    """Take the request path, payload_type, raw payload and write them to
output file-descriptor

Keyword Arguments:
    path -- Decoded payload, can be any format defined in /docs
    payload_type -- Integer which determines the payload format, as define in /docs
    payload -- Raw binary payload, can be any format defined in /docs
    fd -- File Descriptor to write output to

    """
    exchange = try_get_exchange(path)
    if exchange is None:
        return

    record = BlipRecord(exchange, payload_type, payload)
    __logger__.debug("Writing record to disk: {}".format(record))

    write_record(record, fd)

def try_get_exchange(exchange_path,
                     matcher=re_compile(r"/requests/[a-zA-Z0-9]+"),
                     configparse=__configparser__):
    """Attempt to find an exchange id for a provided exchange path.
Return None on failure.

Keyword Arguments:
    exchange_path -- HTTP path possibly corresponding to a valid exchange id
    matcher -- Compiled SRE Pattern used to sanitize paths.
    """
    try:
        sanitized_exchange = matcher.search(exchange_path).group(0)
        exchange = configparse['EXCHANGES'].getint(sanitized_exchange)
        return exchange
    except (KeyError, AttributeError):
        __logger__.debug("Fail to find exchange id for: {}".format(exchange_path))
        return None

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
        __logger__.debug("Failed to find valid json payload.")
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
        __logger__.debug("Failed to find valid protobuf payload.")
        return None


def try_extract_tcp(eth_payload):
    """Attempt to extract a TCP dictionary from raw bytes.
Return None on failure."""

    try:
        eth = dpkt.ethernet.Ethernet(eth_payload)
        ip = eth.ip
        tcp = ip.tcp
    except AttributeError as e:
        __logger__.debug("Failed to extract packet information on packet.")
        return None

    return tcp

def try_extract_http(data):
    """Attempt to extract an HTTP request from raw bytes.
Return None on failure."""

    try:
        req = dpkt.http.Request(data)
    except dpkt.dpkt.UnpackError:
        __logger__.debug("Failed to extract http request from tcp packet.")
        return None

    return req

def capture_traffic(pargs):
    """Initiate capture of data from a device or pcap file"""
    is_dev = pargs.device is not None
    with pargs.output as out: # Ensure proper resource disposal
        callback = partial(capture_callback, out) # This may or may not lead to more context-switching than closures depending on internal implementation.
        __logger__.info("Capturing from {}.".format("device" if is_dev else "pcap"))

        reader = pcapy.open_live(pargs.device, 65535, False, 500) if is_dev else pcapy.open_offline(pargs.pcap_input)
        reader.setfilter(pargs.filter)
        reader.loop(pargs.limit, callback)

def setup_log(level, logfile):
    """Setup a logger to provide debugging information

Keyword Arguments:
    level -- Debug level to use, from ['debug', 'info', 'warning', 'error', 'critical']
    logfile -- Name of the logfile."""
    vlevel = getattr(logging, level.upper())
    __logger__.setLevel(vlevel)

    # ensure logfile target exists
    if not logfile:
        logfile = create_logfile()

    # create a file handler
    handler = logging.FileHandler(logfile)
    handler.setLevel(logging.DEBUG) # ensure handler picks up everything

    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # add the handlers to the logger
    __logger__.addHandler(handler)

def create_logfile():
    """Create a new temporary file for logs and return its filename"""
    with NamedTemporaryFile(prefix="{}_".format(__name__),suffix=".log", delete=False) as f:
        return f.name

def manage_config(files):
    """Update the __configparser__ using the passed files.

Keyword Arguments:
    files -- List of strings representing paths or filenames"""
    if not files or not all(os_isfile(x) for x in files):
        stderr.write("One or more of the files passed as argument for config do not exist.\n")
        sys_exit(1)

    try:
        __configparser__.read(files)
    except configparser.Error as e:
        stderr.write("Error: {}\n".format(e.message))
        sys_exit(1)

def main(args=None):
    """blip main entry point, provides all functionality"""
    try:
        pargs = parse_args(args)
        manage_config(pargs.config)
        setup_log(pargs.log_level, pargs.log_output)

        __logger__.debug("Run program with arguments: {}".format(pargs))
        capture_traffic(pargs)
    except KeyboardInterrupt:
        __logger__.debug("Program shutdown via KeyboardInterrupt.")
        pass
    except Exception:
        print_exc(file=stderr)
        sys_exit(1)
    else:
        __logger__.info("Program finished without any errors.")
        sys_exit(0)

if __name__ == '__main__':
    main()
