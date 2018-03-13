1#!/usr/bin/env python3

from sys import argv, stdout, stderr
import scapy.all as s
import argparse

__version__ = "1.0.0"

def parse_args(args=None):
    argparser = argparse.ArgumentParser(prog="blip", description="Packet sniffing and pcap-reading utility to extract bid-request info and output either to stdout or to a file.")

    device_group = argparser.add_mutually_exclusive_group(required=True)
    device_group.add_argument('--device', '-d', type=str, metavar="DEV", default=None, help="Device from which to capture input")
    device_group.add_argument('--pcap-input', '-p', type=str, metavar="CAPFILE", default=None, help="PCAP file from which to read input")
    argparser.add_argument('--filter','-f', type=str, default=None, help="Berkeley Packet Filter string to optionally apply on all sniffing")

    argparser.add_argument('--output','-o', nargs='?',
                           type=argparse.FileType('w'),
                           metavar='FILE', help="Write binary output to FILE instead of stdout",
                           default=stdout, const=stdout)
    argparser.add_argument('--version', '-v', action='version', version="{} {}".format('%(prog)s', __version__))
    argparser.add_argument('--limit', '-l', type=int, metavar="NUM", help="Only capture NUM packets")
    return argparser.parse_args(args) if args is not None else argparser.parse_args() # Allow REPL debugging with arg lists

def capture_callback(content):
    """Function which will be called on each packet capture which matches
the filters."""
    content.show()

def http_filter(packet):
    """Checks if the passed packet contains http content."""
    return False

def main(args=None):
    pargs = parse_args(args)
    is_dev = pargs.device is not None
    if is_dev:
        with pargs.device as dev: # Ensure proper resource disposal
            s.sniff(prn=capture_callback, iface=dev, lfilter=http_filter, filter=pargs.filter)
    else:
        s.sniff(prn=capture_callback, offline=pargs.pcap_input, lfilter=http_filter, filter=pargs.filter)

if __name__ == '__main__':
    main()
