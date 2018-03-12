#!/usr/bin/env python3

from sys import argv, stdout, stderr
import argparse

__version__ = "1.0.0"

def parse_args(args=None):
    argparser = argparse.ArgumentParser(prog="blip", description="Packet sniffing and pcap-reading utility to extract bid-request info and output either to stdout or to a file.")

    device_group = argparser.add_mutually_exclusive_group(required=True)
    device_group.add_argument('--device', '-d', type=str, metavar="DEV", nargs=1, default=None, help="Device from which to capture input")
    device_group.add_argument('--pcap-input', '-p', type=str, nargs=1, metavar="CAPFILE", default=None, help="PCAP file from which to read input")

    argparser.add_argument('--output','-o', nargs='?',
                           type=argparse.FileType('w'),
                           metavar='FILE', help="Write binary output to FILE instead of stdout",
                           default=stdout, const=stdout)
    argparser.add_argument('--version', '-v', action='version', version="{} {}".format('%(prog)s', __version__))
    argparser.add_argument('--limit', '-l', nargs=1, type=int, metavar="NUM", help="Only capture NUM packets")
    return argparser.parse_args(args) if args is not None else argparser.parse_args() # Allow REPL debugging with arg lists

def main(args=None):
    pargs = parse_args(args)

if __name__ == '__main__':
    main()
