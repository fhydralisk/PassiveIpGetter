from socket import socket, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST
import struct
import sys
import re


def print_usage():
    print "Usage: WOLSender.py macaddress"
    exit(1)


def parse_mac(macaddr):
    pattern = re.compile(r'(?:[\da-fA-F]{1,2}([:\-])){5}[\da-fA-F]{1,2}')
    mr = pattern.match(macaddr)
    if mr is not None:
        macs = macaddr.split(mr.group(1))
        return macs

    return None


def run(macaddr):
    mac = parse_mac(macaddr)
    if mac is None:
        return False

    s = socket(type=SOCK_DGRAM)
    s.setsockopt(SOL_SOCKET, SO_BROADCAST, True)
    macs = tuple(int(m, 16) for m in mac)
    lead_code = struct.pack('6B', 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
    mac_bin = struct.pack('6B', *macs)
    magic = lead_code
    for i in range(16):
        magic += mac_bin

    print magic
    for i in range(4):
        s.sendto(magic, ('255.255.255.255', 9))
    return True

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print_usage()

    macaddr = sys.argv[1]

    if not parse_mac(macaddr):
        print_usage()

    run(macaddr)
