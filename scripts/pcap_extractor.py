#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
DNS Pcap Parser

Uses `dpkt` and `dnslib` to parse DNS packets from a PCAP file and extracts DNS
response records.
"""

__author__ = 'Chaz Lever'
__version__ = '1.0.0'

import dnslib
import dpkt
import gzip
import socket
import urllib


class DnsPcapExtractor(object):
    """
    Extract DNS records from a PCAP file

    Basic Usage::

      >>> with DnsPcapExtractor(path) as pcap:
      >>>     for record in pcap:
      >>>         ts, src, dst, ttl, qname, qtype, rdata = record
    """
    def __init__(self, path):
        """
        Constructs a new :class:`DnsPcapExtractor <DnsPcapExtractor>` object.

        :param path: path to pcap file to parse
        """
        self._path = path
        self._pcap = None

    def __enter__(self):
        return self.open()

    def __exit__(self, type, value, traceback):
        self.close()

    def __iter__(self):
        try:
            for record in self._iterate():
                yield record
        except (dpkt.NeedData, TypeError):
            raise StopIteration

    def _iterate(self):
        for ts, buf in self._pcap:
            # Parse the raw packet
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type != 2048:
                    print("Invalid Eth Type")
                    # Not a valid IPv4 packet
                    continue
                ip = eth.data
                udp = ip.data
                if (udp.dport != 53 and udp.sport != 53) or len(udp.data) <= 0:
                    # Not a valid DNS packet
                    print("Invalid DNS port")
                    continue
                dns = dnslib.DNSRecord.parse(udp.data)
            except GeneratorExit:
                raise dpkt.NeedData
            except Exception as e:
                #print(e)
                #print("src:", socket.inet_ntop(socket.AF_INET, ip.src))
                #print("dst:", socket.inet_ntop(socket.AF_INET, ip.dst))
                #print(":".join("{:02x}".format(ord(c)) for c in udp.data))
                continue

            # Handle DNS record
            try:
                #if ((dns.header.rcode in [dnslib.RCODE.reverse['NOERROR'], dnslib.RCODE.reverse['NXDOMAIN']]) and
                #        dns.header.rd == 1 and  # Recursion Desired
                #        dns.header.qr == dnslib.QR.reverse['RESPONSE'] and
                #        dns.header.opcode == dnslib.OPCODE.reverse['QUERY']):
                if True:
                    src = socket.inet_ntop(socket.AF_INET, ip.src)
                    dst = socket.inet_ntop(socket.AF_INET, ip.dst)
                    # Get Answer, Auth, and Additional Sections
                    for section in (dns.rr, dns.auth, dns.ar):
                        for rr in section:
                            yield(
                                ts,
                                src,
                                dst,
                                rr.ttl,
                                dns.header.rcode,
                                dnslib.QTYPE.forward[rr.rtype],
                                str(rr.rname),
                                str(rr.rdata),
                            )
            except GeneratorExit:
                raise dpkt.NeedData
            except Exception as e:
                print(e)
                continue

    def open(self):
        """
        Open the pcap specified in the constructor and readies
        :class:`DnsPcapExtractor <DnsPcapExtractor>` for iteration.
        """
        try:
            self._fh = gzip.open(self._path, 'rb')
            self._pcap = dpkt.pcap.Reader(self._fh)
        except IOError:
            self._fh = None
            self._pcap = None
        else:
            return self

        try:
            self._fh = open(self._path, 'rb')
            self._pcap = dpkt.pcap.Reader(self._fh)
        except Exception as e:
            print("Error reading pcap: " + str(e))
            self._fh = None
            self._pcap = None
            raise
        finally:
            return self

    def close(self):
        """
        Close the pcap file specified in the constructor.
        """
        try:
            self._fh.close()
        except AttributeError:
            pass
        finally:
            self._pcap = None


def _main():
    import argparse

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description=' '.join(__doc__.split('\n')[3:]))

    parser.add_argument(
        'outpath',
        help='Output path for parsed result.')

    parser.add_argument(
        'inpath',
        help='Input path to PCAP file.')

    args = parser.parse_args()

    with DnsPcapExtractor(args.inpath) as pcap:
        with gzip.open(args.outpath, 'w') as fw:
            for record in pcap:
                ts, src, dst, ttl, rcode, qtype, qname, rdata = record
                fw.write('{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}\n'.format(
                    ts,
                    src,
                    dst,
                    ttl,
                    rcode,
                    qtype,
                    qname,
                    urllib.quote(rdata),
                ))

if __name__ == '__main__':
    _main()
