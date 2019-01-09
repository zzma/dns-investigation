#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
GT PCAP Extractor and Cleaner

This script is used to extract DNS records from GT PCAPs and clean the results
by filtering out any transient traffic.
"""

__author__ = 'Chaz Lever'
__version__ = 1.0

import glob
import gzip
import itertools
import os
import pcap_extractor
import urllib
from datetime import datetime
from multiprocessing import Pool


def _parse_dns_from_pcap(inpath, outpath):
    try:
        with pcap_extractor.DnsPcapExtractor(inpath) as pcap:
            basename = os.path.basename(inpath)
            basename = '{0}.csv.gz'.format(".".join(basename.split('.')[:-1]))
            outpath = os.path.join(outpath, basename)
            with gzip.open(outpath, 'w') as fw:
                fw.write('timestamp|src|dst|ttl|rcode|qtype|qname|rdata\n')
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
    except:
        status = 'FAILED'
    else:
        status = 'SUCCESS'

    return (status, inpath, outpath)


def _parse_dns_from_pcap_wrapper(args):
    return _parse_dns_from_pcap(*args)


def _main():
    import argparse
    parser = argparse.ArgumentParser(
        description=' '.join(__doc__.split('\n')[3:]))

    parser.add_argument(
        '-n', '--num-procs',
        dest='num_procs',
        type=int,
        default=1,
        help='Number of processes to use.')

    parser.add_argument(
        '-p', '--pattern',
        dest='pattern',
        default='*.gz',
        help='Input file search pattern')

    parser.add_argument(
        'outpath',
        help='Output directory path.')

    parser.add_argument(
        'inpath',
        help='Input directory path.')

    args = parser.parse_args()

    try:
        os.makedirs(args.outpath)
    except OSError:
        pass

    pool = Pool(args.num_procs)
    pattern = os.path.join(args.inpath, args.pattern)
    files = (f for f in glob.iglob(pattern) if os.path.isfile(f))
    fargs = itertools.izip_longest(files, (), fillvalue=args.outpath)
    results = pool.imap_unordered(_parse_dns_from_pcap_wrapper, fargs)
    for status, inpath, outpath in results:
        ts = datetime.strftime(datetime.now(), '[%c]')
        print ts, status, inpath, '==>', outpath

    # Clean up and exit gracefully
    pool.close()
    pool.join()

if __name__ == '__main__':
    _main()
