#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## This file is part of Disass                                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2013 Cassidian CyberSecurity SAS. All rights reserved.    ##
## This document is the property of Cassidian CyberSecurity SAS, it may    ##
## not be circulated without prior licence                                 ##
##                                                                         ##
##  Author: Ivan Fontarensky <ivan.fontarensky@cassidian.com>              ##
##                                                                         ##
#############################################################################

__author__ = 'ifontarensky'

import sys
import argparse
from disass.Disass32 import Disass32

# tabmsgsq - Sluegot - Letsgo
# Tested on
# 052ec04866e4a67f31845d656531830d
# 8a86df3d382bfd1e4c4165f4cacfdff8
# f1c02fc41a99b00bbee328e0cbbe747b


def reverse_v1(disass):

    name_dropped_files = disass.where_am_i()
    addr_dropped_files = disass.map_call_by_name[name_dropped_files]

    disass.up()

    d = 0
    while disass.go_to_next_call('strcpy'):
        try:
            address_url_value = disass.get_arguments(2)
            url = disass.get_string(address_url_value)
            print "  C&C%d\t\t: %s" % (d, url[url.find('http'):])
            d += 1
        except:
            continue

    disass.set_position(addr_dropped_files)
    while disass.go_to_next_call('sprintf'):
        print "  Dropped\t:", disass.get_string(disass.get_arguments(2))


def reverse_v2(disass):
    disass.set_position(disass.get_entry_point())
    if disass.go_to_next_call('strncmp'):
        cc = disass.get_string(disass.get_arguments(1))
        print "  C&C\t\t:", cc

    if disass.go_to_next_call('InternetCrackUrlA'):
        disass.up()
        ua = disass.get_arguments(2)
        print "  UserAgent\t:", disass.get_string(ua)

def reverse(path, verbose):

    disass = Disass32(path=path, verbose=verbose)

    if disass.go_to_next_call('CreateMutex'):
        address_mutex = disass.get_arguments(3)
        mutex = disass.get_string(address_mutex)
        print "  Mutex\t\t:", mutex

        version = mutex.split('v')[1]
        print "  Version\t:", version

        if version[0] == '1':
            # Version 1
            reverse_v1(disass)
            return

        elif version[0] == '2':
            #Version 2
            reverse_v2(disass)
            return

    try:
        reverse_v1(disass)
    except:
        print "Not supported"
    return




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='sluegot_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true',
                        default=False)

    parser.add_argument('path', help='path to analyze', nargs="*")

    args = parser.parse_args()

    if len(args.path) == 0:
        print "Usage : sluegot_parser.py sluegot.infected"
        sys.exit(1)

    for path in args.path:
        reverse(path=path, verbose=args.verbose)