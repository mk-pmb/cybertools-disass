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

#Tested on
# 575836ebb1b8849f04e994e9160370e4
# 73d125f84503bd87f8142cf2ba8ab05e
# a38a367d6696ba90b2e778a5a4bf98fd
# f1e5d9bf7705b4dc5be0b8a90b73a863
#


def reverse(path, verbose):
    disass = Disass32(path=path, verbose=verbose)

    if not disass.go_to_next_call('InternetConnectA'):
        print >> sys.stderr, "InternetConnectA not found in %s" % path
        return

    fn = disass.where_am_i()

    address_cc = disass.get_arguments(2)
    print "  CC\t:", disass.get_string(address_cc)

    disass.set_position(disass.map_call_by_name[fn])

    if not disass.go_to_next_call('strcpy'):
        print >> sys.stderr, "strcat not found in %s" % path
        return

    address_url = disass.get_arguments(2)
    print "  URL\t:", disass.get_string(address_url)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='apt1webc2cson_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true',
                        default=False)

    parser.add_argument('path', help='path to analyze', nargs="*")
    args = parser.parse_args()

    if len(args.path) == 0:
        print "Usage : apt1_webc2cson_parser.py apt1webc2cson.infected"
        sys.exit(1)

    for path in args.path:
        reverse(path=path, verbose=args.verbose)