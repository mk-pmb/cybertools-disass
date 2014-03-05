#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

#############################################################################
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
# 001dd76872d80801692ff942308c64e6
# 002325a0a67fded0381b5648d7fe9b8e
# 052ec04866e4a67f31845d656531830d
# 2f930d92dc5ebc9d53ad2a2b451ebf65
# 3e87051b1dc3463f378c7e1fe398dc7d
# 55886d571c2a57984ea9659b57e1c63a
# 8a86df3d382bfd1e4c4165f4cacfdff8


def reverse(path, verbose):
    disass = Disass32(path=path, verbose=verbose)

    disass.go_to_next_call('strncmp')

    try:
    	addr = disass.get_arguments(1)
        print "  CC\t: %s" % disass.get_string(addr)
    except:
	pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='apt1_tabmsgsql_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true',
                        default=False)

    parser.add_argument('path', help='path to analyze', nargs="*")
    args = parser.parse_args()

    if len(args.path) == 0:
        print "Usage : apt1_tabmsgsql_parser.py apt1_tabmsgsql.infected"
        sys.exit(1)

    for path in args.path:
        reverse(path=path, verbose=args.verbose)
