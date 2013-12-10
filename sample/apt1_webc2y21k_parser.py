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
# 2479a9a50308cb72fcd5e4e18ef06468
# 4cabfaef26fd8e5aec01d0c4b90a32f3


def reverse(path, verbose):
    disass = Disass32(path=path, verbose=verbose)

    disass.make_xref()

    for p in disass.xref['InternetConnectA']:
        disass.set_position(p)

        disass.update_stack_and_register()
        try:
            addr = disass.get_arguments(2)
            print "  CC\t: %s" % disass.get_string(addr)
        except:
            continue

        if not disass.go_to_next_call('HttpOpenRequestA'):
            continue

        try:
            lpszVerb = disass.get_string(disass.get_arguments(2))
            lpszObjectName = disass.get_string(disass.get_arguments(3))
            lpszVersion = disass.get_string(disass.get_arguments(4))

            print "  Request\t: %s %s %s" % (lpszVerb,lpszObjectName,lpszVersion)
        except Exception as e:
            print str(e)
            continue



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='apt1webc2y21k_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true',
                        default=False)

    parser.add_argument('path', help='path to analyze', nargs="*")
    args = parser.parse_args()

    if len(args.path) == 0:
        print "Usage : apt1_webc2y21k_parser.py apt1webc2y21k.infected"
        sys.exit(1)

    for path in args.path:
        reverse(path=path, verbose=args.verbose)