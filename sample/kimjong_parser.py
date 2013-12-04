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


def reverse(path, verbose):
    disass = Disass32(path=path, verbose=verbose)

    addressInjectDLL = disass.symbols_exported_by_name['InjectDLL']

    disass.set_position(addressInjectDLL)

    if disass.go_to_next_call('CreateMutexA'):
        address_mutex = disass.get_arguments(3)
        print "  Mutex\t\t:", disass.get_string(address_mutex)


    if disass.go_to_next_call('InternetOpenA'):
        disass.up()
        disass.up()
        print "  UserAgent\t:", disass.get_string(disass.get_arguments(3))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='kimjong_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true',
                        default=False)

    parser.add_argument('path', help='path to analyze', nargs="*")
    args = parser.parse_args()

    if len(args.path) == 0:
        print "Usage : kimjong_parser.py sysninit.ocx.infected"
        sys.exit(1)

    for path in args.path:
        reverse(path=path, verbose=args.verbose)