#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## This file is part of Disass                                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2013 Cassidian CyberSecurity SAS. All rights reserved.    ##
## This document is the property of Cassidian SyberSecurity SAS, it may    ##
## not be circulated without prior licence                                 ##
##                                                                         ##
##  Author: Ivan Fontarensky <ivan.fontarensky@cassidian.com>              ##
##                                                                         ##
#############################################################################

__author__ = 'ifontarensky'

import sys
import argparse
from disass.Disass32 import Disass32


def reverse_minjat(path, verbose):

    disass = Disass32(path=path, verbose=verbose)

    if not disass.go_to_function('CreateThread'):
        print >> sys.stderr, "CreateThread not found"
        sys.exit(0)

    # CreateThread( ..., ... , ... )
    startAddress = disass.get_arguments()[2]

    # We set our position in this Thread
    disass.set_position(startAddress - disass.pe.OPTIONAL_HEADER.ImageBase)

    # We are searching when C&C are copy
    if not disass.go_to_next_call('lstrcpyW'):
        print >> sys.stderr, "lstrcpyW not found"
        sys.exit(0)

    address_cc1 = disass.get_arguments()[1]
    binary_value = disass.get_value(address_cc1)

    print disass.get_string(binary_value)


    # We are searching when C&C are copy
    if not disass.go_to_next_call('lstrcpyW'):
        print >> sys.stderr, "CALL EBX not found"
        sys.exit(0)

    address_cc2 = disass.get_arguments()[1]
    binary_value = disass.get_value(address_cc2)

    print disass.get_string(binary_value)


if __name__ == '__main__':

    verbose = False
    parser = argparse.ArgumentParser(description='minjat_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true', default=argparse.SUPPRESS)

    parser.add_argument('path', help='path to analyze', nargs="*")

    args = parser.parse_args()


    if hasattr(args, 'verbose'):
        verbose = args.verbose

    if len(args.path) == 0:
        print "Usage : minjat_parser.py minjat.infected"
        sys.exit(1)

    reverse_minjat(path=args.path[0], verbose=verbose)