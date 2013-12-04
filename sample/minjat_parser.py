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

    if disass.is_dll():
        addrhMainThread = disass.symbols_exported_by_name['hMainThread']
        disass.set_position(addrhMainThread)
    elif disass.is_exe():
        if not disass.go_to_next_call('CreateThread'):
            print >> sys.stderr, "CreateThread not found in %s" % path
            return

        # CreateThread( ..., ... , ... )
        startAddress = disass.get_arguments(3)

        # We set our position in this Thread
        disass.set_virtual_position(startAddress)
    else:
        return

    # We are searching when C&C are copy
    if not disass.go_to_next_call('lstrcpyW'):
        print >> sys.stderr, "lstrcpyW not found in %s" % path
        sys.exit(0)

    address_cc1 = disass.get_arguments(2)

    print disass.get_string(address_cc1)

    # We are searching when C&C are copy
    if not disass.go_to_next_call('lstrcpyW'):
        print >> sys.stderr, "CALL lstrcpyW not found in %s" % path
        sys.exit(0)

    address_cc2 = disass.get_arguments(2)
    print disass.get_string(address_cc2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='minjat_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true',
                        default=False)

    parser.add_argument('path', help='path to analyze', nargs="*")
    args = parser.parse_args()

    if len(args.path) == 0:
        print "Usage : minjat_parser.py minjat.infected"
        sys.exit(1)

    for path in args.path:
        reverse(path=path, verbose=args.verbose)