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

#
# Tested on :
# 05ec82c2ad8975a1320b6fbde8a57313
# 4b9ff47946eff164adb7a640dbdd658f
# 255e5b506c1ba8a717b4bf54d729d8b5
# 9263d4ec88e0b5f051753871cb8255e7
# bc9a9c55297b0c5ca91987b1d55b55f3
#


def reverse(path, verbose):
    print path
    disass = Disass32(path=path, verbose=verbose)

    if disass.go_to_next_call('CreateMutex'):
        address_mutex = disass.get_arguments(3)
        print "  Mutex\t:", disass.get_string(address_mutex)

    found = False

    if disass.go_to_next_call('__jmp__WS2_32.dll@52'):
        print "  CC1\t:", disass.get_string(disass.get_arguments(1))
        found = True
    if disass.go_to_next_call('__jmp__WS2_32.dll@52'):
        print "  CC2\t:", disass.get_string(disass.get_arguments(1))

    if not found:
        #
        # Check in thread if there is connection with C&C
        #
        if disass.go_to_next_call('CreateThread'):
            startAddress = disass.get_stack()[2]
            disass.symbols_imported_by_name["startAdress"] = startAddress
            disass.symbols_imported[startAddress] = "startAdress"
            disass.set_virtual_position(startAddress)

            if disass.go_to_next_call('__jmp__WS2_32.dll@52'):
                print "  CC1\t:", disass.get_string(disass.get_arguments(1))
                found = True
            if disass.go_to_next_call('__jmp__WS2_32.dll@52'):
                print "  CC2\t:", disass.get_string(disass.get_arguments(1))

    if not found:
        #
        # Check if connection with HttpSendRequestA function
        #
        if disass.go_to_next_call('HttpSendRequestA'):
            disass.up()
            f2 = disass.where_am_i()
            disass.up()
            print "  CC1\t:", disass.get_string(disass.get_arguments(1))
            found = True
            if disass.go_to_next_call(f2):
                print "  CC2\t:", disass.get_string(disass.get_arguments(1))

    return

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='bishona_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true',
                        default=False)

    parser.add_argument('path', help='path to analyze', nargs="*")

    args = parser.parse_args()

    if len(args.path) == 0:
        print "Usage : bishona_parser.py bishona.infected"
        sys.exit(1)

    for path in args.path:
        reverse(path=path, verbose=args.verbose)