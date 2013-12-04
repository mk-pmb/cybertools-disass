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
# Tested on 3db2a93d228d332b095379f1e40650ef
#


def reverse(path, verbose):

    disass = Disass32(path=path, verbose=verbose)

    if disass.go_to_next_call('CreateMutex'):
        address_mutex = disass.get_arguments(3)
        print "  Mutex\t:", disass.get_string(address_mutex)

    if disass.go_to_next_call('InternetOpenA'):
        ua = disass.get_string(disass.get_arguments(1))

        disass.up()
        disass.up()
        last_position = disass.register.eip
        host = disass.get_string(disass.get_arguments(1))

        disass.go_to_next_call('InternetConnectA')
        try:
            port = disass.get_arguments(2)
            print "  Host\t\t:", host
            print "  Port\t\t:", port
            print "  UserAgent\t:", ua
        except:
            pass

        print ""
        disass.set_position(last_position)
        if disass.go_to_next_call('InternetOpenA'):
            ua = disass.get_string(disass.get_arguments(1))

            disass.up()
            disass.up()
            last_position = disass.register.eip
            host = disass.get_string(disass.get_arguments(1))

            disass.go_to_next_call('InternetConnectA')
            try:
                port = disass.get_arguments(3)
                print "  Host\t\t:", host
                print "  Port\t\t:", port
                print "  UserAgent\t:", ua
            except:
                pass
            request = ''
            if disass.go_to_next_call('HttpOpenRequestA'):
                s = disass.get_stack()
                request = '%s%s%s%s' % (disass.get_string(s[10]),"????????",disass.get_string(s[13]),'????????')
                request = '%s %s %s' % (disass.get_string(s[1]),request,disass.get_string(s[3]))
            print "  Request\t:", request
        return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='agentuuw_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true',
                        default=False)

    parser.add_argument('path', help='path to analyze', nargs="*")

    args = parser.parse_args()

    if len(args.path) == 0:
        print "Usage : minjat_parser.py minjat.infected"
        sys.exit(1)

    for path in args.path:
        reverse(path=path, verbose=args.verbose)