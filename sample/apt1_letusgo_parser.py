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
# c7a0398cfb7c40ce7a8cc9acdb28cb0f107a2e892b5fa5ed7700563c8c1540ab 


def reverse(path, verbose):
    disass = Disass32(path=path, verbose=verbose)

    disass.go_to_next_call('InternetConnectA')

    try:
    	addr = disass.get_arguments(2)
        print "  CC\t: %s" % disass.get_string(addr)
    except:
	pass

    if not disass.go_to_next_call('HttpOpenRequestA'):
	return

    try:
        lpszVerb = disass.get_string(disass.get_arguments(2))
        lpszObjectName = disass.get_string(disass.get_arguments(3))
        lpszVersion = disass.get_string(disass.get_arguments(4))

        print "  Request\t: %s %s %s" % (lpszVerb,lpszObjectName,lpszVersion)
    except Exception as e:
        print str(e)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='letusgo_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true',
                        default=False)

    parser.add_argument('path', help='path to analyze', nargs="*")
    args = parser.parse_args()

    if len(args.path) == 0:
        print "Usage : apt1_letusgo_parser.py apt1_letusgo.infected"
        sys.exit(1)

    for path in args.path:
        reverse(path=path, verbose=args.verbose)
