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

# Tested on :
# 26eaac1501c62c470a1a9c615c4d7fb8  sysninit.ocx


def print_result(valuable_information, value):
    if value == "User-Agent":
        for string in valuable_information:
            if "Mozilla" in string:
                print "%-16s\t %s" % ("User-Agent:", string)

    elif value == "Request":
        r = ""
        for string in valuable_information:
            if not any([x in string for x in ('Content-Type:', 'Referer:', 'Accept-Encoding:', 'Accept-Language:',
                                              'Mozilla:', 'Host:')]):
                r += string
        for e in r.split('&'):
            if 'Email' in e:
                print "%-16s\t %s" % ("Email:", e.replace("Email=", ''))
            if 'Passwd' in e:
                print "%-16s\t %s" % ("Password:", e.replace("Passwd=", ''))
    else:
        for string in valuable_information:
            if value in string:
                print "%-16s\t%s" % (value + ":", string.replace(value + ":", ''))


def reverse(path, verbose):
    disass = Disass32(path=path, verbose=verbose)

    if disass.is_dll():
        disass.make_xref()

        valuable_information = list()

        for address in disass.xref['InternetOpenA']:
            disass.set_position(address)

            function = disass.where_am_i()
            disass.set_position(disass.map_call_by_name[function])

            while disass.go_to_instruction('REP'):

                disass.update_stack_and_register()
                try:
                    r = disass.get_string(disass.register.esi)
                    if r not in valuable_information:
                        valuable_information.append(r)
                except:
                    continue

                # If I change function it's finish
                if disass.where_am_i() != function:
                    break

        print_result(valuable_information, 'Host')
        print_result(valuable_information, 'Content-Type')
        print_result(valuable_information, 'Accept-Encoding')
        print_result(valuable_information, 'Referer')
        print_result(valuable_information, 'Accept-Language')
        print_result(valuable_information, 'User-Agent')
        print_result(valuable_information, 'Request')


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