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
# The BANGAT malware family shares a large amount of functionality with the
# AURIGA backdoor.  The malware family contains functionality for keylogging,
# creating and killing processes, performing filesystem and registry modifications,
# spawning interactive command shells, performing process injection, logging off
# the current user or shutting down the local machine.  In addition, the malware
# also implements a custom VNC like protocol which sends screenshots of the desktop
# to the C2 server and accepts keyboard and mouse input.  The malware communicates
# to its C2 servers using SSL, with self signed SSL certificates.  The malware
# family will create a copy of cmd.exe to perform its C2 activity, and replace
# the "Microsoft corp" strings in the cmd.exe binary with different values.
# The malware family typically maintains persistence through installing itself
# as a service.
#  Source : http://contagiodump.blogspot.fr/
#
# Tested on this file
# 0f77af7fa673f5b3d36b926576002a1c
# 15138604260b1d27f92bf1ec6468b326
# 1966b265272e1660e6f340b19a7e5567
# 423a30c077b12354a4a5c31d4de99689
# 43ce605b2584c27064febb0474a787a4
# 616b0f00de54d7501ceee18823f72103
# 80ca8b948409138be40ffbc5d6d95ef1
# 995b44ef8460836d9091a8b361fde489
# c75d351d86de26718a3881f62fddde99
# e66dd357a6dfa6ebd15358e565e8f00f
# f10d145684ba6c71ca2d2f7eb0d89343
#

def identify_cc_function(disass):
    if disass.go_to_next_call('WS2_32.dll@52'):
        disass.up()
        disass.up()
        return True

    return False

def reverse(path, verbose):

    disass = Disass32(path=path, verbose=verbose)

    if disass.is_dll():
        addr_servicemain  = disass.symbols_exported_by_name['ServiceMain']
        disass.set_position(addr_servicemain)

    if not disass.go_to_next_call('_beginthreadex'):
        return

    addr_startthread = disass.get_arguments(3)
    disass.set_virtual_position(addr_startthread)

    list_cc = list()
    while identify_cc_function(disass):
        cc = disass.get_string(disass.get_arguments(1))
        if cc not in list_cc:
            list_cc.append(cc)
        else:
            break

    print path
    for c in list_cc:
        print "  CC\t:", c


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='bangat_parser')
    parser.add_argument('--verbose', '-v', help='Do not output anything on the standard output.', action='store_true',
                        default=False)

    parser.add_argument('path', help='path to analyze', nargs="*")

    args = parser.parse_args()

    if len(args.path) == 0:
        print "Usage : bangat_parser.py bangat.infected"
        sys.exit(1)

    for path in args.path:
        reverse(path=path, verbose=args.verbose)