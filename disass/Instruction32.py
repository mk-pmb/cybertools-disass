#!/usr/bin/env python
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

"""
@author:       Ivan Fontarensky
@contact:      ivan.fontarensky@cassidian.com
@organization: Cassidian CyberSecurity
"""

__author__ = 'ifontarensky'

operators = ['+', '-', '/', '*']


def is_an_operator(operations):
    """
    Check if an operator is in operations
    @param : operation
    @type : string
    return None if not found
    """
    for o in operators:
        if o in operations:
            if o in '**' and '**' in operations:
                continue
            if o in '//' and '//' in operations:
                continue
            if o in '--' and '--' in operations:
                continue
            if o in '++' and '++' in operations:
                continue
            else:
                return o
    return None


def compute_operation(operations, register):
    """
    This function compute an operation.
    @param : operation
    @type : string
    @param : register
    @type Register32
    """

    op = is_an_operator(operations)
    if op != None:
        operandes = operations.split(op, 1)

        r = []
        for o in operandes:

            if is_an_operator(o) != None:
                r.append(compute_operation(o, register))

            elif o in register.get_list_register():
                r.append(register.get(o))
            else:
                r.append(int(o))

        if op == "+":
            return r[0] + r[1]
        elif op == "-":
            return r[0] - r[1]
        elif op == "/":
            return r[0] / r[1]
        elif op == "*":
            return r[0] * r[1]
    else:
        return None

        # vim:ts=4:expandtab:sw=4