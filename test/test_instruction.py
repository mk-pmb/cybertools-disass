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

import pytest
import math
from disass.Instruction32 import compute_operation
from disass.Register32 import Register32



class Test_Instruction_Disass32(object):


    @pytest.mark.parametrize("o", [
        ("3+5", 8), ("2-4", -2), ("2/4", float(2) / float(4)), ("2*4", 2 * 4), ("2+4*2", 2 + 4 * 2),
        ("2+4/2", 2 + 4 / 2), ("2-4/2", 2 - 4 / 2), ("2-0/2", 2 - 0 / 2), ("0/2*3*6+2", 0 / 2 * 3 * 6 + 2),
        ("0x1000",0x1000),("0x1000+5",0x1000+5),
        ( "9", 9 ),
        ( "-9", -9 ),
        ( "--9", 9 ),
        ( "-E", -math.e ),
        ( "9 + 3 + 6", 9 + 3 + 6 ),
        ( "9 + 3 / 11", 9 + 3.0 / 11 ),
        ( "(9 + 3)", (9 + 3) ),
        ( "(9+3) / 11", (9+3.0) / 11 ),
        ( "9 - 12 - 6", 9 - 12 - 6 ),
        ( "9 - (12 - 6)", 9 - (12 - 6) ),
        ( "2*3.14159", 2*3.14159 ),
        ( "3.1415926535*3.1415926535 / 10", 3.1415926535*3.1415926535 / 10 ),
        ( "PI * PI / 10", math.pi * math.pi / 10 ),
        ( "PI*PI/10", math.pi*math.pi/10 ),
        ( "PI^2", math.pi**2 ),
        ( "6.02E23 * 8.048", 6.02E23 * 8.048 ),
        ( "e / 3", math.e / 3 ),
        ( "E^PI", math.e**math.pi ),
        ( "2^3^2", 2**3**2 ),
        ( "2^3+2", 2**3+2 ),
        ( "2^9", 2**9 ),
    ])
    def test_compute_operation_basic(self, o):
        """
        Test de l'initialisation du moteur disass 32
        """
        register = Register32()
        r = compute_operation(o[0], register)

        if r == o[1]:
            print o[1], "=", str(r)
            assert True
        else:
            print "%s !!! %s != %s " % (o[0],str(r), str(o[1]))
            assert False

        return

    @pytest.mark.parametrize("o", [
        ("3+5+eax", 13), ("2-4+eax", 3), ("2/4+eax", float(2) / 4 + 5), ("2*4*eax", 40), ("2+eax*2", 12),
        ("0/2*3*eax+2", 2), ('EDX*4+0x406e88',1*4+0x406e88)
    ])
    def test_compute_operation_register(self, o):
        """
        Test de l'initialisation du moteur disass 32
        """

        register = Register32()
        register.eax = 5
        register.edx = 1
        r = compute_operation(o[0], register)
        if r == o[1]:
            assert True
        else:
            print o[0], o[1], r
            assert False
        return

    @pytest.mark.parametrize("o", [
        ('0x6d40', 0x6d40), ('0x0000', 0x0000), ('0xa0a0', 0xa0a0)
    ])
    def test_compute_instructrion(self,o):
        """
        Test
        """
        register = Register32()
        value = compute_operation(o[0], register)
        if value != o[1]:
            assert False
        else:
            assert True

# vim:ts=4:expandtab:sw=4
