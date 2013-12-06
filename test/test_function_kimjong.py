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


import sys

import pytest
from disass.Disass32 import Disass32
from base64 import b64decode

class Test_Function_Disass32_KimJong(object):


        
    def test_load_data_agentuuw(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.kimjong.f1 import data
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return


    def test_load_data_not_valid_win32(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from disass.exceptions import DataNotWin32ApplicationError
        from test.kimjong.f1 import data
        try:
            disass = Disass32(data=data)
        except DataNotWin32ApplicationError:
            assert True
            return
        except:
            assert False
            return

        assert False
        return

    def test_xref(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.kimjong.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False

        disass.make_xref()

        assert True

    def test_xref(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.kimjong.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False

        disass.make_xref()

        for x in disass.xref['InternetOpenA']:
            if x == 5232 or x == 18035:
                continue
            else:
                assert False

        assert True 



# vim:ts=4:expandtab:sw=4
