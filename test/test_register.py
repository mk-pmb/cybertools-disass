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
from disass.Register32 import Register32

class Test_Register_Disass32(object):


        
    def test_create_register(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        assert True
        return

    def test_eax(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.eax = 0x080484cc

        if register.eax == 0x080484cc:
            assert True
        else:
            assert False

        return

    def test_ax(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.ax = 0x080484cc

        if register.ax == 0x84cc:
            assert True
        else:
            assert False


        return

    def test_al(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.al = 0x84cc

        if register.al != 0xcc:
            assert False
            return

        if register.eax != 0xcc:
            assert False
            return

        assert True
        return

    def test_ebx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.ebx = 0x080484cc

        if register.ebx == 0x080484cc:
            assert True
        else:
            assert False

        return

    def test_bx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.bx = 0x080484cc

        if register.bx == 0x84cc:
            assert True
        else:
            assert False


        return

    def test_bl(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.bl = 0x84cc

        if register.bl != 0xcc:
            assert False
            return

        if register.ebx != 0xcc:
            assert False
            return

        assert True
        return

    def test_bh(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.ebx = 0x080484cc

        if register.bh != 0x84:
            assert False
            return
        register.bh = 0x77

        if register.bh != 0x077:
            assert False
            return

        if register.ebx != 0x080477cc:
            assert False
            return

        assert True
        return

    def test_ecx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.ecx = 0x080484cc

        if register.ecx == 0x080484cc:
            assert True
        else:
            assert False

        return

    def test_cx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.cx = 0x080484cc

        if register.cx == 0x84cc:
            assert True
        else:
            assert False


        return

    def test_cl(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.cl = 0x84cc

        if register.cl != 0xcc:
            assert False
            return

        if register.ecx != 0xcc:
            assert False
            return

        assert True
        return

    def test_ch(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.ecx = 0x080484cc

        if register.ch != 0x84:
            assert False
            return
        register.ch = 0x77

        if register.ch != 0x077:
            assert False
            return

        if register.ecx != 0x080477cc:
            assert False
            return

        assert True
        return


    def test_edx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.edx = 0x080484cc

        if register.edx == 0x080484cc:
            assert True
        else:
            assert False

        return

    def test_dx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.edx = 0x080484cc
        register.dx = 0x7777
        if register.dx != 0x7777:
            assert False
            return

        if register.edx != 0x08047777:
            assert False
            return

        assert True
        return

    def test_dl(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.dl = 0x84cc

        if register.dl != 0xcc:
            assert False
            return

        if register.edx != 0xcc:
            assert False
            return

        assert True
        return

    def test_dh(self):

        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.edx = 0x080484cc

        if register.dh != 0x84:
            assert False
            return
        register.dh = 0x77

        if register.dh != 0x077:
            assert False
            return

        if register.edx != 0x080477cc:
            assert False
            return

        assert True
        return

    def test_cs(self):

        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.cs = 0x1111

        if register.cs != 0x1111:
            assert False
            return

        assert True
        return

    def test_ds(self):

        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.ds = 0x1111

        if register.ds != 0x1111:
            assert False
            return

        assert True
        return

    def test_es(self):

        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.es = 0x1111

        if register.es != 0x1111:
            assert False
            return

        assert True
        return

    def test_fs(self):

        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.fs = 0x1111

        if register.fs != 0x1111:
            assert False
            return

        assert True
        return

    def test_eip(self):

        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.eip = 0x11111111

        if register.eip != 0x11111111:
            assert False
            return

        assert True
        return

    def test_xor(self):

        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            register = Register32()
        except:
            assert False
            return

        register.eax = 0x25
        register.ebx = 0x12

        r = 0x25^0x12

        register.set('ecx',register.eax^register.ebx)

        if register.ecx != r:
            print register.ecx, r
            assert False

        assert True
        return


# vim:ts=4:expandtab:sw=4
