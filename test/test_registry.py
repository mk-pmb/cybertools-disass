


import sys

import pytest
from disass.Registry32 import Registry32

class Test_Registry_Disass32(object):


        
    def test_create_registry(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
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
            registry = Registry32()
        except:
            assert False
            return

        registry.eax = 0x080484cc

        if registry.eax == 0x080484cc:
            assert True
        else:
            assert False

        return

    def test_ax(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.ax = 0x080484cc

        if registry.ax == 0x84cc:
            assert True
        else:
            assert False


        return

    def test_al(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.al = 0x84cc

        if registry.al != 0xcc:
            assert False
            return

        if registry.eax != 0xcc:
            assert False
            return

        assert True
        return

    def test_ebx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.ebx = 0x080484cc

        if registry.ebx == 0x080484cc:
            assert True
        else:
            assert False

        return

    def test_bx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.bx = 0x080484cc

        if registry.bx == 0x84cc:
            assert True
        else:
            assert False


        return

    def test_bl(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.bl = 0x84cc

        if registry.bl != 0xcc:
            assert False
            return

        if registry.ebx != 0xcc:
            assert False
            return

        assert True
        return

    def test_bh(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.ebx = 0x080484cc

        if registry.bh != 0x84:
            assert False
            return
        registry.bh = 0x77

        if registry.bh != 0x077:
            assert False
            return

        if registry.ebx != 0x080477cc:
            assert False
            return

        assert True
        return

    def test_ecx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.ecx = 0x080484cc

        if registry.ecx == 0x080484cc:
            assert True
        else:
            assert False

        return

    def test_cx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.cx = 0x080484cc

        if registry.cx == 0x84cc:
            assert True
        else:
            assert False


        return

    def test_cl(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.cl = 0x84cc

        if registry.cl != 0xcc:
            assert False
            return

        if registry.ecx != 0xcc:
            assert False
            return

        assert True
        return

    def test_ch(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.ecx = 0x080484cc

        if registry.ch != 0x84:
            assert False
            return
        registry.ch = 0x77

        if registry.ch != 0x077:
            assert False
            return

        if registry.ecx != 0x080477cc:
            assert False
            return

        assert True
        return


    def test_edx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.edx = 0x080484cc

        if registry.edx == 0x080484cc:
            assert True
        else:
            assert False

        return

    def test_dx(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.edx = 0x080484cc
        registry.dx = 0x7777
        if registry.dx != 0x7777:
            assert False
            return

        if registry.edx != 0x08047777:
            assert False
            return

        assert True
        return

    def test_dl(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.dl = 0x84cc

        if registry.dl != 0xcc:
            assert False
            return

        if registry.edx != 0xcc:
            assert False
            return

        assert True
        return

    def test_dh(self):

        """
        Test de l'initialisation du moteur disass 32
        """
        try:
            registry = Registry32()
        except:
            assert False
            return

        registry.edx = 0x080484cc

        if registry.dh != 0x84:
            assert False
            return
        registry.dh = 0x77

        if registry.dh != 0x077:
            assert False
            return

        if registry.edx != 0x080477cc:
            assert False
            return

        assert True
        return



# vim:ts=4:expandtab:sw=4
