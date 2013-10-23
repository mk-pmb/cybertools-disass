


import sys

import pytest
from disass.Disass32 import Disass32
from base64 import b64decode

class Test_Function_Disass32(object):


        
    def test_load_data_agentuuw(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.agentuuw.f1 import data
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        assert True

    def test_load_data_minjat(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        assert True
        return

    def test_load_data_not_valid_win32(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from disass.exceptions import DataNotWin32ApplicationError
        from test.minjat.f1 import data
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

    def test_symbols_imported_by_name(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        if "InternetReadFile" in disass.symbols_imported_by_name:
            assert True
        else:
            assert False
        return


# vim:ts=4:expandtab:sw=4
