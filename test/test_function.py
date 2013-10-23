


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

    def test_entrypoint(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        ep = disass.get_entry_point()
        if ep == None:
            assert False

        if ep != disass.register.eip:
            assert False

        assert True
        return

    def test_position_value(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        try:
            disass.set_position(0x0)
        except:
            assert False
            return

        try:
            disass.set_position(0x100)
        except:
            assert False
            return


        try:
            disass.set_position(0x200)
        except:
            assert False
            return

        assert True
        return

    def test_position_negative_value(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        from disass.exceptions import InvalidValueEIP
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        try:
            disass.set_position(-0x20)
        except InvalidValueEIP as e:
            assert True
            return

        assert False
        return

    def test_position_jump_value(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        from disass.exceptions import InvalidValueEIP
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        value = 0x20
        b = disass.decode[value:value+1]

        disass.jump(value)

        if disass.register.eip == b[0][0]:
            assert True
            return

        assert False
        return

    @pytest.mark.parametrize("value", ['[EBP-0x14]','[EBP+0x14]','[EIP]','[CS:0x254]','[CS:DS]'])
    def test_is_register(self,value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        from disass.exceptions import InvalidValueEIP
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        if disass.is_register(value):
            assert True
            return

        assert False
        return

# vim:ts=4:expandtab:sw=4
