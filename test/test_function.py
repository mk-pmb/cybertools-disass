


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


    def test_print_assembly(self):
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
            disass.print_assembly()
        except:
            assert False
            return

        assert True
        return

    def test_next(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return


        s1 = disass.decode[0]
        s2 = disass.decode[1]
        s3 = disass.decode[2]
        s4 = disass.decode[3]

        if disass.register.eip != s1[0]:
            assert False
        disass.next()
        if disass.register.eip != s2[0]:
            assert False
        disass.next()
        if disass.register.eip != s3[0]:
            assert False
        disass.next()
        if disass.register.eip != s4[0]:
            assert False

        assert True
        return

    def test_previous(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return


        s1 = disass.decode[0]
        s2 = disass.decode[1]
        s3 = disass.decode[2]
        s4 = disass.decode[3]

        disass.set_position(s4[0])
        if disass.register.eip != s4[0]:
            assert False
            return

        print s4[0]
        disass.previous()
        if disass.register.eip != s3[0]:
            print disass.register.eip, s3[0]
            assert False
        disass.previous()
        if disass.register.eip != s2[0]:
            assert False
        disass.previous()
        if disass.register.eip != s1[0]:
            assert False

        assert True
        return

    @pytest.mark.parametrize("value", [1,10,50,0x100])
    def test_next_and_forward(self, value):
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

        hist = list()
        for d in disass.decode:
            hist.append(d[0])

        for v in xrange(value):
            disass.next()
            if disass.register.eip != hist[v+1]:
                print "ep", disass.get_entry_point()
                print disass.register.eip ,  hist[v+1]
                print disass.decode[0]
                print disass.decode[1]
                assert False

        for v in xrange(value):
            disass.previous()
            if disass.register.eip != hist[value-v-1]:
                print "ep", disass.get_entry_point()
                print disass.register.eip ,  hist[value-v-1]
                print disass.decode[0]
                print disass.decode[1]
                assert False



        assert True
        return


    @pytest.mark.parametrize("value", ['CALL 0x1111', 'CALL DWORD 0x1111', 'JMP 0x1111'])
    def test_extract_address(self,value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        addr = disass.extract_address(value)

        if addr == '0x1111':
            assert True
            return

        assert False
        return


    @pytest.mark.parametrize("value", [
        ('MOV DWORD [0x41fad0], 0x10','MOV DWORD [0x41fad0], 0x10'),
        ('CALL 0x4171b8','CALL \033[95mCreateThread\033[0m')])
    def test_replace_in_function(self,value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        addr = disass.replace_function(value[0])
        print addr,value[1]
        if addr == value[1]:
            assert True
            return

        assert False
        return

    @pytest.mark.parametrize("value", ['GetVersion','GetCommandLine','CreateThread'])
    def test_go_to_function(self,value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return


        if disass.go_to_function(value):
            assert True
            return

        assert False
        return

    @pytest.mark.parametrize("value", [(0,"0"),(6,"0"),(26,"20"),(99,"40")])
    def test_where_am_i(self,value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        disass.register.eip = value[0]

        disass.map_call[100]="100"
        disass.map_call[0]="0"
        disass.map_call[10]="10"
        disass.map_call[30]="30"
        disass.map_call[40]="40"
        disass.map_call[20]="20"


        if disass.where_am_i() == value[1]:
            assert True
            return

        assert False

    @pytest.mark.parametrize("value", [(0,"0"),(6,"0"),(26,"20"),(99,"40")])
    def test_where_am_i(self,value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return


        disass.map_call[100]="100"
        disass.map_call[0]="0"
        disass.map_call[10]="10"
        disass.map_call[30]="30"
        disass.map_call[40]="40"
        disass.map_call[20]="20"


        if disass.where_am_i(offset=value[0]) == value[1]:
            assert True
            return

        assert False

    @pytest.mark.parametrize("value", [(0,"0"),(6,"0"),(26,"20"),(99,"40")])
    def test_where_am_i(self,value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return


        disass.rename_function('Entrypoint',"hopla")

        try :
            addr = disass.map_call_by_addr["hopla"]
            name = disass.map_call[addr]
        except:
            assert False

        if name == "hopla":
            assert True
            return

        assert False


    def test_get_args(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return


        disass.go_to_function('CreateThread')

        args = disass.get_arguments()

        if args == None:
            assert False
            return

        print args

        assert False
        return


# vim:ts=4:expandtab:sw=4
