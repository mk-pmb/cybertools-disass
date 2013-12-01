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

class Test_Function_Disass32_Minjat(object):



    def test_load_data_minjat(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False

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
            return
        except:
            assert False

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

        try:
            disass.set_position(0x0)
        except:
            assert False

        try:
            disass.set_position(0x100)
        except:
            assert False

        try:
            disass.set_position(0x200)
        except:
            assert False

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

        try:
            disass.set_position(-0x20)
        except InvalidValueEIP as e:
            assert True
            return

        assert False

    @pytest.mark.parametrize("value", ['[EBP-0x14]','[EBP+0x14]','[EIP]','[CS:0x254]','[CS:DS]','CALL EAX'])
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

        if disass.is_register(value):
            assert True
            return

        assert False

    @pytest.mark.parametrize("value", ['CALL [0x14]'])
    def test_is_not_register(self,value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        from disass.exceptions import InvalidValueEIP
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False

        if disass.is_register(value):
            assert False

        assert True

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

        addr = disass._extract_address(value)

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
        print addr, value[1]
        if addr == value[1]:
            assert True
            return

        assert False
        return


    def test_go_to_next_call_Create2times(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data


        disass = Disass32(data=b64decode(data))
        disass2 = Disass32(data=b64decode(data))

        disass.go_to_next_call('CreateThread')

        if not disass2.go_to_next_call('CreateThread'):
            assert False
        assert True

    @pytest.mark.parametrize("value", ['GetVersion', 'GetCommandLine', 'CreateThread'])
    def test_go_to_next_call(self,value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return


        if disass.go_to_next_call(value):
            assert True
            return

        assert False
        return



    @pytest.mark.parametrize("value", [(0,"0"),(6,"0"),(26,"20"),(99,"40")])
    def test_where_am_i(self, value):
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
    def test_where_am_i(self, value):
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
    def test_where_am_i(self, value):
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
            addr = disass.map_call_by_name["hopla"]
            name = disass.map_call[addr]
        except:
            assert False

        if name == "hopla":
            assert True
            return

        assert False

    @pytest.mark.parametrize("value", ['GetCommandLine'])
    def test_get_args(self, value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False
            return

        if not disass.go_to_next_call(value):
            assert False
            return

        args = disass.get_stack()

        if args == None:
            assert False
            return

        assert True
        return

    def test_get_unicode_value(self):
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False

        domain = disass.get_string(0x41bad8)

        if domain != 'timesofindia.8866.org':
            print domain
            assert False

        assert True

    def test_script(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False


        if not disass.go_to_next_call("CreateThread"):
            assert False

        startAddress = disass.get_stack()[2]
        if startAddress == 0:
            assert False

        disass.set_position(startAddress - disass.pe.OPTIONAL_HEADER.ImageBase)

        disass.go_to_instruction('CALL EBX')

        assert True

    def test_next_call(self):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data

        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False


        if not disass.go_to_next_call("CreateThread"):
            assert False

        startAddress = disass.get_stack()[2]
        if startAddress == 0:
            assert False

      # CreateThread( ..., ... , ... )
        startAddress = disass.get_stack()[2]

        # We set our position in this Thread
        disass.set_position(startAddress - disass.pe.OPTIONAL_HEADER.ImageBase)

        if not disass.go_to_next_call('lstrcpyW'):
            assert False

        eip1 = disass.register.eip

        if not disass.go_to_next_call('lstrcpyW'):
            assert False
        eip2 = disass.register.eip

        if eip1 == eip2:
            assert False

        assert True

    @pytest.mark.parametrize("value", ['GetCommandLine', 'GetStdHandle',  'HeapDestroy',
'FreeEnvironmentStringsA','GetCurrentProcess','RegOpenKeyExW','FreeEnvironmentStringsW',
'GetCPInfo','GetStringTypeA','GetModuleFileNameW','ExitProcess','GetMessageW','ShowWindow',
'GetModuleFileNameA','LoadLibraryA','UnhandledExceptionFilter','InterlockedDecrement',
'MultiByteToWideChar','SetFilePointer','LoadAcceleratorsW','CreateThread','TerminateProcess','LoadStringW',
'CoUninitialize','GetVersion','GetCurrentThreadId','LeaveCriticalSection','HeapFree','EnterCriticalSection',
'SetHandleCount','LoadLibraryW','LoadCursorW','GetOEMCP','TlsAlloc','CopyFileW','GetStartupInfoA',
'LCMapStringW','VirtualFree','wsprintfW' ])
    def test_next_call_from_import(self, value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False

        res = disass.go_to_next_call(value)
        if not res:
            assert False

        assert True

    @pytest.mark.parametrize("value", ['CreateThread'])
    def test_get_arguments(self, value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False

        res = disass.go_to_next_call(value)

        if int(disass.get_arguments(3)) == 0x403b16:
            return

        assert False

    @pytest.mark.parametrize("value", ['CreateMutex'])
    def test_get_arguments_bad_value(self, value):
        """
        Test de l'initialisation du moteur disass 32
        """
        from test.minjat.f1 import data
        try:
            disass = Disass32(data=b64decode(data))
        except:
            assert False


        res = disass.go_to_next_call(value)

        try:
            a = disass.get_arguments(0)
        except ValueError as e:
            return

        assert False

# vim:ts=4:expandtab:sw=4
