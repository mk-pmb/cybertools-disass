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

import sys

try:
    from distorm3 import Decode
except ImportError:
    print 'distorm3 is not installed, this is a fatal error'
    print 'pip install distorm3'
    sys.exit(1)

try:
    import pefile
except ImportError:
    print 'pefile is not installed, this is a fatal error'
    print 'pip install pefile'
    sys.exit(1)

from disass.Register32 import Register32
from disass.prettyprint import bcolors
from disass.exceptions import DataNotWin32ApplicationError
from disass.exceptions import InvalidValueEIP

class Disass32():
    """
    Detect all executable
    """
    def __init__(self,path=None,data=None,verbose=False):

        self.register = Register32()
        self.load_win32_pe(path=path,data=data)
        self.verbose = verbose


    def load_win32_pe(self,path=None,data=None):
        """
        TODO:
        """
        if path != None:
            self.pe = pefile.PE(path)
        else:
            if data!=None:
                try:
                    self.pe = pefile.PE(data=data)
                except:
                    raise DataNotWin32ApplicationError

        self.symbols_imported = dict()
        self.symbols_imported_by_name = dict()
        self.symbols_exported = dict()
        self.symbols_exported_by_name = dict()
        self.action_reverse = dict()

        self.get_list_imported_symbols()
        self.get_list_exported_symbols()
        self.decode = None
        self.data_code = self.pe.get_memory_mapped_image()
        self.set_position(self.get_entry_point())


    def get_list_imported_symbols(self):
        """
        TODO:
        """
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    self.symbols_imported[int(imp.address)] = imp.name
                    self.symbols_imported_by_name[imp.name] = int(imp.address)
        except Exception as e:
            pass


    def get_list_exported_symbols(self):
        """
        TODO:
        """
        try:
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                self.symbols_exported[int(exp.address)] = exp.name
                self.symbols_exported_by_name[exp.name] = int(exp.address)
        except Exception as e:
            pass

    def is_dll(self):
        """
        TODO:
        """
        return (self.pe.FILE_HEADER.Characteristics & 0x2000)

    def is_exe(self):
        """
        TODO:
        """
        return  not (self.pe.FILE_HEADER.Characteristics & 0x2000)

    def is_register(self,value):
        v = value.lower()

        if (v in self.register.get_list_register()):
            return True

        for r in self.register.get_list_register():
            if r in v:
                return True

        return False

    def get_entry_point(self):
        """
        TODO:
        """
        try:
            if self.is_dll():
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.ordinal == 1:
                        return int(exp.address)
            else:
                return int(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        except:
            return None

    def set_position(self,pos):
        """
        TODO:
        """

        if pos < 0 :
            raise InvalidValueEIP


        self.register.eip = pos
        eip = self.register.eip
        self.decode = Decode(eip,self.data_code[eip:eip+0x200])

    def jump(self,value):
        """
        @param value: Skip value instructions.
        @type value: int
        """
        eip=self.decode[value:value+1][0][0]
        self.set_position(eip)

    #def trace_to(self,value):


    def get_function_name(self,opcode=None,saddr=None):
        """
        @param opcode: Opcode what we want resolv.
        @type opcode:
        @param saddr:
        @type saddr:
        """
        if opcode!=None:

            try:
                # Récupération de l'adresse
                if "CALL" in opcode:
                    if "CALL DWORD" in opcode:
                        saddr = opcode.split(' ')[2]
                    else:
                        saddr = opcode.split(' ')[1]

                elif "JMP" in opcode:
                    if "JMP DWORD" in opcode:
                        saddr = opcode.split(' ')[2]
                    else:
                        saddr = opcode.split(' ')[1]
                elif "MOV " in opcode:
                    if "MOV DWORD" in opcode:
                        saddr = opcode.split(' ')[3]
                    else:
                        saddr = opcode.split(' ')[2]
                    if self.is_register(saddr):
                        return saddr
                else:
                    return ''
            except:
                print >> sys.stderr, bcolors.FAIL + "\tErreur: Decomposition not possible : '%s' found in %s" % (saddr,opcode) + bcolors.ENDC
                return saddr

            saddr2 = saddr
            if '[' in saddr:
                saddr2 = saddr[1:-1]

            if ":" in saddr2:
                return saddr

            if self.is_register(saddr2):
                return saddr

            try:

                addr = int(saddr2,16)


                if addr in self.symbols_imported:
                    return self.symbols_imported[addr]
                else:
                    return saddr

            except Exception as e:
                print >> sys.stderr, bcolors.FAIL + "\tErreur: Convertion not possible : '%s' found in %s" % (saddr2,opcode) + bcolors.ENDC
                print >> sys.stderr, str(e)
                return saddr



    def print_assembly(self,start=0,nb_instruction=0x20):
        """
        TODO:
        """
        for b in self.decode[start:nb_instruction]:
            try:
                if "CALL" in b[2]:
                    if "CALL DWORD" in b[2]:
                        print "\t%04x : %15s : CALL DWORD %s" % (b[0],b[3],bcolors.HEADER + self.get_function_name(b[2]) + bcolors.ENDC)

                    elif "CALL" in b[2]:
                        print "\t%04x : %15s : CALL %s" % (b[0],b[3],bcolors.HEADER + self.get_function_name(b[2]) + bcolors.ENDC)

                elif "JMP" in b[2]:
                    print "\t%04x : %15s : JMP %s" % (b[0],b[3], bcolors.HEADER + self.get_function_name(b[2]) + bcolors.ENDC)

                elif "MOV " in b[2]:
                    dest = b[2].split(' ')[1]
                    src = b[2].split(' ')[2]
                    if not self.is_register(src):
                        print "\t%04x : %15s : MOV %s %s" % (b[0],b[3], dest,bcolors.HEADER + self.get_function_name(b[2]) + bcolors.ENDC)
                    else:
                        print "\t%04x : %15s : %s" % (b[0],b[3], b[2])
                else:
                    print "\t%04x : %15s : %s" % (b[0],b[3], b[2])
            except Exception as e:
                print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't decompose this opcode '%s'" % b[2] + bcolors.ENDC
                raise e



# vim:ts=4:expandtab:sw=4