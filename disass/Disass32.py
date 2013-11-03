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
from traceback import print_stack

__author__ = 'ifontarensky'

import sys,traceback

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
from disass.Instruction32 import compute_operation
from disass.prettyprint import bcolors
from disass.exceptions import DataNotWin32ApplicationError
from disass.exceptions import InvalidValueEIP

class Disass32():
    """
    Detect all executable
    """
    def __init__(self,path=None,data=None,verbose=False):

        self.verbose = verbose
        self.register = Register32()
        self.stack = list()
        self.map_cal = dict()
        self.load_win32_pe(path=path,data=data)


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

        self.decode = Decode(eip, self.data_code[eip:eip+0x1000])

        if self.verbose:
            self.print_assembly()


    def go_to_function(self,name,offset=0,history=[],indent=1):
        """

        """

        if offset==0:
            eip = self.register.eip
            offset = eip
            self.stack = []
        bakstack = self.stack



        for d in Decode(offset,self.data_code[offset:offset+0x1000]):
            instruction = d[2]
            offset = d[0]

            history.append(offset)

            if name in self.replace_function(instruction):
                self.set_position(offset)

                return True
            else:
                if 'RET' in instruction:
                    ret = self.stack.pop()
                    return False

                if "CALL" in instruction :
                    saddr = self.get_function_name(instruction)

                    if "0x" in saddr:
                        if '[' in saddr:
                            continue
                        if ':' in saddr:
                            continue

                        try:
                            saddr = compute_operation(saddr, self.register)
                        except Exception as e:
                            print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't eval instruction'%s'" % instruction + bcolors.ENDC
                            continue
                        addr = saddr


                        if addr in history:
                            continue

                        if addr not in history:
                            self.stack.append(offset)
                            self.map_cal[addr]="CALL_%s" % addr
                            if self.go_to_function(name, addr, history, indent+1):
                                return True

        self.stack = bakstack
        return False


    def extract_address(self, opcode):
        """

        """
        try:
            # Récupération de l'adresse
            if "CALL" in opcode:
                if "CALL DWORD" in opcode:
                    saddr = opcode.split(' ')[2]
                elif "CALL FAR" in opcode:
                    saddr = opcode.split(' ')[2]
                else:
                    saddr = opcode.split(' ')[1]
                return saddr

            elif "JMP" in opcode:
                if "JMP DWORD" in opcode:
                    saddr = opcode.split(' ')[2]
                elif "JMP FAR" in opcode:
                    if "JMP FAR DWORD" in opcode:
                        saddr = opcode.split(' ')[3]
                    else:
                        saddr = opcode.split(' ')[2]
                else:
                    saddr = opcode.split(' ')[1]
                return saddr

            else:
                return ''
        except:
            print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't extract address : '%s' found " % (opcode) + bcolors.ENDC
            return ''



    def get_function_name(self,opcode=None,saddr=None):
        """
        @param opcode: Opcode what we want resolv.
        @type opcode:
        @param saddr:
        @type saddr:
        """
        if opcode!=None:

            try:
                saddr = self.extract_address(opcode)

            except:
                print >> sys.stderr, bcolors.FAIL + "\tErreur: Decomposition not possible : '%s' found in %s" % (saddr,opcode) + bcolors.ENDC
                return saddr

            if saddr == '':
                return opcode


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
                return opcode
        else:
            return opcode

    def print_assembly(self,start=0,nb_instruction=0x20):
        """
        TODO:
        """

        n = nb_instruction
        eip = self.register.eip

        position = 0


        dec = self.decode[position:position+n]

        nn = 0
        for b in dec:
            self.print_instruction(nn,b[0], b[3], b[2])
            nn +=1
        print ""

    def replace_function(self, instruction):
        """
        Replace address in instruction by the corresponding name
        @param : instruction
        @type : string
        """
        try:
            if "CALL" in instruction:
                if "CALL DWORD" in instruction:
                    return "CALL DWORD %s" % (bcolors.HEADER + self.get_function_name(instruction) + bcolors.ENDC)

                elif "CALL" in instruction:
                    return "CALL %s" % (bcolors.HEADER + self.get_function_name(instruction) + bcolors.ENDC)

            elif "JMP" in instruction:
                return "JMP %s" % (bcolors.HEADER + self.get_function_name(instruction) + bcolors.ENDC)

            else:
                return "%s" % (instruction)
        except Exception as e:
            print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't replace name this opcode '%s'" % instruction + bcolors.ENDC
            raise e

    def print_instruction(self,nn, offset, code, instruction):
        """
        Print instruction in arguments
        @param : offset
        @param : code
        @param : instruction
        """
        if self.get_entry_point() == offset:
            print "\t-------------- ENTRYPOINT -------------"
        if  offset in self.map_cal:
            print "\t %s%s%s" % (bcolors.OKGREEN,self.map_cal[offset],bcolors.ENDC)
        try:
            if offset == self.register.eip:
                print "\t%s%s%s%04x : %15s : %s%s%s%s" % (bcolors.BGGREEN, bcolors.BOLD, bcolors.FGBLACK, offset, code, self.replace_function(instruction), bcolors.ENDC, bcolors.ENDC, bcolors.ENDC)
            else:
                print "\t%04x : %15s : %s" % (offset, code, self.replace_function(instruction))
        except Exception as e:
            print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't print this instructrion '%s:%s'" % (offset, instruction) + bcolors.ENDC
            raise e

    def next(self):
        """
        Advance one instruction
        """
        eip = self.register.eip
        dec = Decode(eip, self.data_code[eip:eip+0x40])
        self.set_position(dec[1][0])

        if self.verbose:
            self.print_assembly()

    def previous(self):
        """
        Advance one instruction
        """
        eip = self.register.eip
        dec = Decode(eip-0x40, self.data_code[eip-0x40:eip])
        s = len(dec)
        self.set_position(dec[s-1][0])

        if self.verbose:
            self.print_assembly()

# vim:ts=4:expandtab:sw=4
