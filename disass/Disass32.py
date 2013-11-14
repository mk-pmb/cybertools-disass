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

import sys, traceback

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
from disass.exceptions import FunctionNameNotFound

history_cmd_to_script = list()

def script(funct_to_script):


    def wrapper_around_function(*args, **kwargs):

        # Execute before execution, save command
        history_cmd_to_script.append((funct_to_script.__name__, args[1:]))

        # Call function
        res = funct_to_script(*args, **kwargs)

        # Execute after execution, save result
        return res

    return wrapper_around_function

def make_script():
    s='''
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from disass.Disass32 import Disass32

'''
    print history_cmd_to_script
    for hist in history_cmd_to_script:
        func = hist[0]


        if func == 'go_to_function':
            s += '''
if not disass.%s(%s):
    return

''' % (func, hist[1])
        else:
            s += '''
disass.%s(%s)''' % (func, hist[1])

    print s



class Disass32():
    """
    Detect all executable
    """
    @script
    def __init__(self, path=None, data=None, verbose=False):

        self.verbose = verbose
        self.register = Register32(self)

        self.map_call = dict()
        self.map_call_by_addr = dict()
        self.load_win32_pe(path=path, data=data)


    def load_win32_pe(self, path=None, data=None):
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
        ep = self.get_entry_point()
        self.map_call[ep]="Entrypoint"
        self.map_call_by_addr["Entrypoint"] = ep
        self.set_position(ep)


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

    def is_register(self, value):
        """
        Check if a value is in registeraddress = self.extract_address(instruction)
            if address != '' and '[' in address:
        @param value
        """
        v = value.lower()

        v=v.replace('call', '')

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

    @script
    def go_to_function(self, name, offset=0):
        return self._go_to_function(name, offset, [])

    @script
    def go_to_instruction(self, instruction, offset=0):
        return self._go_to_instruction(instruction, offset, [])

    @script
    def go_to_next_call(self, name, offset=0):
        return self._go_to_next_call(name, offset, [])

    def _go_to_function(self, name, offset, history=[], indent=1):
        """

        """

        if offset == 0:
            self.next()
            eip = self.register.eip
            offset = eip


        for d in Decode(offset, self.data_code[offset:offset+0x1000]):
            instruction = d[2]
            offset = d[0]

            history.append(offset)

            if name in self.replace_function(instruction):
                self.set_position(offset)
                return True

            if 'RET' in instruction:
                return False

            if "CALL" in instruction :
                address_expression = self.get_function_name(instruction)

                if "0x" in address_expression:
                    if '[' in address_expression:
                        continue
                    if ':' in address_expression:
                        continue

                    try:
                        address = compute_operation(address_expression, self.register)

                        if address in history:
                            continue

                        if address not in self.map_call:
                            self.map_call[address] = "CALL_%x" % address
                            self.map_call_by_addr["CALL_%x" % address] = address

                        if self._go_to_function(name, address, history, indent+1):
                            return True

                    except Exception as e:
                        print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't eval instruction'%s'" % instruction + bcolors.ENDC

        return False

    def _go_to_instruction(self, instruction_search, offset, history=[], indent=1):
        """

        """

        if offset == 0:
            self.next()
            eip = self.register.eip
            offset = eip


        for d in Decode(offset, self.data_code[offset:offset+0x1000]):
            instruction = d[2]
            offset = d[0]

            history.append(offset)

            if instruction_search in instruction:
                self.set_position(offset)
                return True

            if 'RET' in instruction:
                return False

            if "CALL" in instruction :
                address_expression = self.get_function_name(instruction)

                if "0x" in address_expression:
                    if '[' in address_expression:
                        continue
                    if ':' in address_expression:
                        continue

                    try:
                        address = compute_operation(address_expression, self.register)

                        if address in history:
                            continue

                        if address not in self.map_call:
                            self.map_call[address] = "CALL_%x" % address
                            self.map_call_by_addr["CALL_%x" % address] = address

                        if self._go_to_instruction(instruction_search, address, history, indent+1):
                            return True

                    except Exception as e:
                        print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't eval instruction'%s'" % instruction + bcolors.ENDC

        return False

    def _go_to_next_call(self, name, offset, history=[], indent=1):
        """

        """

        if offset == 0:
            self.next()
            eip = self.register.eip
            offset = eip



        for d in Decode(offset, self.data_code[offset:offset+0x1000]):
            instruction = d[2]
            offset = d[0]

            history.append(offset)

            if name in self.replace_function(instruction):
                self.set_position(offset)
                return True

            if 'RET' in instruction:
                return False

            if "CALL" in instruction :
                address_expression = self.get_function_name(instruction)

                if "0x" in address_expression:
                    if '[' in address_expression:
                        continue
                    if ':' in address_expression:
                        continue

                    try:
                        address = compute_operation(address_expression, self.register)

                        if address in history:
                            continue

                        if address not in self.map_call:
                            self.map_call[address] = "CALL_%x" % address
                            self.map_call_by_addr["CALL_%x" % address] = address

                        if self._go_to_next_call(name, address, history, indent+1):
                            return True

                    except Exception as e:
                        print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't eval instruction'%s'" % instruction + bcolors.ENDC

                if self.is_register(instruction):
                    self.update_stack_and_register(offset)

                    value = self.register.get(address_expression.lower())
                    if value in self.symbols_imported:
                        if name == self.symbols_imported[value]:
                            self.set_position(offset)
                            return True

        return False


    def get_value(self, address):

        address = address - self.pe.OPTIONAL_HEADER.ImageBase

        data = self.data_code[address:address+0x100]

        return data

    def get_string(self, data):
        if data[0].isalpha():

            #is unicode ?
            if data[1] == '\x00':
                return str(data.split('\x00\x00')[0].replace('\x00', ''))

            elif data[1].isalpha():
                return data.split('\x00')[0]

        return None

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

    def extract_value(self, opcode):
        """

        """
        try:
            # Récupération de l'adresse
            if "PUSH" in opcode:
                if "PUSH DWORD" in opcode:
                    saddr = opcode.split(' ')[2]
                else:
                    saddr = opcode.split(' ')[1]
                return saddr

            elif "POP" in opcode:
                if "POP DWORD" in opcode:
                    saddr = opcode.split(' ')[2]
                else:
                    saddr = opcode.split(' ')[1]
                return saddr

            else:
                return ''
        except:
            print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't extract value : '%s' found " % (opcode) + bcolors.ENDC
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
                addr = int(saddr2, 16)

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

        if dec[0][0] not in self.map_call:
            offset = dec[0][0]
            print "\t %s%s%s" % (bcolors.OKGREEN, self.where_am_i(offset=offset), bcolors.ENDC)
            print '\t [...]'

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
        if offset in self.map_call:
            print "\t %s%s%s" % (bcolors.OKGREEN, self.map_call[offset], bcolors.ENDC)
        try:
            if offset == self.register.eip:
                print "\t%s%s%s%04x : %15s : %s%s%s%s" % (bcolors.BGGREEN, bcolors.BOLD, bcolors.FGBLACK, offset, code, self.replace_function(instruction), bcolors.ENDC, bcolors.ENDC, bcolors.ENDC)
            else:
                found = False
                strva = None
                last_part = instruction.split(' ')[-1:][0]
                for r in self.register.get_list_register():
                    if r in last_part.lower():
                        found = True
                try:
                    if not found:
                        if '0x' in last_part and len(last_part) == 8 and '[' not in last_part:
                            address = int(last_part, 16)
                            value = self.get_value(address)
                            strva = self.get_string(value)

                        if '0x' in last_part and len(last_part) == 10 and '[' in last_part:
                            address = int(last_part[1:-1], 16)
                            strva = "0x%x -> %s"% (address, self.symbols_imported[address])
                except:
                    strva = None
                    pass

                if strva != None:
                    print "\t%04x : %15s : %s\t\t%s;%s%s" % (offset, code, self.replace_function(instruction), bcolors.OKBLUE, strva, bcolors.ENDC)

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

    def where_am_i(self, offset=None):
        if offset == None:
            offset = self.register.eip

        data = self.map_call

        if offset in data:
            return data[offset]
        else:
            return data[offset] if offset in data else data[min(data.keys(), key=lambda k: abs(offset-k if offset-k>0 else k ))]


    def rename_function(self, old_name, new_name):
        """
        @param old_name
        @param new_name
        """
        if old_name in self.map_call_by_addr:
            addr = self.map_call_by_addr[old_name]
            self.map_call[addr] = new_name
            self.map_call_by_addr[new_name] = addr
            del self.map_call_by_addr[old_name]
        else:
            raise FunctionNameNotFound


    def get_instruction(self,offset=None):
        if offset == None:
            offset = self.register.eip

        return Decode(offset, self.data_code[offset:offset+0x20])[0][2]

    @script
    def get_arguments(self, offset=None):
        """
        Get arguments from a
        """
        if offset == None:
            offset = self.register.eip

        instruction = Decode(offset, self.data_code[offset:offset+0x50])[0][2]
        if "CALL" not in instruction:
            return None

        self.update_stack_and_register(offset)
        return self.stack


    def update_stack_and_register(self, offset):
        """
        Update Stack and register
        """
        if offset == None:
            offset = self.register.eip

        # Am I on a function ?
        functionname = self.where_am_i(offset)

        addr = self.map_call_by_addr[functionname]

        self.stack = list()
        for d in Decode(addr, self.data_code[addr:addr+(offset-addr)]):

            if "PUSH" in d[2]:
                svalue = self.extract_value(d[2])

                if '[' in svalue:
                    svalue = svalue[1:-1]
                    svalue = compute_operation(svalue, self.register)
                    svalue = "[%s]" % svalue
                else:
                    svalue = compute_operation(svalue, self.register)
                self.stack.append(svalue)

            elif "POP" in d[2]:
                svalue = self.extract_value(d[2])
                svalue = compute_operation(svalue, self.register)
                self.stack.append(svalue)

            elif "CALL" in d[2]:
                self.stack=list()

            elif "LEAVE" in d[2]:
                continue

            elif "MOV" in d[2] or "LEA" in d[2]:
                bloc = d[2].split(' ')
                if "DWORD" in d[2]:
                    pass
                elif "BYTE" in d[2]:
                    pass
                else:
                    bloc = d[2].split(' ')

                    try:
                        dst = bloc[1][:-1].lower()
                        src = bloc[2].lower()

                        if '[' in dst:
                            continue
                        if ':' in src or ':' in dst:
                            continue


                        if '[' in src:
                            value_src = compute_operation(src[1:-1], self.register)
                            self.register.set_address(dst, value_src)
                        else:
                            value_src = compute_operation(src, self.register)
                            self.register.set(dst, value_src)

                    except Exception as e:
                        print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't update stack and registry '%s'" % (str(e)) + bcolors.ENDC
                        pass

            elif "XOR" in d[2]:
                bloc = d[2].split(' ')
                dst = bloc[1][:-1].lower()
                src = bloc[2].lower()
                self.register.set(dst, self.register.get(dst) ^ self.register.get(src))


        self.stack.reverse()




# vim:ts=4:expandtab:sw=4
