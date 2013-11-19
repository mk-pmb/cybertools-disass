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
from disass.template import Template

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

AUTO_ENCODING = 0
ASCII_ENCODING = 1
UNICODE_ENCODING = 2

STDCALL = 0x100
CDECL = 0x101
FASTCALL = 0x102
THISCALL = 0x103

class Disass32():
    """
    Detect all executable
    """
    @script
    def __init__(self, path=None, data=None, verbose=False):

        self.verbose = verbose
        self.path = path
        self.register = Register32(self)

        self.map_call = dict()
        self.map_call_by_name = dict()
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

        self.action_reverse = dict()
        self.symbols_imported = dict()
        self.symbols_imported_by_name = dict()
        self.symbols_exported = dict()
        self.symbols_exported_by_name = dict()
        self.get_list_imported_symbols()
        self.get_list_exported_symbols()
        self.decode = None
        self.data_code = self.pe.get_memory_mapped_image()
        ep = self.get_entry_point()
        self.map_call[ep]="Entrypoint"
        self.map_call_by_name["Entrypoint"] = ep
        self.set_position(ep)
        self.backhistory = []



    def get_list_imported_symbols(self):
        """
        TODO:
        """
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.ordinal != None:
                        name = "%s@%d" % (entry.dll, imp.ordinal)
                        self.symbols_imported[int(imp.address)] = name
                        self.symbols_imported_by_name[name] = int(imp.address)

                    else:
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

    def set_position(self, pos):
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

        return True

    def set_virtual_position(self, pos):
        """
        TODO:
        """
        return self.set_position(pos - self.pe.OPTIONAL_HEADER.ImageBase)

    @script
    def go_to_instruction(self, instruction, offset=0):
        return self._go_to_instruction(instruction, offset, [])

    @script
    def go_to_next_call(self, name, offset=0):
        eip = self.register.eip
        res = self._go_to_next_call(name, offset, [])
        if not res:
            self.set_position(eip)
            return False
        return True

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
                self.backhistory = history
                self.set_position(offset)
                return True

            if 'RET' in instruction:
                return False

            if "CALL" in instruction :
                address_expression = self._get_function_name(instruction)

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
                            self.map_call_by_name["CALL_%x" % address] = address

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
                self.backhistory = history
                self.set_position(offset)
                return True

            if 'RET' in instruction:
                return False

            if 'JMP' in instruction or 'JNZ' in instruction:
                address_expression = self._get_function_name(instruction)

                if address_expression in self.symbols_imported_by_name:
                    #Trampoline Function
                    name_tampoline = "__jmp__%s"%address_expression
                    self.symbols_imported_by_name[name_tampoline] = offset
                    self.symbols_imported[offset] = name_tampoline

                    if name in name_tampoline:
                        self.set_position(history[-2])
                        self.backhistory = history[:-2]
                        return True

                    return False

                if address_expression == None:
                    continue

                if "0x" in address_expression:
                    if '[' in address_expression:
                        continue
                    if ':' in address_expression:
                        continue

                    try:
                        address = compute_operation(address_expression, self.register)
                    except Exception as e:
                        print >> sys.stderr, str(e), address_expression
                        print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't eval JMP instruction'%s'" % instruction + bcolors.ENDC
                        continue

                    if address in history:
                        continue
                    if self._go_to_next_call(name, address, history, indent+1):
                        return True


            if "CALL" in instruction:

                address_expression = self._get_function_name(instruction)


                if "0x" in address_expression:
                    if '[' in address_expression:
                        continue
                    if ':' in address_expression:
                        continue

                    try:
                        address = compute_operation(address_expression, self.register)
                    except Exception as e:
                        print >> sys.stderr, str(e), address_expression
                        print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't eval CALL instruction'%s'" % instruction + bcolors.ENDC
                        continue

                    if address in history:
                        continue

                    if address not in self.map_call:
                        self.map_call[address] = "CALL_%x" % address
                        self.map_call_by_name["CALL_%x" % address] = address

                    if self._go_to_next_call(name, address, history, indent+1):
                        return True


                if self.is_register(instruction):
                    self.backhistory = history
                    self.update_stack_and_register(offset)

                    value = self.register.get(address_expression.lower())
                    if value in self.symbols_imported:
                        if name == self.symbols_imported[value]:
                            self.backhistory = history
                            self.set_position(offset)
                            return True

        return False

    def get_value(self, address):
        address = address - self.pe.OPTIONAL_HEADER.ImageBase

        return  self.data_code[address:address+0x100]



    def get_string(self, address, type=AUTO_ENCODING):
        import string
        data = self.get_value(address)

        if data[0] in string.printable:

            if type == AUTO_ENCODING:
                if data[1] == '\x00':
                    return self._extract_unicode_string(data)

                elif data[1] in string.printable:
                    return self._extract_ascii_string(data)

            if type == UNICODE_ENCODING:
                return self._extract_unicode_string(data)

            if type == ASCII_ENCODING:
                return self._extract_ascii_string(data)

        return None


    def _extract_unicode_string(self, data):
        if data[1] == '\x00':
            return str(data.split('\x00\x00')[0].replace('\x00', ''))

    def _extract_ascii_string(self, data):
        import string
        if data[1] in string.printable:
            return data.split('\x00')[0]

    def _extract_address(self, opcode):
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
            elif "JNZ" in opcode:
                if "JNZ DWORD" in opcode:
                    saddr = opcode.split(' ')[2]
                elif "JNZ FAR" in opcode:
                    if "JNZ FAR DWORD" in opcode:
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

    def _extract_value(self, opcode):
        """

        """
        try:
            # Récupération de l'adresse
            if "PUSH" in opcode:
                if "PUSHF" in opcode:
                    return ''
                if "PUSH DWORD" in opcode:
                    saddr = opcode.split(' ')[2]
                else:
                    saddr = opcode.split(' ')[1]
                return saddr

            elif "POP" in opcode:
                if "POPF" in opcode:
                    return ''

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

    def _get_function_name(self, opcode=None, saddr=None):
        """
        @param opcode: Opcode what we want resolv.
        @type opcode:
        @param saddr:
        @type saddr:
        """
        if opcode!=None:

            try:
                saddr = self._extract_address(opcode)

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
            self.print_instruction(nn, b[0], b[3], b[2])
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
                fct = self._get_function_name(instruction)
                if fct == None:
                    return instruction
                if "CALL DWORD" in instruction:
                    return "CALL DWORD %s" % (bcolors.HEADER + fct + bcolors.ENDC)

                elif "CALL" in instruction:
                    return "CALL %s" % (bcolors.HEADER + fct + bcolors.ENDC)

            elif "JMP" in instruction:
                fct = self._get_function_name(instruction)
                if fct == None:
                    return instruction
                if "JMP DWORD" in instruction:
                    return "JMP DWORD %s" % (bcolors.HEADER + fct + bcolors.ENDC)
                else:
                    return "JMP %s" % (bcolors.HEADER + fct + bcolors.ENDC)

            else:
                return "%s" % (instruction)
        except Exception as e:
            print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't replace name in this instruction '%s'" % instruction + bcolors.ENDC
            print >> sys.stderr, str(e)
            return instruction

    def print_instruction(self, nn=0, offset=None, code=None, instruction=None):
        """
        Print instruction in arguments
        @param : offset
        @param : code
        @param : instruction
        """

        if offset==None and code==None and instruction == None:
            offset = self.decode[0:1][0][0]
            code = self.decode[0:1][0][3]
            instruction = self.decode[0:1][0][2]

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
                            strva = self.get_string(address)

                        if '0x' in last_part and len(last_part) == 10 and '[' in last_part:
                            address = int(last_part[1:-1], 16)
                            strva = "0x%x -> %s"% (address, self.symbols_imported[address])
                except:
                    strva = None
                    pass

                if strva != None:
                    print "\t%04x : %15s : %-50s\t%s;%s%s" % (offset, code, self.replace_function(instruction), bcolors.OKBLUE, strva, bcolors.ENDC)

                else:
                    print "\t%04x : %15s : %-50s" % (offset, code, self.replace_function(instruction))
        except Exception as e:
            print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't print this instruction '%s:%s'" % (offset, instruction) + bcolors.ENDC
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

    def up(self):
        f1 = self.where_am_i()
        c = 0
        for h in self.backhistory:
            if h == self.map_call_by_name[f1]:
                self.backhistory = self.backhistory[:c]
                self.set_position(previous_position)
                return True
            else:
                previous_position = h
            c+=1
        return False

    def where_am_i(self, offset=None):
        if offset == None:
            offset = self.register.eip

        data = self.map_call

        if offset in data:
            return data[offset]
        else:
            return data[offset] if offset in data else data[min(data.keys(), key=lambda k: abs(offset-k if offset-k>0 else k ))]

    def where_start_my_bloc(self,offset=None):
        if offset == None:
            offset = self.register.eip

        self.backhistory.reverse()
        hr = self.backhistory
        p = hr[0]
        for h in hr[1:]:
            if p-h<0:
                self.backhistory.reverse()
                return p
            if p-h>0x10:
                self.backhistory.reverse()
                return p
            p = h
        return offset

    def rename_function(self, old_name, new_name):
        """
        @param old_name
        @param new_name
        """
        if old_name in self.map_call_by_name:
            addr = self.map_call_by_name[old_name]
            self.map_call[addr] = new_name
            self.map_call_by_name[new_name] = addr
            del self.map_call_by_name[old_name]
        else:
            raise FunctionNameNotFound


    def get_instruction(self,offset=None):
        if offset == None:
            offset = self.register.eip

        return Decode(offset, self.data_code[offset:offset+0x20])[0][2]

    @script
    def get_stack(self, offset=None):
        """
        Get Stack from a
        """
        if offset == None:
            offset = self.register.eip

        instruction = Decode(offset, self.data_code[offset:offset+0x50])[0][2]
        if "CALL" not in instruction:
            return None

        self.update_stack_and_register(offset)
        return self.stack

    @script
    def get_arguments(self, n=None, convention=STDCALL, offset=None):
        """
        Get arguments from a
        """
        if offset == None:
            offset = self.register.eip
        self.update_stack_and_register(offset)
        if convention==STDCALL or convention==CDECL or convention==THISCALL:
            if n == None:
                return self.get_stack(offset=offset)
            else:
                return self.get_stack(offset=offset)[n]

        if convention==FASTCALL:
            if n==None:
                l = []
                l.append(self.register.ecx)
                l.append(self.register.edx)
                l.extend(self.get_stack(offset=offset))
                return l
            elif n == 0:
                return self.register.ecx
            elif n == 1:
                return self.register.edx
            else:
                return self.get_stack(offset=offset)[n-2]




    def update_stack_and_register(self, offset=None):
        """
        Update Stack and register
        """
        if offset == None:
            offset = self.register.eip

        # Am I on a function ?
        functionname = self.where_am_i(offset)

        addr = self.map_call_by_name[functionname]
        if addr < offset:
            s = addr
            e = offset
        else:
            s = self.where_start_my_bloc()
            e = offset

        self.stack = list()
        for d in Decode(addr, self.data_code[s:e]):
            if "PUSH" in d[2]:
                svalue = self._extract_value(d[2])

                if svalue == '':
                    continue

                if '[' in svalue:
                    svalue = svalue[1:-1]
                    svalue = compute_operation(svalue, self.register)
                    svalue = "[%s]" % svalue
                else:
                    svalue = compute_operation(svalue, self.register)
                self.stack.append(svalue)

            elif "POP" in d[2]:
                svalue = self._extract_value(d[2])

                if svalue == '':
                    continue

                svalue = compute_operation(svalue, self.register)
                self.stack.append(svalue)

            elif "CALL" in d[2]:
                continue

            elif "LEAVE" in d[2]:
                continue

            elif "MOVSD" in d[2]:
                continue

            elif ("MOV" in d[2] or "LEA" in d[2]):
                bloc = d[2].split(' ')
                if "DWORD" in d[2]:
                    pass
                elif "BYTE" in d[2]:
                    pass
                else:
                    bloc = d[2].split(' ')

                    if 'REP' in bloc:
                        continue
                    if 'MOVSW' in bloc:
                        continue
                    if 'MOVSB' in bloc:
                        continue
                    if 'MOVZX' in bloc:
                        continue
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
                        print >> sys.stderr, bcolors.FAIL + "\tErreur: '%s'" % (bloc) + bcolors.ENDC
                        print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't update stack and registry '%s' for %s" % (str(e),d[2]) + bcolors.ENDC
                        pass

            elif "XOR" in d[2]:
                try:
                    bloc = d[2].split(' ')
                    dst = bloc[1][:-1].lower()
                    if '[' in d[2]:
                        continue
                    src = bloc[2].lower()
                    self.register.set(dst, self.register.get(dst) ^ self.register.get(src))
                except Exception as e:
                    print >> sys.stderr, bcolors.FAIL + "\tErreur: '%s'" % (bloc) + bcolors.ENDC
                    print >> sys.stderr, bcolors.FAIL + "\tErreur: Can't xor '%s' for %s" % (str(e),d[2]) + bcolors.ENDC
                    pass


        self.stack.reverse()

    def make_template(self, start=0, nb_instruction=0x20):
        n = nb_instruction
        eip = self.register.eip

        position = 0

        dec = self.decode[position:position+n]

        nn = 0
        assembly=''
        for b in dec:
            assembly += b[2]+'\n'

        template = Template(assembly)
        print template.compare(assembly)


# vim:ts=4:expandtab:sw=4
