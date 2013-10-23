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

from disass.exceptions import DataNotWin32ApplicationError

class Disass32():
    """
    Detect all executable
    """
    def __init__(self,path=None,data=None,verbose=False):
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
        self.verbose = verbose
        self.get_list_imported_symbols()
        self.get_list_exported_symbols()
        self.decode = None
        self.data_code = self.pe.get_memory_mapped_image()


    def get_list_imported_symbols(self):
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    self.symbols_imported[int(imp.address)] = imp.name
                    self.symbols_imported_by_name[imp.name] = int(imp.address)
        except Exception as e:
            pass


    def get_list_exported_symbols(self):
        try:
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                self.symbols_exported[int(exp.address)] = exp.name
                self.symbols_exported_by_name[exp.name] = int(exp.address)
        except Exception as e:
            pass