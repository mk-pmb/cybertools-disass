#!/usr/bin/env python
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

"""
@author:       Ivan Fontarensky
@contact:      ivan.fontarensky@cassidian.com
@organization: Cassidian CyberSecurity
"""

__author__ = 'ifontarensky'


class DisassException(Exception):
    """Generic Disass Specific exception, to help differentiate from other exceptions"""
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class DataNotWin32ApplicationError(DisassException):
    """Data Not a Win32 Application Exception"""
    def __init__(self):
        self.reasons = []
        DisassException.__init__(self, "This is not a valid win32 application")


class InvalidValueEIP(DisassException):
    """Exception for gracefully not saving Relative URLs in the cache"""


class FunctionNameNotFound(DisassException):
    """Exception for failed sanity checks (which can potentially be disabled)"""




# vim:ts=4:expandtab:sw=4