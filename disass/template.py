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

import unicodedata
import re

notalphanum_re = re.compile('\W+')


TEMPLATES = ['0004080b0c0e0f0m0p0x10141518191c1f1j1p262c30383b3m404145464e4m4p585b5c5d5f606364686e6f7c80838486888a8b8c8e8m8p9094989b9ca1a8adaeahalanapaxb0b2b3b5b6b8babbbebpbxbyc7cacccdcecjcpcxd0d4dddedidldmdwdxeaebecedeeesf1f3fcfffmfpfsh0hdhehlhmhricieilimipjmjnjzl0laldlellmompndnzoporovp0pcpepmpopppspurdres0shsispstsutbteubusv0vdvevfvzwox0x1x2x3x4x5x6x8x9xaxbxcxexfxjxmxoxpxsxtxwxxytz0zx']


class Template():
    def __init__(self, assembly):
        self.assembly = assembly
        self.make_template(assembly)
        self.ngram = ''

    def compute_ngram(self, lines):
        """
        Compute ngram for input lines
        """
        line = ''.join(lines)
        return self.key_ngram(line, 2)

    def asciify(self, s):
        return unicodedata.normalize('NFKD', unicode(s)).encode('ASCII', 'ignore')

    def key_ngram(self, s, n):
        s = s.lower()
        s = notalphanum_re.sub('', s)
        len_s = len(s)
        ngrams = set()
        i = 0
        while i + n <= len_s:
            ngrams.add(s[i:i + n])
            i += 1
        return self.asciify(''.join(sorted(ngrams)))

    def make_template(self, assembly):
        self.ngram = self.compute_ngram(assembly)

    def compare(self, assembly):
        for t in TEMPLATES:
            return self.levenshtein(self.ngram, t)

    # http://hetland.org/coding/python/levenshtein.py
    def levenshtein(self, a, b):
        """Calculates the Levenshtein distance between a and b."""
        n, m = len(a), len(b)
        if n > m:
            # Make sure n <= m, to use O(min(n,m)) space
            a, b = b, a
            n, m = m, n
        current = range(n + 1)
        for i in xrange(1, m + 1):
            previous, current = current, [i] + [0] * n
            for j in xrange(1, n + 1):
                add, delete = previous[j] + 1, current[j - 1] + 1
                change = previous[j - 1]
                if a[j - 1] != b[i - 1]:
                    change += 1
                current[j] = min(add, delete, change)
        return current[n]

