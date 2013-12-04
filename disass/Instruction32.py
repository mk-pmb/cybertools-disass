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

from pyparsing import Literal, CaselessLiteral, Word, Group, Optional, \
    ZeroOrMore, Forward, nums, alphas, Regex, ParserElement, ParseException

import math
import operator
import re


def bnf(exprStack):
    """
    expop   :: '^'
    multop  :: '*' | '/'
    addop   :: '+' | '-'
    integer :: ['+' | '-'] '0'..'9'+
    atom    :: PI | E | real | fn '(' expr ')' | '(' expr ')'
    factor  :: atom [ expop factor ]*
    term    :: factor [ multop factor ]*
    expr    :: term [ addop term ]*
    """
    def pushFirst(strg, loc, toks):
        exprStack.append(toks[0])

    def pushUMinus(strg, loc, toks):
        for t in toks:
            if t == '-':
                exprStack.append('unary -')
                #~ exprStack.append('-1')
                #~ exprStack.append('*')
            else:
                break

    point = Literal('.')
    e     = CaselessLiteral('E')
    #~ fnumber = Combine(Word('+-'+nums, nums) +
                       #~ Optional(point + Optional(Word(nums))) +
                       #~ Optional(e + Word('+-'+nums, nums)))
    fnumber = Regex(r' [+-]? \d+ (:? \. \d* )? (:? [eE] [+-]? \d+)?', re.X)
    xnumber = Regex(r'0 [xX] [0-9 a-f A-F]+', re.X)
    ident = Word(alphas, alphas+nums+'_$')

    plus  = Literal('+')
    minus = Literal('-')
    mult  = Literal('*')
    div   = Literal('/')
    lpar  = Literal('(').suppress()
    rpar  = Literal(')').suppress()
    addop  = plus | minus
    multop = mult | div
    expop = Literal('^')
    pi    = CaselessLiteral('PI')

    expr = Forward()
    atom_parts = pi | e | xnumber | fnumber | ident + lpar + expr + rpar | ident
    atom_action = atom_parts.setParseAction(pushFirst)
    group = Group(lpar + expr + rpar)
    atom = ((0, None) * minus + atom_action | group).setParseAction(pushUMinus)

    # by defining exponentiation as 'atom [ ^ factor ]...' instead of 'atom [ ^ atom ]...',
    # we get right-to-left exponents, instead of left-to-right
    # that is, 2^3^2 = 2^(3^2), not (2^3)^2.
    factor = Forward()
    factor << atom + ZeroOrMore((expop + factor).setParseAction(pushFirst))

    term = factor + ZeroOrMore((multop + factor).setParseAction(pushFirst))
    expr << term + ZeroOrMore((addop + term).setParseAction(pushFirst))
    return expr


# map operator symbols to corresponding arithmetic operations
epsilon = 1e-12
opn = { '+' : operator.add,
        '-' : operator.sub,
        '*' : operator.mul,
        '/' : operator.truediv,
        '^' : operator.pow }


def evaluateStack(s):
    op = s.pop()
    if op == 'unary -':
        return -evaluateStack(s)
    if op in '+-*/^':
        op2 = evaluateStack(s)
        op1 = evaluateStack(s)
        return opn[op](op1, op2)
    elif op == 'PI':
        return math.pi # 3.1415926535
    elif op == 'E':
        return math.e  # 2.718281828
    elif op[0].isalpha():
        raise Exception('invalid identifier "%s"' % op)
    elif op.startswith('0x') or op.startswith('0X'):
        return int(op, 16)
    elif '.' in op or 'e' in op or 'E' in op:
        return float(op)
    else:
        return int(op)


def evaluate(expression, exprStack=None):
    exprStack = exprStack or []
    bnf(exprStack).parseString(expression, parseAll=True)
    return evaluateStack(exprStack[:])


ParserElement.verbose_stacktrace = False


def compute_operation(expVal, register):
    expVal = expVal.lower()
    for r in register.get_list_register():
        if r in expVal:
            expVal = expVal.replace(r, str(register.get(r)))
    return evaluate(expVal)


# vim:ts=4:expandtab:sw=4