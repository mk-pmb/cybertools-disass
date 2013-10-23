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

"""
AL/AH/EAX : Registre général, sa valeur change très vite.
BL/BH/EBX : Registre général, peut servir d'offset mémoire (exemple : "mov al, byte ptr ds:[bx+10]").
CL/CH/ECX : Sert en général de compteur pour les boucles (exemple : "mov ecx, 5 ; rep movsd" : copie 5 doubles mots).
DL/DH/EDX : Registre général, obligatoire pour l'accès aux ports (moyen de communiquer avec toutes les puces de l'ordinateur, par exemple les ports 42h et 43h servent à contrôler le haut-parleur interne. Voyez les instructions IN et OUT.
CS : Segment mémoire du code.
DS : Segment mémoire des données.
ES : Segment mémoire.
FS : Autre segment mémoire.
GS : Autre segment mémoire.
SS : Segment mémoire de la pile ("S" = Stack = Pile).
BP : Offset mémoire, très souvent une copie de SP à laquelle on soustrait une valeur pour lire dans la pile (on ne doit pas modifier SP).
EDI/DI : Offset mémoire utilisé avec ES (ou FS ou GS si spécifié, exemple : "mov al, byte ptr gs:[10]").
EIP/IP : Offset mémoire du code (inaccessible directement, modifiable indirectement avec l'instruction CALL, JMP, ou J[cas]).
ESI/SI : Offset mémoire utilisé avec DS.
ESP/SP : Offset mémoire de la pile.\

"""

class Registry32(object):

    def __init__(self):
        self._eax = 0
        self._ebx = 0
        self._ecx = 0
        self._edx = 0

    def _set_eax(self,v):
        self._eax = v&0xffffffff

    def _get_eax(self):
        return self._eax

    def _get_ax(self):
        return (self._eax & 0x0000ffff)

    def _set_ax(self,v):
        self._eax = (self._eax & 0xffff0000) + (v & 0x0000ffff)

    def _set_ah(self,v):
        self._eax = (self._eax & 0xffff00ff) + ( v << 8 )

    def _get_ah(self):
        return ((self._eax & 0x0000ff00)>>8)

    def _set_al(self,v):
        self._eax = (self._eax & 0xffffff00) + ( v & 0x000000ff )

    def _get_al(self):
        return (self._eax & 0x000000ff)

    def _set_ebx(self,v):
        self._ebx = v&0xffffffff

    def _get_ebx(self):
        return self._ebx

    def _get_bx(self):
        return (self._ebx & 0x0000ffff)

    def _set_bx(self,v):
        self._ebx = (self._ebx & 0xffff0000) + (v & 0x0000ffff)

    def _set_bh(self,v):
        self._ebx = (self._ebx & 0xffff00ff) + ( v << 8 )

    def _get_bh(self):
        return ((self._ebx & 0x0000ff00)>>8)

    def _set_bl(self,v):
        self._ebx = (self._ebx & 0xffffff00) + ( v & 0x000000ff )

    def _get_bl(self):
        return (self._ebx & 0x000000ff)

    def _set_ecx(self,v):
        self._ecx = v&0xffffffff

    def _get_ecx(self):
        return self._ecx

    def _get_cx(self):
        return (self._ecx & 0x0000ffff)

    def _set_cx(self,v):
        self._ecx = (self._ecx & 0xffff0000) + (v & 0x0000ffff)

    def _set_ch(self,v):
        self._ecx = (self._ecx & 0xffff00ff) + ( v << 8 )

    def _get_ch(self):
        return ((self._ecx & 0x0000ff00)>>8)

    def _set_cl(self,v):
        self._ecx = (self._ecx & 0xffffff00) + ( v & 0x000000ff )

    def _get_cl(self):
        return (self._ecx & 0x000000ff)

    def _set_edx(self,v):
        self._edx = v&0xffffffff

    def _get_edx(self):
        return self._edx

    def _get_dx(self):
        return (self._edx & 0x0000ffff)

    def _set_dx(self,v):
        self._edx = (self._edx & 0xffff0000) + (v & 0x0000ffff)

    def _set_dh(self,v):
        self._edx = (self._edx & 0xffff00ff) + ( v << 8 )

    def _get_dh(self):
        return ((self._edx & 0x0000ff00)>>8)

    def _set_dl(self,v):
        self._edx = (self._edx & 0xffffff00) + ( v & 0x000000ff )

    def _get_dl(self):
        return (self._edx & 0x000000ff)

    def _set_edi(self,v):
        self._edi = v&0xffffffff

    def _get_edi(self):
        return self._edi

    def _get_di(self):
        return (self._edi & 0x0000ffff)

    def _set_di(self,v):
        self._edi = (self._edi & 0xffff0000) + (v & 0x0000ffff)

    def _set_eip(self,v):
        self._eip = v&0xffffffff

    def _get_eip(self):
        return self._eip

    def _get_ip(self):
        return (self._eip & 0x0000ffff)

    def _set_ip(self,v):
        self._eip = (self._eip & 0xffff0000) + (v & 0x0000ffff)

    def _set_esi(self,v):
        self._esi = v&0xffffffff

    def _get_esi(self):
        return self._esi

    def _get_si(self):
        return (self._esi & 0x0000ffff)

    def _set_si(self,v):
        self._esi = (self._esi & 0xffff0000) + (v & 0x0000ffff)

    def _set_esp(self,v):
        self._esp = v&0xffffffff

    def _get_esp(self):
        return self._esp

    def _get_sp(self):
        return (self._esp & 0x0000ffff)

    def _set_sp(self,v):
        self._esp = (self._esp & 0xffff0000) + (v & 0x0000ffff)


    eax = property(_get_eax, _set_eax,doc='read/write registry eax')
    ax = property(_get_ax, _set_ax,doc='read/write registry ax')
    ah = property(_get_ah, _set_ah,doc='read/write registry ah')
    al = property(_get_al, _set_al,doc='read/write registry al')

    ebx = property(_get_ebx, _set_ebx,doc='read/write registry ebx')
    bx = property(_get_bx, _set_bx,doc='read/write registry bx')
    bh = property(_get_bh, _set_bh,doc='read/write registry bh')
    bl = property(_get_bl, _set_bl,doc='read/write registry bl')

    ecx = property(_get_ecx, _set_ecx,doc='read/write registry ecx')
    cx = property(_get_cx, _set_cx,doc='read/write registry cx')
    ch = property(_get_ch, _set_ch,doc='read/write registry ch')
    cl = property(_get_cl, _set_cl,doc='read/write registry cl')

    edx = property(_get_edx, _set_edx,doc='read/write registry edx')
    dx = property(_get_dx, _set_dx,doc='read/write registry dx')
    dh = property(_get_dh, _set_dh,doc='read/write registry dh')
    dl = property(_get_dl, _set_dl,doc='read/write registry dl')

    edi = property(_get_edi, _set_edi,doc='read/write registry edi')
    di = property(_get_di, _set_di,doc='read/write registry di')

    eip = property(_get_eip, _set_eip,doc='read/write registry edi')
    ip = property(_get_ip, _set_ip,doc='read/write registry di')

    esi = property(_get_esi, _set_esi,doc='read/write registry edi')
    si = property(_get_si, _set_si,doc='read/write registry di')

    esp = property(_get_esp, _set_esp,doc='read/write registry edi')
    sp = property(_get_sp, _set_sp,doc='read/write registry di')
