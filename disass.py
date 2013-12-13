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
##  Author: Jean Michel Picod <jean-michel.picod@cassidian.com>            ##
##                                                                         ##
#############################################################################

"""

@author:       Jean Michel Picod
@contact:      jean-michel.picod@cassidian.com
@author:       Ivan Fontarensky
@contact:      ivan.fontarensky@cassidian.com
@organization: Cassidian CyberSecurity
"""

__author__ = 'ifontarensky'
__author__ = 'jmpicod'

import sys
import __builtin__


def get_jeanmishell():
    try:
        import IPython.Shell
        return IPython.Shell.IPShell(argv=[''], user_ns=locals(), user_global_ns=globals())
    except ImportError as e:
        try:
            from IPython.terminal.interactiveshell import TerminalInteractiveShell
        except ImportError:
            try:
                from IPython.frontend.terminal.interactiveshell import TerminalInteractiveShell
            except ImportError:
                return None
        ipsh = TerminalInteractiveShell()
        ipsh.user_global_ns.update(globals())
        ipsh.user_global_ns.update(locals())
        ipsh.autocall = 2
        return ipsh

if __name__ == '__main__':
    import code
    import traceback
    intro = """Disass - Tool for manipulating binary and make script to reverse

This how you can interact with dumps:
    >>> disass = Disass32(path=malware.exe)
    >>> print "%x" % disass.registry.eax


"""
    try:
        import rlcompleter
        import readline
    except ImportError as e:
        print >>sys.stderr, traceback.format_exc()
    else:
        class DisassCompleter(rlcompleter.Completer):
            pass

        readline.set_completer(DisassCompleter().complete)
        readline.parse_and_bind("C-o: operate-and-get-next")
        readline.parse_and_bind("tab: complete")

    builtins = __import__("disass.all", globals(), locals(), ["."]).__dict__
    __builtin__.__dict__.update(builtins)

    ipsh = get_jeanmishell()
    if ipsh is not None:
        ipsh.mainloop(intro)
    else:
        ipsh = code.InteractiveConsole(globals())
        ipsh.interact(intro)

# vim:ts=4:expandtab:sw=4
