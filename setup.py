#!/usr/bin/python
#############################################################################
##                                                                         ##
## This file is part of magic                                              ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2012 Cassidian CyberSecurity SAS. All rights reserved.    ##
## This document is the property of Cassidian CyberSecurity SAS, it may    ##
## not be circulated without prior licence                                 ##
##                                                                         ##
##  Author: Ivan Fontarensky <ivan.fontarensky@cassidian.com>              ##
##  Author: Fabien Perigaud <fabien.perigaud@cassidian.com>                ##
##  Author: Jeremy Richard <jeremy.richard@cassidian.com>                  ##
##  Author: Jean-Michel Picod <jean-michel.picod@cassidian.com>            ##
##                                                                         ##
#############################################################################

"""
@author:       Ivan Fontarensky
@contact:      ivan.fontarensky@cassidian.com
@organization: Cassidian CyberSecurity
"""


from distutils.core import setup


data_files = []

setup(
    name='disass',
    version='0.5',
    packages=['disass'],
    data_files=data_files,
    # Metadata
    author='Ivan Fontarensky',
    author_email='ivan.fontarensky@cassidian.com',
    license='GPLv3',
    # keywords='',
)
