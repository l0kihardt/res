#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1
BINARY_NAME = './tea'
# modify this
elf = ELF(BINARY_NAME)

if DEBUG:
    io = process(BINARY_NAME)
else:
    io = remote(sys.argv[1], int(sys.argv[2]))

if DEBUG: context(log_level='debug')
pause()

# define symbols and offsets here


