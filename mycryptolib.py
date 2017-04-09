#!/usr/bin/env python
# -*- coding: utf-8 -*-

class Unbuffered(object):
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)

import sys
sys.stdout = Unbuffered(sys.stdout)
import random
import binascii
import re
from Crypto.Cipher import AES
from Crypto import Random

key = 'V38lKILOJmtpQMHp'
flag = 'BCTF{3c1fffb76f147d420f984ac651505905}'

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def encrypt( msg, iv_p=0, refresh_key = False):
    raw = pad(msg)
    if iv_p == 0:
        iv = Random.new().read( AES.block_size )
    else:
        iv = iv_p
    global key
    if refresh_key == True:
        key = Random.new().read( AES.block_size )
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return cipher.encrypt( raw )
