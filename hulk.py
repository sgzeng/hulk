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
flag = 'BCTF{beaty_and_beast}'

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

#input string in hex format, output the hex decoded string
def hex2charlist(hexstr):
    charlist = []
    length = len(hexstr)
    if length % 2 != 0:
        hexstr = '0' + hexstr
        length += 1
    for i in range(0, length, 2):
        charlist.append(chr(int(hexstr[i]+hexstr[i+1], 16)))
    return charlist

if __name__ == '__main__':
    pattern = '\A[0-9a-fA-F]+\Z'
    # while True:
    request1 = raw_input('Give me the first hex vaule to encrypt: 0x').strip()
    if len(request1) > 64 or not re.match(pattern, request1):
        print 'invalid input, bye!'
        exit(0)
    plaintext1 = "".join(item for item in hex2charlist(request1)) + flag
    ciphertext1 = encrypt(plaintext1, refresh_key = True)
    plaintext1_str = request1+'|flag'
    ciphertext1_str = ciphertext1.encode('hex')
    print 'plaintext: 0x%s\nciphertext: 0x%s' % (plaintext1_str, ciphertext1_str)

    request2 = raw_input('Give me the second hex vaule to encrypt: 0x').strip()
    if len(request2) > 64 or not re.match(pattern, request2):
        print 'invalid input, bye!'
        exit(0)
    plaintext2 = "".join(item for item in hex2charlist(request2))
    ciphertext2 = encrypt(plaintext2, str(ciphertext1[-16:]), refresh_key = False)
    plaintext2_str = request2
    ciphertext2_str = ciphertext2.encode('hex')
    print 'plaintext: 0x%s\nciphertext: 0x%s' % (plaintext2_str, ciphertext2_str)

