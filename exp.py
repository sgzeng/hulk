#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import binascii
import sys
from Crypto.Cipher import AES
from Crypto import Random
from zio import *

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encrypt( msg, iv_p=0):
    raw = pad(msg)
    if iv_p == 0:
        iv = Random.new().read( AES.block_size )
    else:
        iv = iv_p
    global key
    key = Random.new().read( AES.block_size )
    cipher = AES.new('V38lKILOJmtpQMHp', AES.MODE_CBC, iv )
    return cipher.encrypt( raw )


def xor_strings(xs, ys, zs):
    return "".join(chr(ord(x) ^ ord(y) ^ ord(z)) for x, y, z in zip(xs, ys, zs))

def xor_block(vector_init, previous_cipher,p_guess):
    xored = xor_strings(vector_init, previous_cipher, p_guess)
    return xored

def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

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
    print "Start cracking\n"
    secret = []
    i_know = "BCTF{"
    padding = 16 - len(i_know) - 1
    i_know = "a"*padding + i_know
    add_byte = 16
    length_block = 16
    t = 0
    while(t < 16):
        for i in range(0,256):
            io = zio('python ./hulk.py')
            # io = zio(('202.112.51.211',9999))
            io.write(("a"*(add_byte+padding)).encode('hex')+'\n')
            io.readline()
            enc = io.readline()[14:-1].decode('hex')
            original = split_len(binascii.hexlify(enc), 32)
            vector_init = str(enc[-length_block:])
            previous_cipher = str(enc[0:length_block])
            p_guess = i_know + chr(i)
            xored = xor_block( vector_init, previous_cipher, p_guess)
            xored_hex = xored.encode('hex')
            io.write(xored_hex+'\n')
            io.readline()
            enc = io.readline()[14:-1].decode('hex')
            result = split_len(binascii.hexlify(enc), 32)

            # sys.stdout.write("\r%s -> %s " % (original[1], result[0]))
            # sys.stdout.flush()

            if result[0] == original[1]:
                print " found secert " + chr(i)
                i_know = p_guess[1:]
                add_byte = add_byte - 1
                secret.append(chr(i))
                t = t + 1
                break
            elif i == 255:
                print "Unable to find the char..."
            io.close()
    found = ''.join(secret)
    print "\n" + found

