#!/usr/bin/python

import wave
import sys
from struct import pack,unpack,unpack_from
from base64 import b64encode, b64decode
import string
import marshal
from gmpy import *

### Main ###

def welcome():
    print """
    *** F4bCTF framework ***
    """

def help(cmd=None):
    if cmd == None:
        print """No help :)"""

if __name__ == '__main__':
    welcome()

### Math / Crypto ###

def discrete_log():
    print """Pari/GP:
? znlog(h,Mod(g,p))
%4 = 46363574342518235210803009231514833
"""
class RC4:
    def __init__(self, key = None):
        self.state = list(range(256))
        self.x = self.y = 0
 
        if key is not None:
            self.init(key)
 
    def init(self, key):
        for i in range(256):
            self.x = (ord(key[i % len(key)]) + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0
 
    def crypt(self, input):
        output = [None]*len(input)
        for i in range(len(input)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = chr((ord(input[i]) ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF]))
        return ''.join(output)


### Stego ###

def stego_wave_lsb(filename, little_endian=True):
    fff = wave.open(filename, "rb")
    frames = fff.getnframes()
    xb = ""
    xc = ""
    for k in xrange(frames):
        d, = unpack_from("<H",fff.readframes(1))
        xb += "1" if (d & 1) != 0 else "0"
        if len(xb) == 8:
            if little_endian:
                xc += chr(int(xb[::-1],2))
            else:
                xc += chr(int(xb,2))
            xb = ""
    return xc

### Encoding ###

def base64_encode(a, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"):
    std_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if alphabet == std_alpha:
        return b64encode(a)
    return b64encode(a).translate(string.maketrans(std_alpha,alphabet))

def base64_decode(a, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"):
    std_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if alphabet == std_alpha:
        return b64decode(a)
    return b64decode(a.translate(string.maketrans(alphabet, std_alpha)))
    

### Basic Ops ###

def ror(x, y, size=32):
    mod = 1<<size
    y = y % size
    return ( (x>>y) | (x<<(size-y)) ) % mod

def rol(x, y, size=32):
    mod = 1<<size
    y = y % size
    return ( (x<<y) | (x>>(size-y)) ) % mod


### Python stuff ###

def py_get_pyc_bytecode(filename):
    ff=open(filename,"rb")
    ff.seek(8,0)
    co = marshal.load(ff)
    ff.close()
    return co

def py_exec_bytecode(co, bytecode):
    code = type(compile("def f(): pass", "noname", "exec"))
    code_obj = code(co.co_argcount, co.co_nlocals, co.co_stacksize,co.co_flags, bytecode, co.co_consts, co.co_names,co.co_varnames, co.co_filename, co.co_name,co.co_firstlineno, co.co_lnotab, co.co_freevars,co.co_cellvars)
    exec(code_obj)
