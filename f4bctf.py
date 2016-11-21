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
        print """No help yet :)"""

if __name__ == '__main__':
    welcome()

### Math / Crypto ###

def discrete_log():
    print """Pari/GP:
? znlog(h,Mod(g,p))
"""

def discrete_log_ecdh():
    print """Sage:
sage: p=20444105256826571394...
sage: E = EllipticCurve(GF(p),[367894248...9918684797,650136343866907...])
sage: g=E(113701520505..., 72521...)
sage: v1=E(5021929082392381871...,3742011...)

sage: g.discrete_log(v1)
9518829...

sage: v2=E(5457510164662...,644200868...)

sage: g.discrete_log(v2)
3371528...

sage: 951882...*v2
(125391391... : 7297914... : 1)
sage: 3371528...*v1
(125391391... : 7297914... : 1)
sage: 
"""   

def ceil_int(a, b):
    return a/b + (a%b != 0)

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

def RSA_padding_oracle(n, e, bits, c0, oracle, verbose=True):
    B = 2**(bits-16)
    
    # Find first s1
    s1 = ceil_int(n, 3*B)
    if verbose:
        print "[*] Looking for s1..."
    while True:
        c1 = (pow(s1,e,n) * c0) % n
        if oracle(c1):
            break
        s1 += 1
    if verbose:
        print "[+] Found s1: %d" % s1

    # Find the first intervals
    M = []
    a = B*2
    b = B*3 - 1
    si = s1

    for r in range(ceil_int((a*si - B*3 + 1), n), ((b*si - B*2)/n) + 1):
        newa = max(a, ceil_int(B*2 + r*n, si))
        newb = min(b, (B*3 - 1 + r*n) / si)
        if newa <= newb:
            M.append([newa, newb])

    if verbose:
        print "[*] Found %d intervals" % len(M)

    # Now recursively reduce intervals
    while True:
        if len(M) == 1:
            m0 = M[0]
            a = m0[0]
            b = m0[1]
            print a,b
            r = ceil_int( (b*si - B*2)*2, n)
            found = False
            while not found:
                for si in range(ceil_int((B*2 + r*n), b), (B*3 - 1 + r*n)/a + 1):
                    mi = (pow(si,e,n) * c0) % n
                    if oracle(mi):
                        found = True
                        break
                if not found:
                    r += 1
            if verbose:
                print "[+] Si: %d" % si
        elif len(M) > 1:
            si += 1
            while True:
                mi = (pow(si,e,n) * c0) % n
                if oracle(mi):
                    break
                si += 1
            if verbose:
                print "[+] Si: %d" % si

        M2 = []
        for (a,b) in M:
            for r in range(ceil_int((a*si - B*3 + 1), n), (b*si - B*2)/n + 1):
                newa = max(a, ceil_int(B*2 + r*n, si))
                newb = min(b, (B*3 - 1 + r*n) / si)
                if newa <= newb:
                    M2.append([newa, newb])
        
        if len(M2) > 0:
            M = M2

        if len(M) == 1:
            if M[0][0] == M[0][1]:
                if verbose:
                    print "[+] Found: %d" % M[0][0]
                return M[0][0]
        
    return -1

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


### ELF Stuff ###

def elf_hash(mystr):
    h = 5381
    for x in mystr:
        h = h*33 + ord(x)
    return h & 0xffffffff
