# f4bctf

## Available commands

### Math / Crypto

- RC4 class:  RC4("key").crypt("blah")
- discrete_log(): outputs Pari/GP syntax

### Stego

- stego_wave_lsb(filename, little_endian=True): get lsb from a wave file

### Encoding

- base64_encode(a, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
- base64_decode(a, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

### Basic operations

- ror(x, y, size=32)
- rol(x, y, size=32)

### Python bytecode manipulation

- py_get_pyc_bytecode(filename): returns a code object from a .pyc file
- py_exec_bytecode(co, bytecode): edit the co_code of a given code object