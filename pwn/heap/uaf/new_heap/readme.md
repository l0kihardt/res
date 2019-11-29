# information
Running on Ubuntu 16.04, this is a pretty traditional heap exploit challenge.
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

