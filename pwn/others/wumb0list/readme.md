# information
Actually, as far as im concerned, this is a reverse challenge. Its hard to reverse all these fucking structures.
There are actually three kinds of structures: link, item, quantity
```
00000000 item            struc ; (sizeof=0x20, align=0x8, mappedto_6)
00000000 next            dq ?                    ; offset
00000008 pre             dq ?                    ; offset
00000010 name            dq ?                    ; offset
00000018 id              dq ?
00000020 item            ends
00000020
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 list            struc ; (sizeof=0x10, align=0x8, mappedto_7)
00000000 name            dq ?                    ; offset
00000008 link            dq ?                    ; offset
00000010 list            ends
00000010
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 quantity        struc ; (sizeof=0x18, mappedto_8)
00000000 next            dq ?
00000008 item            dq ?                    ; offset
00000010 quantity        dq ?
00000018 quantity        ends
```
# bug
There is an OOB bug in the *list management* operations. List array has only 10 elements, but we can access the index 10. This is a 100% OOB bug.
```C
    case '4':
          output_0((__int64 *)list, 0xAuLL);
          numa = read_int("Enter list number: ");
          if ( numa <= 0xA )
            view_list((list *)&list[2 * numa]);
          break;
```
And the funny things is that the list array is on the stack, below is the variable *filename*. We can control it by setting filename.
```C
  void *list[20]; // [rsp+50h] [rbp-4B0h]
  char filename[1032]; // [rsp+F0h] [rbp-410h]
  unsigned __int64 canary; // [rsp+4F8h] [rbp-8h]
```
# leak
By setting the filename to a got addr, we can get the leak. Since the PIE is not enabled. The only thing to remember is that the link parameter should be NULL.
```
    if ( link )
    {
      LODWORD(a1) = printf("List %s\n-----------------\n", a1->name);
      while ( link )
      {
        printf("%lu: %s * %lu\n", link->item->id, link->item->name, link->quantity);
        a1 = (list *)link->next;
        link = (quantity *)link->next;
      }
    }
    else
```
# exploit
To exploit this chall, we can just overwrite the GOT with *set_quantity* function.
Need to make the idx parameter equal to the `i->item-id`.
```
item *__fastcall edit_quantity(list *a1, __int64 quantity, _QWORD *idx)
{
  item *id; // rax
  quantity *i; // [rsp+20h] [rbp-8h]

  id = a1->link;
  for ( i = (quantity *)a1->link; i; i = (quantity *)i->next )
  {
    id = (item *)i->item->id;
    if ( idx == (_QWORD *)id )
      break;
    id = (item *)i->next;
  }
  if ( i )
  {
    id = (item *)i;
    i->quantity = quantity;
  }
  return id;
}
```
