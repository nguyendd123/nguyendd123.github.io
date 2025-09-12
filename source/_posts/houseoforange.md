---
date: '2025-09-09T20:28:06+07:00'
draft: false
title: 'House of Orange Attack'
tags: ['unsortedbin', 'heap overflow', 'house_of_Orange']
---
---
## 0x1. Preparation

To use this attack, you must have libc address and be able to overflow heap, overwrite top chunk's size. And this attack just works with glibc with version <= 2.25.

## 0x2. Perform

- If you try to allocate a size exceeding the top chunk's size, it leads you 2 cases:
    - In case your desired size > 128, they will allocate you chunk on mmap region instead of heap.
    - In other case, sbrk() will grow the existing heap segment, create a new top chunk and free the current top chunk.

To do this successfully, you should shrink top chunk's size by overwriting a smaller size to it :b.

After put top chunk into unsorted bin, you can overwrite ```_IO_list_all``` to ```topchunk->bk```, because ```_IO_list_all``` is an array of addresses store ```_IO_FILE_plus``` need to be flushed after the process. 

Call malloc to assign the address of unsorted bin to ```_IO_list_all```, which is top chunk now. You can create a fake ```_IO_FILE_plus``` in the old top chunk like we did in SEE THE FILE challenge. 

The reason why we can assign the address of unsorted bin to ```_IO_list_all``` is that:

```c
for (;;){
    while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av)){
        bck = victim->bk;
        size = chunksize (victim);
        
        ...

        /* remove from unsorted list */
        unsorted_chunks (av)->bk = bck;
        bck->fd = unsorted_chunks (av);

        /* Take now instead of binning if exact fit */

        if (size == nb)
        {
            set_inuse_bit_at_offset (victim, size);
            if (av != &main_arena)
            victim->size |= NON_MAIN_ARENA;
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
        }

        /* place chunk in bin */

        if (in_smallbin_range (size))
        {
            victim_index = smallbin_index (size);
            bck = bin_at (av, victim_index);
            fwd = bck->fd;
        }
        ....
    }
}
```

```unsorted_chunks``` will return the address of unsorted bin, I guess.

- When you call malloc, they will find in fastbins first, then unsorted bin. In unsorted bin they will handle the head of linked-list:
    - If the chunk's size fits the request, they return this chunk. In other case they will put it to appropriate bins.
    - ```head->bk``` will become the head, thus ```head->bk->fd``` points to the address of unsorted bin.

Especially, they do the first thing after the second one, so the ```_IO_list_all``` would be the address of unsorted bin before the arrangement. You can change the size of the old top chunk again before malloc, thus when they put this chunk to appropriate bin, they will meet error and call ```abort -> fflush```. 

- Reference: [House of Orange](https://guyinatuxedo.github.io/43-house_of_orange/house_orange_exp/index.html)