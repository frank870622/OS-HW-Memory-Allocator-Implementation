#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/mman.h>
#include "hw_malloc.h"

typedef struct chunk_header* chunk_ptr_t;
typedef struct chunk_size_and_flag chunk_info_t;

struct chunk_size_and_flag {
    int prev_chunk_size:31;
    int current_chunk_size:31;
    unsigned int allocated_flag:1;
    unsigned int mmap_flag:1;
} __attribute__((packed));

struct chunk_header {
    chunk_ptr_t prev;
    chunk_ptr_t next;
    chunk_info_t size_and_flag;
} __attribute__((packed));

// initial bin, start, end
struct chunk_header bin[11];
chunk_ptr_t start_brk = NULL;
chunk_ptr_t end_brk = NULL;
// mmap
struct chunk_header mmap_head;
chunk_ptr_t mmap_head_ptr = NULL;
//


//detele chunk from bin
void delete_bin(chunk_ptr_t chunk)
{
    //printf("delete pos:0x%012llx\n", (long long int)chunk);
    chunk -> prev -> next = chunk -> next;
    chunk -> next -> prev = chunk -> prev;
    chunk -> next = chunk;
    chunk -> prev = chunk;
    chunk -> size_and_flag.prev_chunk_size = chunk -> size_and_flag.current_chunk_size;
    return;
}

void add_bin(chunk_ptr_t chunk)
{
    int bin_num;
    if(chunk->size_and_flag.current_chunk_size == 32) {
        bin_num = 0;
    } else if(chunk->size_and_flag.current_chunk_size == 64) {
        bin_num = 1;
    } else if(chunk->size_and_flag.current_chunk_size == 128) {
        bin_num = 2;
    } else if(chunk->size_and_flag.current_chunk_size == 256) {
        bin_num = 3;
    } else if(chunk->size_and_flag.current_chunk_size == 512) {
        bin_num = 4;
    } else if(chunk->size_and_flag.current_chunk_size == 1024) {
        bin_num = 5;
    } else if(chunk->size_and_flag.current_chunk_size == 2048) {
        bin_num = 6;
    } else if(chunk->size_and_flag.current_chunk_size == 4096) {
        bin_num = 7;
    } else if(chunk->size_and_flag.current_chunk_size == 8192) {
        bin_num = 8;
    } else if(chunk->size_and_flag.current_chunk_size == 16384) {
        bin_num = 9;
    } else if(chunk->size_and_flag.current_chunk_size == 32768) {
        bin_num = 10;
    } else {
        printf("out of size(%d) in add_bin()\n", chunk->size_and_flag.current_chunk_size);
        exit(1);
    }

    //regular with memory address
    chunk_ptr_t the_next_chunk = &bin[bin_num];
    while(the_next_chunk -> prev != &bin[bin_num] && the_next_chunk -> prev > chunk) {
        the_next_chunk = the_next_chunk -> prev;
    }
    //connect bin
    the_next_chunk -> prev -> next = chunk;
    chunk -> prev = the_next_chunk -> prev;
    chunk -> next = the_next_chunk;
    the_next_chunk -> prev = chunk;
    //set pre size
    chunk -> size_and_flag.prev_chunk_size = chunk -> prev -> size_and_flag.current_chunk_size;
    the_next_chunk -> size_and_flag.prev_chunk_size = chunk -> size_and_flag.current_chunk_size;
    //reset chunk paremeter
    chunk -> size_and_flag.allocated_flag = 0;
    chunk -> size_and_flag.mmap_flag = 0;

    //printf("add chunk pos : 0x%012llx ,  size: %d\n", (long long int)chunk, chunk -> size_and_flag.current_chunk_size);

    //printf("bin[bin_num].next position: %d\n", bin[bin_num].next);
    //printf("bin[bin_num].prev position: %d\n", bin[bin_num].prev);

    return;
}

void *hw_malloc(size_t bytes)
{
    //printf("size of struct chunk_header: %ld\n", sizeof(struct chunk_header));
    //printf("into hw_malloc user bytes:%ld\n", bytes);

    //mmap
    if(bytes > 32768) {
        chunk_ptr_t malloc_chunk = NULL;

        //if first time of mmap
        if(mmap_head_ptr == NULL) {
            //printf("first to mmap\n");
            mmap_head.next = &mmap_head;
            mmap_head.prev = &mmap_head;
            mmap_head.size_and_flag.current_chunk_size = 0;
            mmap_head.size_and_flag.prev_chunk_size = 0;
            mmap_head.size_and_flag.allocated_flag = 0;
            mmap_head.size_and_flag.mmap_flag = 0;
            mmap_head_ptr = &mmap_head;
        }

        //use mmap to get memory
        malloc_chunk = (chunk_ptr_t)mmap(NULL, bytes + sizeof(struct chunk_header), PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
        //printf("malloc_chunk pos: %p size:%ld\n", malloc_chunk + sizeof(struct chunk_header), bytes);


        //regular with address and size
        chunk_ptr_t the_next_chunk = &mmap_head;
        while(the_next_chunk -> prev != &mmap_head && the_next_chunk -> prev -> size_and_flag.current_chunk_size > (int)bytes) {
            the_next_chunk = the_next_chunk -> prev;
        }

        //printf("connect mmap list\n");
        //printf("sizeof(malloc_chunk):%d\n", sizeof(malloc_chunk));
        //printf("sizeof(the_next_chunk -> prev):%d\n", sizeof(the_next_chunk -> prev));
        //printf("the_next_chunk -> next: %d\n", the_next_chunk -> next);
        //printf("the_next_chunk -> prev: %d\n", the_next_chunk -> prev);
        //printf("the_next_chunk -> prev -> next: %d\n", the_next_chunk -> prev -> next);

        //connect link list
        //printf("connect link list\n");
        the_next_chunk -> prev -> next = malloc_chunk;
        malloc_chunk -> prev = the_next_chunk -> prev;
        malloc_chunk -> next = the_next_chunk;
        the_next_chunk -> prev = malloc_chunk;
        //set mmap chunk paremeter
        //printf("set mmap chunk paremeter\n");
        malloc_chunk -> size_and_flag.allocated_flag = 0;
        malloc_chunk -> size_and_flag.mmap_flag = 1;
        //set size
        //printf("set size\n");
        malloc_chunk -> size_and_flag.current_chunk_size = bytes;
        malloc_chunk -> size_and_flag.prev_chunk_size = malloc_chunk -> prev -> size_and_flag.current_chunk_size;
        the_next_chunk -> size_and_flag.prev_chunk_size = malloc_chunk -> size_and_flag.current_chunk_size;
        //printf("0x%012llx\n", mmap_head.next);
        printf("0x%012llx\n", (long long int)malloc_chunk + (long long int)sizeof(struct chunk_header));
        return malloc_chunk;
    }
    //brk
    else {
        // initial pointer
        chunk_ptr_t malloc_chunk = NULL;

        //size of bytes
        int size = bytes + sizeof(struct chunk_header);
        if(size == 0)
            return NULL;
        else if(size <= 32)
            size = 32;
        else if(size <= 64)
            size = 64;
        else if(size <= 128)
            size = 128;
        else if(size <= 256)
            size = 256;
        else if(size <= 512)
            size = 512;
        else if(size <= 1024)
            size = 1024;
        else if(size <= 2048)
            size = 2048;
        else if(size <= 4096)
            size = 4096;
        else if(size <= 8192)
            size = 8192;
        else if(size <= 16384)
            size = 16384;
        else size = 32768;

        //printf("change user bytes:%ld to size: %d\n", bytes, size);

        //first time get in
        if(start_brk == NULL) {
            //for two part of sbrk memory
            chunk_ptr_t first_chunk = NULL;
            chunk_ptr_t second_chunk = NULL;

            //initail bin
            for(int i=0; i<11; ++i) {
                bin[i].prev = &bin[i];
                bin[i].next = &bin[i];
                bin[i].size_and_flag.prev_chunk_size = 0;
                bin[i].size_and_flag.current_chunk_size = 0;
                bin[i].size_and_flag.allocated_flag = 0;
                bin[i].size_and_flag.mmap_flag = 0;
            }
            bin[0].size_and_flag.current_chunk_size = 32;
            bin[1].size_and_flag.current_chunk_size = 64;
            bin[2].size_and_flag.current_chunk_size = 128;
            bin[3].size_and_flag.current_chunk_size = 256;
            bin[4].size_and_flag.current_chunk_size = 512;
            bin[5].size_and_flag.current_chunk_size = 1024;
            bin[6].size_and_flag.current_chunk_size = 2048;
            bin[7].size_and_flag.current_chunk_size = 4096;
            bin[8].size_and_flag.current_chunk_size = 8192;
            bin[9].size_and_flag.current_chunk_size = 16384;
            bin[10].size_and_flag.current_chunk_size = 32768;


            //printf("use sbrk to get memory & its start,end address\n");
            //use sbrk to get memory & its start,end address
            start_brk = sbrk(0);
            brk((char*)start_brk + 65536);
            end_brk = sbrk(0);

            //printf("start_brk:0x%012llx\nend_brk:0x%012llx\n", (long long int)start_brk, (long long int)end_brk);

            //printf("cut initail chunk to two part\n");
            //cut initail chunk to two part
            first_chunk = start_brk;
            second_chunk = (char*)start_brk + 32768;
            //second_chunk = shift(start_brk, 32768);
            first_chunk -> size_and_flag.current_chunk_size = 32768;
            second_chunk -> size_and_flag.current_chunk_size = 32768;

            //printf("first_chunk: 0x%012llx\n", (long long int)start_brk);
            //printf("second_chunk: 0x%012llx\n", (long long int)second_chunk);

            //printf("add chunk to bin[10](first time)\n");
            //add chunk to bin[10]
            add_bin(first_chunk);
            add_bin(second_chunk);
        }

        //check whether bins have the size which users want
        for(int i=0; i<11; ++i) {
            if(
                (i == 0 && size == 32) ||
                (i == 1 && size == 64) ||
                (i == 2 && size == 128) ||
                (i == 3 && size == 256) ||
                (i == 4 && size == 512) ||
                (i == 5 && size == 1024) ||
                (i == 6 && size == 2048) ||
                (i == 7 && size == 4096) ||
                (i == 8 && size == 8192) ||
                (i == 9 && size == 16384) ||
                (i == 10 && size == 32768)
            ) {
                if(bin[i].next != &bin[i]) {
                    //printf("bin[%d] has user want size: %d\n", i, size);
                    malloc_chunk = bin[i].next;
                    malloc_chunk -> size_and_flag.allocated_flag = 1;
                    delete_bin(malloc_chunk);

                    return (char*)malloc_chunk + sizeof(struct chunk_header) - (char*)start_brk;
                }
            }
        }

        //bins don't have the size which users want
        //maybe you need to split
        int bin_num = -1;
        if(size == 32) {
            bin_num = 0;
        } else if(size == 64) {
            bin_num = 1;
        } else if(size == 128) {
            bin_num = 2;
        } else if(size == 256) {
            bin_num = 3;
        } else if(size == 512) {
            bin_num = 4;
        } else if(size == 1024) {
            bin_num = 5;
        } else if(size == 2048) {
            bin_num = 6;
        } else if(size == 4096) {
            bin_num = 7;
        } else if(size == 8192) {
            bin_num = 8;
        } else if(size == 16384) {
            bin_num = 9;
        } else if(size == 32768) {
            bin_num = 10;
        } else {
            printf("out of size(%d) in add_bin()\n", size);
            exit(1);
        }

        for(int i = bin_num; i < 11; ++i) {
            if(bin[i].next != &bin[i]) {
                if(bin[i].next -> size_and_flag.current_chunk_size == size) {
                    //find the size user want
                    //printf("bin[%d] has user want size: %d\n", i, size);
                    malloc_chunk = bin[i].next;
                    malloc_chunk -> size_and_flag.allocated_flag = 1;
                    delete_bin(malloc_chunk);
                    return (char*)malloc_chunk + sizeof(struct chunk_header) - (char*)start_brk;
                } else if(i != 0) {
                    //split memory
                    //printf("split memory from bin[%d] to bin[%d]\n", i, i-1);

                    chunk_ptr_t split_chunk_1 = NULL;
                    chunk_ptr_t split_chunk_2 = NULL;

                    split_chunk_1 = bin[i].next;
                    delete_bin(split_chunk_1);

                    split_chunk_2 = (char*)split_chunk_1 + (split_chunk_1 -> size_and_flag.current_chunk_size)/2;
                    split_chunk_1 -> size_and_flag.current_chunk_size = split_chunk_1 -> size_and_flag.current_chunk_size / 2;
                    split_chunk_2 -> size_and_flag.current_chunk_size = split_chunk_1 -> size_and_flag.current_chunk_size;

                    add_bin(split_chunk_1);
                    add_bin(split_chunk_2);

                    i -= 2;
                    if(i < 0)   i = -1;
                }
            }
        }

    }

    printf("can't alloc memory\n");
    exit(1);

    return NULL;
}

int hw_free(void *mem)
{
    //free memeory
    long long int address = *(long long int*)mem;
    //printf("input mem %012llx\n", address);
    if(address > 65535) {
        //free mmap memrory
        chunk_ptr_t free_chunk = (long long int)address;
        //printf("free mmap mem 0x%012llx\n", (long long int)free_chunk);
        //printf("free_chunk -> size %d\n", free_chunk -> size_and_flag.current_chunk_size);
        //printf("free_chunk -> mmap_flag %d\n", free_chunk -> size_and_flag.mmap_flag);
        if(free_chunk -> size_and_flag.current_chunk_size != 0 && free_chunk -> size_and_flag.mmap_flag == 1) {
            //printf("free mmap mem 0x%012llx, size:%d\n", (long long int)free_chunk, free_chunk -> size_and_flag.current_chunk_size);
            //remove from mmap list
            free_chunk -> prev -> next = free_chunk -> next;
            free_chunk -> next -> prev = free_chunk -> prev;
            free_chunk -> next -> size_and_flag.prev_chunk_size = free_chunk -> prev -> size_and_flag.current_chunk_size;
            free_chunk -> next = free_chunk;
            free_chunk -> prev = free_chunk;
            free_chunk -> size_and_flag.prev_chunk_size = free_chunk -> size_and_flag.current_chunk_size;
            //remove by munmap
            free_chunk -> next = free_chunk;
            free_chunk -> prev = free_chunk;
            free_chunk -> size_and_flag.allocated_flag = 0;
            free_chunk -> size_and_flag.mmap_flag = 0;
            free_chunk -> size_and_flag.prev_chunk_size = 0;

            munmap(free_chunk, free_chunk -> size_and_flag.current_chunk_size);
            printf("success\n");
        } else {
            printf("mmap address not exist\n");
            printf("fail\n");
        }
        return 0;
    } else {
        chunk_ptr_t free_chunk = (char*)start_brk + address - sizeof(struct chunk_header);

        //printf("start_brk: %d\n", start_brk);
        //printf("address: %d\n", address);
        //printf("free brk mem: 0x%12llx, size:%d\n", (long long int)free_chunk, free_chunk -> size_and_flag.current_chunk_size);

        if(
            free_chunk -> size_and_flag.current_chunk_size != 32 &&
            free_chunk -> size_and_flag.current_chunk_size != 64 &&
            free_chunk -> size_and_flag.current_chunk_size != 128 &&
            free_chunk -> size_and_flag.current_chunk_size != 256 &&
            free_chunk -> size_and_flag.current_chunk_size != 512 &&
            free_chunk -> size_and_flag.current_chunk_size != 1024 &&
            free_chunk -> size_and_flag.current_chunk_size != 2048 &&
            free_chunk -> size_and_flag.current_chunk_size != 4096 &&
            free_chunk -> size_and_flag.current_chunk_size != 8192 &&
            free_chunk -> size_and_flag.current_chunk_size != 16384 &&
            free_chunk -> size_and_flag.current_chunk_size != 32768
        ) {
            printf("free pos not exist free_chunk:0x%012llx\n", (long long int)free_chunk);
            printf("fail\n");
            return 0;
        }
        add_bin(free_chunk);
        //printf("merge bin\n");

        //merge memroy
        for(int i = 0; i < 10; ++i) {
            //printf("i = %d\n", i);
            if(bin[i].next != &bin[i] && bin[i].next->next != &bin[i] && bin[i].next -> size_and_flag.current_chunk_size + bin[i].next == bin[i].next->next) {
                /*
                printf("bin:%d\n", &bin[i]);
                printf("bin.next:%d\n", bin[i].next);
                printf("bin.next->next:%d\n", bin[i].next->next);
                printf("bin.prev:%d\n", bin[i].prev);
                */
                //printf("merge 0x%012llx, 0x%012llx\n", (long long int)bin[i].next, (long long int)bin[i].next->next);

                chunk_ptr_t merge_chunk1 = bin[i].next;
                chunk_ptr_t merge_chunk2 = bin[i].next->next;


                delete_bin(merge_chunk1);
                delete_bin(merge_chunk2);

                merge_chunk1 -> size_and_flag.current_chunk_size = (merge_chunk1 -> size_and_flag.current_chunk_size) * 2;
                add_bin(merge_chunk1);
            }

        }
        printf("success\n");
    }

    return 0;
}

int test_free(void *mem)
{

    return 0;
}

void print_bin(int bin_num)
{
    chunk_ptr_t chunk = bin[bin_num].next;
    while(chunk != &bin[bin_num]) {
        if(chunk == start_brk)
            printf("0x%012d--------%d\n", 0, chunk -> size_and_flag.current_chunk_size);
        else
            printf("0x%012llx--------%d\n", (long long int)chunk - (long long int)start_brk, chunk -> size_and_flag.current_chunk_size);

        chunk = chunk -> next;
    }
}

void print_mmap()
{
    chunk_ptr_t chunk = mmap_head.next;
    while(chunk != &mmap_head) {
        //printf("%p\n", mmap_head.next);
        //printf("0x%012llx\n", (long long int)malloc_chunk);
        printf("0x%012llx--------%ld\n", (long long int)chunk, chunk -> size_and_flag.current_chunk_size + sizeof(struct chunk_header));
        chunk = chunk -> next;
    }
}

void *get_start_sbrk(void)
{
    return start_brk;
}
