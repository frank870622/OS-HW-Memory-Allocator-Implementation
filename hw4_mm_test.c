#include "lib/hw_malloc.h"
#include "hw4_mm_test.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[])
{
    while(1) {
        fflush(stdin);
        char input[100];
        scanf("%s", input);
        //printf("get input:%s\n", input);
        if(strcmp(input, "alloc") == 0) {
            int bytes = 0;
            scanf("%d", &bytes);
            //printf("get input:%d\n", bytes);
            if(bytes > 32768) {
                hw_malloc(bytes);
            } else {
                printf("0x%012x\n", hw_malloc(bytes));
            }
        } else if(strcmp(input, "free") == 0) {
            long long int address;
            scanf("%llx", &address);
            //printf("get input: 0x%llx\n", address);
            hw_free(&address);
            /*
            int trash;
            int address = 0;
            scanf("%dx%d", &trash, &address);
            printf("get input: 0x%d\n", address);
            hw_free(&address);
            */
        } else if(strcmp(input, "print") == 0) {
            char input_str[30];
            scanf("%s", input_str);
            //printf("input_str： %s\n", input_str);
            if(strcmp(input_str, "mmap_alloc_list") == 0) {
                print_mmap();
            } else {
                char address_str[30];
                char trash[30];
                sscanf(input_str, "%[^0-9]%[0-9]", trash, address_str);
                int address = 0;
                sscanf(address_str, "%d", &address);
                //printf("address: %d\n", address);
                print_bin(address);
            }

        }

    }
    return 0;
}
