#include <stdio.h>

void debug(unsigned char *array, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x ", array[i]);
    }
    printf("\n");
}