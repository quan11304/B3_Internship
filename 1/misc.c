#include <stdio.h>
#include <stdlib.h>
#include "datatypes.h"

void debug(unsigned char *array, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x ", array[i]);
    }
    printf("\n");
}

int end(FILE *stream, int status) {
    // To close the file stream before terminating the programme
    fclose(stream);
    printf("\n");
    exit(status);
}

QWORD hextoint(BYTE *input, int size) {
    // Convert from hex array to int
    QWORD var = 0;
    for (int i = 0; i < size; i++) {
        QWORD temp = input[i];
        var = var | temp << (i * 8);
    }
    return var;
}

DWORD getval(FILE *stream, int size, int offset) {
    BYTE input[size];
    fseek(stream, offset,SEEK_SET);
    fread(input, 1, dd, stream);
    hextoint(input, size);
    // No return but this still works?
}