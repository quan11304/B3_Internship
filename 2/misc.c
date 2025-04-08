#include <stdio.h>
#include <stdlib.h>
#include <winnt.h>

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

ULONGLONG hextoint(BYTE *input, int size) {
    // Convert from hex array to int
    ULONGLONG var = 0;
    for (int i = 0; i < size; i++) {
        ULONGLONG temp = input[i];
        var = var | temp << (i * 8);
    }
    return var;
}

ULONGLONG getval(FILE *stream, int length, int whence, int offset) {
    BYTE input[length];
    fseek(stream, offset, whence);
    fread(input, 1, length, stream);
    hextoint(input, length);
    // No return but this still works?
}

void setval_char(FILE *stream, char *data, int length) {
    fwrite(data, 1, length, stream);
}

void setval_int(FILE *stream, int data, int length) {
    BYTE input[length];
    sprintf(input, "%llx", data);
    fwrite(data, 1, length, stream);
}