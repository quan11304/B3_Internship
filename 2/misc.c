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

void setval_char(FILE *stream, char *data, int length, int whence, int offset) {
    fseek(stream, offset, whence);
    for (int i = 0, term = 0; i < length; ++i) {
        if (term != 0) {
            fwrite('\0', 1, 1, stream);
        } else if (data + i != 0) {
            fwrite(data, 1, 1, stream);
        } else {
            term = 1;
            fwrite('\0', 1, 1, stream);
        }
    }
    // Write until end of string (termination \0)
    // Insert \0 after end of string until length is reached
}

void setval_int(FILE *stream, ULONGLONG data, int length, int whence, int offset) {
    // BYTE input[length];
    // sprintf(input, "%llx", data);
    // puts(input);
    fseek(stream, offset, whence);
    fwrite(&data, 1, length, stream);
}
