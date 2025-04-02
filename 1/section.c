#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BYTE 1
#define WORD 2
#define DWORD 4
#define BYTEL 2
#define WORDL 3
#define DWORDL 5

typedef unsigned char uchar;

FILE *f;

int end(int status) {
	// To close the file stream before terminating the programme
	fclose(f);
	printf("\n");
	exit(status);
}

void debug (uchar *array, int size) {
	for (int i = 0; i<size; i++){
		printf("%02x ",array[i]);
	}
	printf("\n");
}

unsigned int getaddr(int size, int offset) {
	uchar input[size];
	fseek(f,offset,SEEK_SET);
	fread(input,1,DWORD,f);
	debug(input, size);
	
	// Convert from hex array to int
	unsigned int var = 0;
	for(int i=0;i<size;i++) {
		var = var | input[i]<<(i*8);
	}
	return var;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Missing argument.\n");
		printf("Usage: ./section path/to/PE/executable (Linux)\n");
		printf("       section path\\to\\PE\\executable (Windows)\n");
		exit(1);
	}

	// argv[1] = Path to executable
	f = fopen(argv[1],"rb");
	
	// Verify magic byte
	uchar magic[WORDL];
	fread(magic,1,WORD,f);
	if (strcmp(magic,"MZ") != 0) {
		printf("Input error. File is not a PE executable.");
		end(1);
	}
	
	unsigned int lfanew = getaddr(DWORD, 0x3C);
	
	end(0);
}
