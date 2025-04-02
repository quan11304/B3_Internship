#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BYTE 1		// Corresponds to char
#define WORD 2		// Corresponds to short
#define DWORD 4		// Corresponds to long
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

unsigned long getval(int size, int offset) {
	uchar input[size];
	fseek(f,offset,SEEK_SET);
	fread(input,1,DWORD,f);
	debug(input, size);
	
	// Convert from hex array to int
	unsigned long var = 0;
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
	
	unsigned long lfanew = getval(DWORD, 0x3C);
	
	unsigned short no_sections = getval(WORD, lfanew + 6);
	
	unsigned long optional = lfanew + 24;
		
	unsigned long entry = getval(DWORD, optional + 16);
	
	// 0Bh 01h => optional_magic = 267 => 32-bit
	// 0Bh 02h => optional_magic = 523 => 64-bit
	unsigned short optional_magic = getval (WORD, optional);
	
	printf("%lu %u %lu %lu %u", lfanew, no_sections, optional, entry, optional_magic);
	
	end(0);
}
