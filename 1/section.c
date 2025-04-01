#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BYTE 1
#define WORD 2
#define DWORD 4
#define BYTEL 2
#define WORDL 3
#define DWORDL 5

FILE *f;

int end(int status) {
	fclose(f);
	printf("\n");
	exit(status);
}

void debug (unsigned char *array) {
	for (int i = 0; i<DWORD; i++){
		printf("%02x\n",array[i]);
	}
}

//char *getaddr(unsigned char *input, int size, int offset) {
//	fseek(f,offset,SEEK_SET);
//	fread(input,1,DWORD,f);
//	char *str = malloc(size+1);
//	sprintf(str, "%x", * (uint32_t *) input);
//	return str;
//}

int main(int argc, char* argv[]) {
	// argv[1] = Path to executable
	f = fopen(argv[1],"rb");
	
	unsigned char magic[WORDL];
	fread(magic,1,WORD,f);
	if (strcmp(magic,"MZ") != 0) {
		printf("Input error. File is not a PE executable.");
		end(1);
	}
	
//	unsigned char lfanew[DWORDL];
//	lfanew_str = getaddr(lfanew, DWORDL, 0x3C);
	fseek(f, 0x3C, SEEK_SET);
	fread(lfanew,1,DWORD,f);
	char lfanew_str[DWORDL];
	sprintf(lfanew_str, "%x", * (uint32_t *) lfanew);
	

	
	char sig[DWORD];
//	fseek()
	
	
	end(1);
}
