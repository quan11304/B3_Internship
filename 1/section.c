#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define db 1		// Corresponds to char
#define dw 2		// Corresponds to short
#define dd 4		// Corresponds to long
#define dbl 2
#define dwl 3
#define ddl 5

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;

// Ref: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY;

// Ref: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER;

// Ref: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;

// Ref: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    unsigned long long   ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    unsigned long long   SizeOfStackReserve;
    unsigned long long   SizeOfStackCommit;
    unsigned long long   SizeOfHeapReserve;
    unsigned long long   SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

FILE *f;

int end(int status) {
    // To close the file stream before terminating the programme
    fclose(f);
    printf("\n");
    exit(status);
}

DWORD getval(int size, int offset) {
    BYTE input[size];
    fseek(f, offset,SEEK_SET);
    fread(input, 1,dd, f);

    // Convert from hex array to int
    DWORD var = 0;
    for (int i = 0; i < size; i++) {
        var = var | input[i] << (i * 8);
    }
    return var;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Missing argument.\n");
        printf("Usage: ./section path/to/PE/executable (Linux)\n");
        printf("       section path\\to\\PE\\executable (Windows)\n");
        exit(1);
    }

    // argv[1] = Path to executable
    f = fopen(argv[1], "rb");

    // Verify magic byte
    BYTE magic[dwl];
    fread(magic, 1,dw, f);
    if (strcmp(magic, "MZ") != 0) {
        printf("Input error. File is not a PE executable.");
        end(1);
    }

    DWORD lfanew = getval(dd, 0x3C); // PE Header addres
    WORD no_sections = getval(dw, lfanew + 6);
    WORD optional_size = getval(dw, lfanew + 20);
    DWORD optional = lfanew + 24;
    DWORD entry = getval(dd, optional + 16);
    // 0Bh 01h => optional_magic = 0x10B = 267 => 32-bit
    // 0Bh 02h => optional_magic = 0x20B = 523 => 64-bit
    WORD optional_magic = getval(dw, optional);
    DWORD sectbl1 = optional + optional_size;

    char sections[no_sections][8 + 1];
    for (int i = 0; i < no_sections; i++) {
        fseek(f, sectbl1 + 40 * i, SEEK_SET);
        fread(sections[i], 1, 8, f);
        sections[i][8] = '\0'; // Name does not have a terminating \0
        printf("%s\n", sections[i]);
    }

    end(0);
}
