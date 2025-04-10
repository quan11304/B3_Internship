#include "main.h"

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Missing argument.\n");
		printf("Usage: section path\\to\\PE\\executable (Windows)\n");
		exit(1);
	}

	// argv[1] = Path to executable
	FILE *fr = fopen(argv[1], "r+b");
	FILE *fa = fopen(argv[1], "a+b");

	IMAGE_DOS_HEADER imageDosHeader;
	IMAGE_FILE_HEADER imageFileHeader;
	IMAGE_OPTIONAL_HEADER imageOptionalHeader;

	// Verify magic byte (0x4D 0x5A == "MZ")
	imageDosHeader.e_magic = getval(fr, dw, SEEK_SET,0);
	if (imageDosHeader.e_magic != 0x5a4d) {
		printf("Input error. File is not a PE executable.");
		end(fr, 1);
	}

	imageDosHeader.e_lfanew = getval(fr, dd, SEEK_SET, 0x3C);

	imageFileHeader.NumberOfSections =
		getval(fr, dw, SEEK_SET, imageDosHeader.e_lfanew+6);
	setval_int(fr,imageFileHeader.NumberOfSections+1,
		sizeof(imageFileHeader.NumberOfSections),
		SEEK_CUR, -sizeof(imageFileHeader.NumberOfSections));

	imageFileHeader.SizeOfOptionalHeader =
		getval(fr, dw, SEEK_SET, imageDosHeader.e_lfanew + 20);

	DWORD ioh_addr = imageDosHeader.e_lfanew + 24;

	// 0x10B => 32-bit
	// 0x20B => 64-bit
	imageOptionalHeader.Magic = getval(fr, dw, SEEK_SET, ioh_addr);

	imageOptionalHeader.AddressOfEntryPoint =
		getval(fr, dd, SEEK_SET, ioh_addr+16);
	imageOptionalHeader.ImageBase =
		getval(fr,dd, SEEK_SET, ioh_addr+28);
	imageOptionalHeader.SectionAlignment =
		getval(fr, dd, SEEK_SET, ioh_addr+32);
	imageOptionalHeader.FileAlignment =
		getval(fr, dd, SEEK_SET, ioh_addr+36);
	// TO-DO: Increase SizeOfImage
	imageOptionalHeader.SizeOfImage =
		getval(fr, dd, SEEK_SET,ioh_addr + 56);

	DWORD lastish_addr = ioh_addr + imageFileHeader.SizeOfOptionalHeader
		+ 40 * (imageFileHeader.NumberOfSections-1);

	DWORD newish_addr = lastish_addr + 40;

	// Section Header
	// Name
	setval_char(fr, ".infect",8, SEEK_SET, newish_addr);
	// VirtualSize
	setval_int(fr, 0, dd, SEEK_CUR, 0);
	// VirtualAddress
	setval_int(fr, 0, dd, SEEK_CUR, 0);
	// SizeOfRawData
	setval_int(fr, 0, dd, SEEK_CUR, 0);
	// PointerToRawData
	setval_int(fr, 0, dd, SEEK_CUR, 0);
	// PointerToRelocations
	setval_int(fr, 0, dd, SEEK_CUR, 0);
	// PointerToLinenumbers
	setval_int(fr, 0, dd, SEEK_CUR, 0);
	// NumberOfRelocations
	setval_int(fr, 0, dd, SEEK_CUR, 0);
	// NumberOfLinenumbers
	setval_int(fr, 0, dd, SEEK_CUR, 0);
	// Characteristics
	setval_int(fr, 0, dd, SEEK_CUR, 0);



	end(fr, 0);
}
