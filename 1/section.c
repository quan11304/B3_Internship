#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "struct.h"
#include "misc.c"

// String array to be printed out. Has no actual meaning in the programme.
char *datadir[16] = {
    "Export", "Import", "Resource", "Exception",
    "Security", "BaseReloc", "Debug", "Copyright",
    "GlobalPtr", "TLS", "Load_Config", "Bound_Import",
    "IAT", "Delay_Import", "COM_Descriptor", "Reserved"
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Missing argument.\n");
        printf("Usage: ./section path/to/PE/executable (Linux)\n");
        printf("       section path\\to\\PE\\executable (Windows)\n");
        exit(1);
    }

    // argv[1] = Path to executable
    FILE *f = fopen(argv[1], "rb");

    // Verify magic byte
    BYTE e_magic[dwl];
    fread(e_magic, 1,dw, f);
    e_magic[dw] = 0;
    if (strcmp(e_magic, "MZ") != 0) {
        printf("Input error. File is not a PE executable.");
        end(f, 1);
    }

    DWORD e_lfanew = getval(f, dd, 0x3C); // PE Header address
    fseek(f, e_lfanew, SEEK_SET);

    printf("%-30s | %-11s | %-11s\n", "Field", "Value (Int)", "Value (Hex)");

    BYTE Signature[ddl];
    fread(Signature, 1, dd, f);
    Signature[dd] = 0;
    DWORD Signature_int = hextoint(Signature, ddl);
    printf("%-30s | %-11lu | %-#11lx\n", "Signature", Signature_int, Signature_int);

    IMAGE_FILE_HEADER ifh;

    BYTE Machine[dwl];
    fread(Machine, 1, dw, f);
    Machine[dw] = 0;
    ifh.Machine = (WORD) hextoint(Machine, dwl);
    printf("%-30s | %-11u | %-#11x\n", "Machine", ifh.Machine, ifh.Machine);

    BYTE NumberOfSections[dwl];
    fread(NumberOfSections, 1, dw, f);
    NumberOfSections[dw] = 0;
    ifh.NumberOfSections = (WORD) hextoint(NumberOfSections, dwl);
    printf("%-30s | %-11u | %-#11x\n", "NumberOfSections", ifh.NumberOfSections, ifh.NumberOfSections);

    BYTE TimeDateStamp[ddl];
    fread(TimeDateStamp, 1, dd, f);
    TimeDateStamp[dd] = 0;
    ifh.TimeDateStamp = hextoint(TimeDateStamp, ddl);
    printf("%-30s | %-11lu | %-#11lx\n", "TimeDateStamp", ifh.TimeDateStamp, ifh.TimeDateStamp);

    BYTE PointerToSymbolTable[ddl];
    fread(PointerToSymbolTable, 1, dd, f);
    PointerToSymbolTable[dd] = 0;
    ifh.PointerToSymbolTable = hextoint(PointerToSymbolTable, ddl);
    printf("%-30s | %-11lu | %-#11lx\n", "PointerToSymbolTable", ifh.PointerToSymbolTable, ifh.PointerToSymbolTable);

    BYTE NumberOfSymbols[ddl];
    fread(NumberOfSymbols, 1, dd, f);
    NumberOfSymbols[dd] = 0;
    ifh.NumberOfSymbols = hextoint(NumberOfSymbols, ddl);
    printf("%-30s | %-11lu | %-#11lx\n", "NumberOfSymbols", ifh.NumberOfSymbols, ifh.NumberOfSymbols);

    BYTE SizeOfOptionalHeader[dwl];
    fread(SizeOfOptionalHeader, 1, dw, f);
    SizeOfOptionalHeader[dw] = 0;
    ifh.SizeOfOptionalHeader = (WORD) hextoint(SizeOfOptionalHeader, dwl);
    printf("%-30s | %-11u | %-#11x\n", "SizeOfOptionalHeader", ifh.SizeOfOptionalHeader, ifh.SizeOfOptionalHeader);

    BYTE Characteristics[dwl];
    fread(Characteristics, 1, dw, f);
    Characteristics[dw] = 0;
    ifh.Characteristics = (WORD) hextoint(Characteristics, dwl);
    printf("%-30s | %-11u | %-#11x\n", "Characteristics", ifh.Characteristics, ifh.Characteristics);

    // 0Bh 01h => optional_magic = 0x10B = 267 => 32-bit
    // 0Bh 02h => optional_magic = 0x20B = 523 => 64-bit
    BYTE Magic[dwl];
    fread(Magic, 1, dw, f);
    Magic[dw] = 0;
    WORD _Magic = (WORD) hextoint(Magic, dwl);

    IMAGE_SECTION_HEADER section[ifh.NumberOfSections];

    if (_Magic == 267) {
        IMAGE_OPTIONAL_HEADER32 ioh;
        ioh.Magic = _Magic;
        printf("%-30s | %-11u | %-#11x\n", "Magic", ioh.Magic, ioh.Magic);

        BYTE MajorLinkerVersion[dbl];
        fread(MajorLinkerVersion, 1, db, f);
        MajorLinkerVersion[db] = 0;
        ioh.MajorLinkerVersion = (BYTE) hextoint(MajorLinkerVersion, dbl);
        printf("%-30s | %-11u | %-#11x\n", "MajorLinkerVersion", ioh.MajorLinkerVersion, ioh.MajorLinkerVersion);

        BYTE MinorLinkerVersion[dbl];
        fread(MinorLinkerVersion, 1, db, f);
        MinorLinkerVersion[db] = 0;
        ioh.MinorLinkerVersion = (BYTE) hextoint(MinorLinkerVersion, dbl);
        printf("%-30s | %-11u | %-#11x\n", "MinorLinkerVersion", ioh.MinorLinkerVersion, ioh.MinorLinkerVersion);

        BYTE SizeOfCode[ddl];
        fread(SizeOfCode, 1, dd, f);
        SizeOfCode[dd] = 0;
        ioh.SizeOfCode = hextoint(SizeOfCode, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfCode", ioh.SizeOfCode, ioh.SizeOfCode);

        BYTE SizeOfInitializedData[ddl];
        fread(SizeOfInitializedData, 1, dd, f);
        SizeOfInitializedData[dd] = 0;
        ioh.SizeOfInitializedData = hextoint(SizeOfInitializedData, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfInitializedData", ioh.SizeOfInitializedData,
               ioh.SizeOfInitializedData);

        BYTE SizeOfUninitializedData[ddl];
        fread(SizeOfUninitializedData, 1, dd, f);
        SizeOfUninitializedData[dd] = 0;
        ioh.SizeOfUninitializedData = hextoint(SizeOfUninitializedData, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfUninitializedData", ioh.SizeOfUninitializedData,
               ioh.SizeOfUninitializedData);

        BYTE AddressOfEntryPoint[ddl];
        fread(AddressOfEntryPoint, 1, dd, f);
        AddressOfEntryPoint[dd] = 0;
        ioh.AddressOfEntryPoint = hextoint(AddressOfEntryPoint, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "AddressOfEntryPoint", ioh.AddressOfEntryPoint, ioh.AddressOfEntryPoint);

        BYTE BaseOfCode[ddl];
        fread(BaseOfCode, 1, dd, f);
        BaseOfCode[dd] = 0;
        ioh.BaseOfCode = hextoint(BaseOfCode, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "BaseOfCode", ioh.BaseOfCode, ioh.BaseOfCode);

        BYTE BaseOfData[ddl];
        fread(BaseOfData, 1, dd, f);
        BaseOfData[dd] = 0;
        ioh.BaseOfData = hextoint(BaseOfData, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "BaseOfData", ioh.BaseOfData, ioh.BaseOfData);

        BYTE ImageBase[ddl];
        fread(ImageBase, 1, dd, f);
        ImageBase[dd] = 0;
        ioh.ImageBase = hextoint(ImageBase, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "ImageBase", ioh.ImageBase, ioh.ImageBase);

        BYTE SectionAlignment[ddl];
        fread(SectionAlignment, 1, dd, f);
        SectionAlignment[dd] = 0;
        ioh.SectionAlignment = hextoint(SectionAlignment, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SectionAlignment", ioh.SectionAlignment, ioh.SectionAlignment);

        BYTE FileAlignment[ddl];
        fread(FileAlignment, 1, dd, f);
        FileAlignment[dd] = 0;
        ioh.FileAlignment = hextoint(FileAlignment, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "FileAlignment", ioh.FileAlignment, ioh.FileAlignment);

        BYTE MajorOperatingSystemVersion[dwl];
        fread(MajorOperatingSystemVersion, 1, dw, f);
        MajorOperatingSystemVersion[dw] = 0;
        ioh.MajorOperatingSystemVersion = (WORD) hextoint(MajorOperatingSystemVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MajorOperatingSystemVersion", ioh.MajorOperatingSystemVersion,
               ioh.MajorOperatingSystemVersion);

        BYTE MinorOperatingSystemVersion[dwl];
        fread(MinorOperatingSystemVersion, 1, dw, f);
        MinorOperatingSystemVersion[dw] = 0;
        ioh.MinorOperatingSystemVersion = (WORD) hextoint(MinorOperatingSystemVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MinorOperatingSystemVersion", ioh.MinorOperatingSystemVersion,
               ioh.MinorOperatingSystemVersion);

        BYTE MajorImageVersion[dwl];
        fread(MajorImageVersion, 1, dw, f);
        MajorImageVersion[dw] = 0;
        ioh.MajorImageVersion = (WORD) hextoint(MajorImageVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MajorImageVersion", ioh.MajorImageVersion, ioh.MajorImageVersion);

        BYTE MinorImageVersion[dwl];
        fread(MinorImageVersion, 1, dw, f);
        MinorImageVersion[dw] = 0;
        ioh.MinorImageVersion = (WORD) hextoint(MinorImageVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MinorImageVersion", ioh.MinorImageVersion, ioh.MinorImageVersion);

        BYTE MajorSubsystemVersion[dwl];
        fread(MajorSubsystemVersion, 1, dw, f);
        MajorSubsystemVersion[dw] = 0;
        ioh.MajorSubsystemVersion = (WORD) hextoint(MajorSubsystemVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MajorSubsystemVersion", ioh.MajorSubsystemVersion,
               ioh.MajorSubsystemVersion);

        BYTE MinorSubsystemVersion[dwl];
        fread(MinorSubsystemVersion, 1, dw, f);
        MinorSubsystemVersion[dw] = 0;
        ioh.MinorSubsystemVersion = (WORD) hextoint(MinorSubsystemVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MinorSubsystemVersion", ioh.MinorSubsystemVersion,
               ioh.MinorSubsystemVersion);

        BYTE Win32VersionValue[ddl];
        fread(Win32VersionValue, 1, dd, f);
        Win32VersionValue[dd] = 0;
        ioh.Win32VersionValue = hextoint(Win32VersionValue, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "Win32VersionValue", ioh.Win32VersionValue, ioh.Win32VersionValue);

        BYTE SizeOfImage[ddl];
        fread(SizeOfImage, 1, dd, f);
        SizeOfImage[dd] = 0;
        ioh.SizeOfImage = hextoint(SizeOfImage, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfImage", ioh.SizeOfImage, ioh.SizeOfImage);

        BYTE SizeOfHeaders[ddl];
        fread(SizeOfHeaders, 1, dd, f);
        SizeOfHeaders[dd] = 0;
        ioh.SizeOfHeaders = hextoint(SizeOfHeaders, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfHeaders", ioh.SizeOfHeaders, ioh.SizeOfHeaders);

        BYTE CheckSum[ddl];
        fread(CheckSum, 1, dd, f);
        CheckSum[dd] = 0;
        ioh.CheckSum = hextoint(CheckSum, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "CheckSum", ioh.CheckSum, ioh.CheckSum);

        BYTE Subsystem[dwl];
        fread(Subsystem, 1, dw, f);
        Subsystem[dw] = 0;
        ioh.Subsystem = (WORD) hextoint(Subsystem, dwl);
        printf("%-30s | %-11u | %-#11x\n", "Subsystem", ioh.Subsystem, ioh.Subsystem);

        BYTE DllCharacteristics[dwl];
        fread(DllCharacteristics, 1, dw, f);
        DllCharacteristics[dw] = 0;
        ioh.DllCharacteristics = (WORD) hextoint(DllCharacteristics, dwl);
        printf("%-30s | %-11u | %-#11x\n", "DllCharacteristics", ioh.DllCharacteristics, ioh.DllCharacteristics);

        BYTE SizeOfStackReserve[ddl];
        fread(SizeOfStackReserve, 1, dd, f);
        SizeOfStackReserve[dd] = 0;
        ioh.SizeOfStackReserve = hextoint(SizeOfStackReserve, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfStackReserve", ioh.SizeOfStackReserve, ioh.SizeOfStackReserve);

        BYTE SizeOfStackCommit[ddl];
        fread(SizeOfStackCommit, 1, dd, f);
        SizeOfStackCommit[dd] = 0;
        ioh.SizeOfStackCommit = hextoint(SizeOfStackCommit, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfStackCommit", ioh.SizeOfStackCommit, ioh.SizeOfStackCommit);

        BYTE SizeOfHeapReserve[ddl];
        fread(SizeOfHeapReserve, 1, dd, f);
        SizeOfHeapReserve[dd] = 0;
        ioh.SizeOfHeapReserve = hextoint(SizeOfHeapReserve, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfHeapReserve", ioh.SizeOfHeapReserve, ioh.SizeOfHeapReserve);

        BYTE SizeOfHeapCommit[ddl];
        fread(SizeOfHeapCommit, 1, dd, f);
        SizeOfHeapCommit[dd] = 0;
        ioh.SizeOfHeapCommit = hextoint(SizeOfHeapCommit, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfHeapCommit", ioh.SizeOfHeapCommit, ioh.SizeOfHeapCommit);

        BYTE LoaderFlags[ddl];
        fread(LoaderFlags, 1, dd, f);
        LoaderFlags[dd] = 0;
        ioh.LoaderFlags = hextoint(LoaderFlags, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "LoaderFlags", ioh.LoaderFlags, ioh.LoaderFlags);

        BYTE NumberOfRvaAndSizes[ddl];
        fread(NumberOfRvaAndSizes, 1, dd, f);
        NumberOfRvaAndSizes[dd] = 0;
        ioh.NumberOfRvaAndSizes = hextoint(NumberOfRvaAndSizes, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "NumberOfRvaAndSizes", ioh.NumberOfRvaAndSizes, ioh.NumberOfRvaAndSizes);

        // Data Directories
        for (int i = 0; i < 16; ++i) {
            char field[strlen(datadir[i]) + strlen(" VirtualAddress")];

            BYTE VirtualAddress[ddl];
            fread(VirtualAddress, 1, dd, f);
            VirtualAddress[dd] = 0;
            ioh.DataDirectory[i].VirtualAddress = hextoint(VirtualAddress, ddl);
            strcpy(field, datadir[i]);
            strcat(field, " VirtualAddress");
            printf("%-30s | %-11lu | %-#11lx\n", field,
                   ioh.DataDirectory[i].VirtualAddress, ioh.DataDirectory[i].VirtualAddress);

            BYTE Size[ddl];
            fread(Size, 1, dd, f);
            Size[dd] = 0;
            strcpy(field, datadir[i]);
            strcat(field, " Size");
            ioh.DataDirectory[i].Size = hextoint(Size, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", field, ioh.DataDirectory[i].Size, ioh.DataDirectory[i].Size);
        }

        for (int i = 0; i < ifh.NumberOfSections; ++i) {
            printf("\n");
            fread(section[i].Name, 1,IMAGE_SIZEOF_SHORT_NAME, f);
            section[i].Name[IMAGE_SIZEOF_SHORT_NAME] = 0;
            printf("%-30s | %-11s | %-#11llx\n", section[i].Name,
                   "", hextoint(section[i].Name, IMAGE_SIZEOF_SHORT_NAME + 1));

            // Either PhysicalAddress or VirtualSize
            BYTE PhysicalAddress[ddl];
            fread(PhysicalAddress, 1, dd, f);
            PhysicalAddress[dd] = 0;
            section[i].Misc.PhysicalAddress = hextoint(PhysicalAddress, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "PhysicalAddress/VirtualSize", section[i].Misc.PhysicalAddress,
                   section[i].Misc.PhysicalAddress);


            BYTE VirtualAddress[ddl];
            fread(VirtualAddress, 1, dd, f);
            VirtualAddress[dd] = 0;
            section[i].VirtualAddress = hextoint(VirtualAddress, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "VirtualAddress", section[i].VirtualAddress,
                   section[i].VirtualAddress);

            BYTE SizeOfRawData[ddl];
            fread(SizeOfRawData, 1, dd, f);
            SizeOfRawData[dd] = 0;
            section[i].SizeOfRawData = hextoint(SizeOfRawData, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "SizeOfRawData", section[i].SizeOfRawData, section[i].SizeOfRawData);

            BYTE PointerToRawData[ddl];
            fread(PointerToRawData, 1, dd, f);
            PointerToRawData[dd] = 0;
            section[i].PointerToRawData = hextoint(PointerToRawData, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "PointerToRawData", section[i].PointerToRawData,
                   section[i].PointerToRawData);

            BYTE PointerToRelocations[ddl];
            fread(PointerToRelocations, 1, dd, f);
            PointerToRelocations[dd] = 0;
            section[i].PointerToRelocations = hextoint(PointerToRelocations, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "PointerToRelocations", section[i].PointerToRelocations,
                   section[i].PointerToRelocations);

            BYTE PointerToLinenumbers[ddl];
            fread(PointerToLinenumbers, 1, dd, f);
            PointerToLinenumbers[dd] = 0;
            section[i].PointerToLinenumbers = hextoint(PointerToLinenumbers, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "PointerToLinenumbers", section[i].PointerToLinenumbers,
                   section[i].PointerToLinenumbers);

            BYTE NumberOfRelocations[dwl];
            fread(NumberOfRelocations, 1, dw, f);
            NumberOfRelocations[dw] = 0;
            section[i].NumberOfRelocations = (WORD) hextoint(NumberOfRelocations, dwl);
            printf("%-30s | %-11u | %-#11x\n", "NumberOfRelocations", section[i].NumberOfRelocations,
                   section[i].NumberOfRelocations);

            BYTE NumberOfLinenumbers[dwl];
            fread(NumberOfLinenumbers, 1, dw, f);
            NumberOfLinenumbers[dw] = 0;
            section[i].NumberOfLinenumbers = (WORD) hextoint(NumberOfLinenumbers, dwl);
            printf("%-30s | %-11u | %-#11x\n", "NumberOfLinenumbers", section[i].NumberOfLinenumbers,
                   section[i].NumberOfLinenumbers);

            BYTE characteristics[ddl];
            fread(characteristics, 1, dd, f);
            characteristics[dd] = 0;
            section[i].Characteristics = hextoint(characteristics, dd);
            printf("%-30s | %-11lu | %-#11lx\n", "Characteristics", section[i].Characteristics,
                   section[i].Characteristics);
        }

        // Export Table
        if (ioh.DataDirectory[0].VirtualAddress != 0) {
            fseek(f, ioh.DataDirectory[0].VirtualAddress, SEEK_SET);
            IMAGE_EXPORT_DIRECTORY export;
            printf("\n");
            printf("Export table: \n");

            BYTE Characteristics2[ddl];
            fread(Characteristics2, 1, dd, f);
            Characteristics2[dd] = 0;
            export.Characteristics = hextoint(Characteristics2, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "Characteristics", export.Characteristics, export.Characteristics);

            BYTE TimeDateStamp2[ddl];
            fread(TimeDateStamp2, 1, dd, f);
            TimeDateStamp2[dd] = 0;
            export.TimeDateStamp = hextoint(TimeDateStamp2, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "TimeDateStamp", export.TimeDateStamp, export.TimeDateStamp);

            BYTE MajorVersion[dwl];
            fread(MajorVersion, 1, dw, f);
            MajorVersion[dw] = 0;
            export.MajorVersion = (WORD) hextoint(MajorVersion, dwl);
            printf("%-30s | %-11u | %-#11x\n", "MajorVersion", export.MajorVersion, export.MajorVersion);

            BYTE MinorVersion[dwl];
            fread(MinorVersion, 1, dw, f);
            MinorVersion[dw] = 0;
            export.MinorVersion = (WORD) hextoint(MinorVersion, dwl);
            printf("%-30s | %-11u | %-#11x\n", "MinorVersion", export.MinorVersion, export.MinorVersion);

            BYTE nName[ddl];
            fread(nName, 1, dd, f);
            nName[dd] = 0;
            export.nName = hextoint(nName, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "nName", export.nName, export.nName);

            BYTE nBase[ddl];
            fread(nBase, 1, dd, f);
            nBase[dd] = 0;
            export.nBase = hextoint(nBase, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "nBase", export.nBase, export.nBase);

            BYTE NumberOfFunctions[ddl];
            fread(NumberOfFunctions, 1, dd, f);
            NumberOfFunctions[dd] = 0;
            export.NumberOfFunctions = hextoint(NumberOfFunctions, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "NumberOfFunctions", export.NumberOfFunctions,
                   export.NumberOfFunctions);

            BYTE NumberOfNames[ddl];
            fread(NumberOfNames, 1, dd, f);
            NumberOfNames[dd] = 0;
            export.NumberOfNames = hextoint(NumberOfNames, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "NumberOfNames", export.NumberOfNames, export.NumberOfNames);

            BYTE AddressOfFunctions[ddl];
            fread(AddressOfFunctions, 1, dd, f);
            AddressOfFunctions[dd] = 0;
            export.AddressOfFunctions = hextoint(AddressOfFunctions, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "AddressOfFunctions", export.AddressOfFunctions,
                   export.AddressOfFunctions);


            BYTE AddressOfNames[ddl];
            fread(AddressOfNames, 1, dd, f);
            AddressOfNames[dd] = 0;
            export.AddressOfNames = hextoint(AddressOfNames, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "AddressOfNames", export.AddressOfNames, export.AddressOfNames);

            BYTE AddressOfNameOrdinals[ddl];
            fread(AddressOfNameOrdinals, 1, dd, f);
            AddressOfNameOrdinals[dd] = 0;
            export.AddressOfNameOrdinals = hextoint(AddressOfNameOrdinals, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "AddressOfNameOrdinals", export.AddressOfNameOrdinals,
                   export.AddressOfNameOrdinals);
        }

        // Import table
        if (ioh.DataDirectory[1].VirtualAddress != 0) {
            fseek(f, ioh.DataDirectory[1].VirtualAddress, SEEK_SET);
            IMAGE_IMPORT_DIRECTORY import;
            printf("\n");
            printf("Import table:\n");

            BYTE Characteristics2[ddl];
            fread(Characteristics2, 1, dd, f);
            Characteristics2[dd] = 0;
            import.Misc.Characteristics = hextoint(Characteristics2, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "Characteristics/OG1stThunk", import.Misc.Characteristics,
                   import.Misc.Characteristics);

            BYTE TimeDateStamp2[ddl];
            fread(TimeDateStamp2, 1, dd, f);
            TimeDateStamp2[dd] = 0;
            import.TimeDateStamp = hextoint(TimeDateStamp2, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "TimeDateStamp", import.TimeDateStamp, import.TimeDateStamp);

            BYTE ForwarderChain[ddl];
            fread(ForwarderChain, 1, dd, f);
            ForwarderChain[dd] = 0;
            import.ForwarderChain = hextoint(ForwarderChain, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "ForwarderChain", import.ForwarderChain, import.ForwarderChain);

            BYTE Name1[ddl];
            fread(Name1, 1, dd, f);
            Name1[dd] = 0;
            import.Name1 = hextoint(Name1, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "Name1", import.Name1, import.Name1);

            BYTE FirstThunk[ddl];
            fread(FirstThunk, 1, dd, f);
            FirstThunk[dd] = 0;
            import.FirstThunk = hextoint(FirstThunk, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "FirstThunk", import.FirstThunk, import.FirstThunk);
        }
    } else if (_Magic == 523) {
        IMAGE_OPTIONAL_HEADER64 ioh;
        ioh.Magic = _Magic;
        printf("%-30s | %-11u | %-#11x\n", "Magic", ioh.Magic, ioh.Magic);

        BYTE MajorLinkerVersion[dbl];
        fread(MajorLinkerVersion, 1, db, f);
        MajorLinkerVersion[db] = 0;
        ioh.MajorLinkerVersion = (BYTE) hextoint(MajorLinkerVersion, dbl);
        printf("%-30s | %-11u | %-#11x\n", "MajorLinkerVersion", ioh.MajorLinkerVersion, ioh.MajorLinkerVersion);

        BYTE MinorLinkerVersion[dbl];
        fread(MinorLinkerVersion, 1, db, f);
        MinorLinkerVersion[db] = 0;
        ioh.MinorLinkerVersion = (BYTE) hextoint(MinorLinkerVersion, dbl);
        printf("%-30s | %-11u | %-#11x\n", "MinorLinkerVersion", ioh.MinorLinkerVersion, ioh.MinorLinkerVersion);

        BYTE SizeOfCode[ddl];
        fread(SizeOfCode, 1, dd, f);
        SizeOfCode[dd] = 0;
        ioh.SizeOfCode = hextoint(SizeOfCode, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfCode", ioh.SizeOfCode, ioh.SizeOfCode);

        BYTE SizeOfInitializedData[ddl];
        fread(SizeOfInitializedData, 1, dd, f);
        SizeOfInitializedData[dd] = 0;
        ioh.SizeOfInitializedData = hextoint(SizeOfInitializedData, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfInitializedData", ioh.SizeOfInitializedData,
               ioh.SizeOfInitializedData);

        BYTE SizeOfUninitializedData[ddl];
        fread(SizeOfUninitializedData, 1, dd, f);
        SizeOfUninitializedData[dd] = 0;
        ioh.SizeOfUninitializedData = hextoint(SizeOfUninitializedData, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfUninitializedData", ioh.SizeOfUninitializedData,
               ioh.SizeOfUninitializedData);

        BYTE AddressOfEntryPoint[ddl];
        fread(AddressOfEntryPoint, 1, dd, f);
        AddressOfEntryPoint[dd] = 0;
        ioh.AddressOfEntryPoint = hextoint(AddressOfEntryPoint, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "AddressOfEntryPoint", ioh.AddressOfEntryPoint, ioh.AddressOfEntryPoint);

        BYTE BaseOfCode[ddl];
        fread(BaseOfCode, 1, dd, f);
        BaseOfCode[dd] = 0;
        ioh.BaseOfCode = hextoint(BaseOfCode, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "BaseOfCode", ioh.BaseOfCode, ioh.BaseOfCode);

        BYTE ImageBase[8 + 1];
        fread(ImageBase, 1, 8, f);
        ImageBase[8] = 0;
        ioh.ImageBase = hextoint(ImageBase, 8 + 1);
        printf("%-30s | %-11llu | %-#11llx\n", "ImageBase", ioh.ImageBase, ioh.ImageBase);

        BYTE SectionAlignment[ddl];
        fread(SectionAlignment, 1, dd, f);
        SectionAlignment[dd] = 0;
        ioh.SectionAlignment = hextoint(SectionAlignment, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SectionAlignment", ioh.SectionAlignment, ioh.SectionAlignment);

        BYTE FileAlignment[ddl];
        fread(FileAlignment, 1, dd, f);
        FileAlignment[dd] = 0;
        ioh.FileAlignment = hextoint(FileAlignment, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "FileAlignment", ioh.FileAlignment, ioh.FileAlignment);

        BYTE MajorOperatingSystemVersion[dwl];
        fread(MajorOperatingSystemVersion, 1, dw, f);
        MajorOperatingSystemVersion[dw] = 0;
        ioh.MajorOperatingSystemVersion = (WORD) hextoint(MajorOperatingSystemVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MajorOperatingSystemVersion", ioh.MajorOperatingSystemVersion,
               ioh.MajorOperatingSystemVersion);

        BYTE MinorOperatingSystemVersion[dwl];
        fread(MinorOperatingSystemVersion, 1, dw, f);
        MinorOperatingSystemVersion[dw] = 0;
        ioh.MinorOperatingSystemVersion = (WORD) hextoint(MinorOperatingSystemVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MinorOperatingSystemVersion", ioh.MinorOperatingSystemVersion,
               ioh.MinorOperatingSystemVersion);

        BYTE MajorImageVersion[dwl];
        fread(MajorImageVersion, 1, dw, f);
        MajorImageVersion[dw] = 0;
        ioh.MajorImageVersion = (WORD) hextoint(MajorImageVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MajorImageVersion", ioh.MajorImageVersion, ioh.MajorImageVersion);

        BYTE MinorImageVersion[dwl];
        fread(MinorImageVersion, 1, dw, f);
        MinorImageVersion[dw] = 0;
        ioh.MinorImageVersion = (WORD) hextoint(MinorImageVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MinorImageVersion", ioh.MinorImageVersion, ioh.MinorImageVersion);

        BYTE MajorSubsystemVersion[dwl];
        fread(MajorSubsystemVersion, 1, dw, f);
        MajorSubsystemVersion[dw] = 0;
        ioh.MajorSubsystemVersion = (WORD) hextoint(MajorSubsystemVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MajorSubsystemVersion", ioh.MajorSubsystemVersion,
               ioh.MajorSubsystemVersion);

        BYTE MinorSubsystemVersion[dwl];
        fread(MinorSubsystemVersion, 1, dw, f);
        MinorSubsystemVersion[dw] = 0;
        ioh.MinorSubsystemVersion = (WORD) hextoint(MinorSubsystemVersion, dwl);
        printf("%-30s | %-11u | %-#11x\n", "MinorSubsystemVersion", ioh.MinorSubsystemVersion,
               ioh.MinorSubsystemVersion);

        BYTE Win32VersionValue[ddl];
        fread(Win32VersionValue, 1, dd, f);
        Win32VersionValue[dd] = 0;
        ioh.Win32VersionValue = hextoint(Win32VersionValue, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "Win32VersionValue", ioh.Win32VersionValue, ioh.Win32VersionValue);

        BYTE SizeOfImage[ddl];
        fread(SizeOfImage, 1, dd, f);
        SizeOfImage[dd] = 0;
        ioh.SizeOfImage = hextoint(SizeOfImage, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfImage", ioh.SizeOfImage, ioh.SizeOfImage);

        BYTE SizeOfHeaders[ddl];
        fread(SizeOfHeaders, 1, dd, f);
        SizeOfHeaders[dd] = 0;
        ioh.SizeOfHeaders = hextoint(SizeOfHeaders, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "SizeOfHeaders", ioh.SizeOfHeaders, ioh.SizeOfHeaders);

        BYTE CheckSum[ddl];
        fread(CheckSum, 1, dd, f);
        CheckSum[dd] = 0;
        ioh.CheckSum = hextoint(CheckSum, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "CheckSum", ioh.CheckSum, ioh.CheckSum);

        BYTE Subsystem[dwl];
        fread(Subsystem, 1, dw, f);
        Subsystem[dw] = 0;
        ioh.Subsystem = (WORD) hextoint(Subsystem, dwl);
        printf("%-30s | %-11u | %-#11x\n", "Subsystem", ioh.Subsystem, ioh.Subsystem);

        BYTE DllCharacteristics[dwl];
        fread(DllCharacteristics, 1, dw, f);
        DllCharacteristics[dw] = 0;
        ioh.DllCharacteristics = (WORD) hextoint(DllCharacteristics, dwl);
        printf("%-30s | %-11u | %-#11x\n", "DllCharacteristics", ioh.DllCharacteristics, ioh.DllCharacteristics);

        BYTE SizeOfStackReserve[8 + 1];
        fread(SizeOfStackReserve, 1, 8, f);
        SizeOfStackReserve[8] = 0;
        ioh.SizeOfStackReserve = hextoint(SizeOfStackReserve, 8 + 1);
        printf("%-30s | %-11llu | %-#11llx\n", "SizeOfStackReserve", ioh.SizeOfStackReserve, ioh.SizeOfStackReserve);

        BYTE SizeOfStackCommit[8 + 1];
        fread(SizeOfStackCommit, 1, 8, f);
        SizeOfStackCommit[8] = 0;
        ioh.SizeOfStackCommit = hextoint(SizeOfStackCommit, 8 + 1);
        printf("%-30s | %-11llu | %-#11llx\n", "SizeOfStackCommit", ioh.SizeOfStackCommit, ioh.SizeOfStackCommit);

        BYTE SizeOfHeapReserve[8 + 1];
        fread(SizeOfHeapReserve, 1, 8, f);
        SizeOfHeapReserve[8] = 0;
        ioh.SizeOfHeapReserve = hextoint(SizeOfHeapReserve, 8 + 1);
        printf("%-30s | %-11llu | %-#11llx\n", "SizeOfHeapReserve", ioh.SizeOfHeapReserve, ioh.SizeOfHeapReserve);

        BYTE SizeOfHeapCommit[8 + 1];
        fread(SizeOfHeapCommit, 1, 8, f);
        SizeOfHeapCommit[8] = 0;
        ioh.SizeOfHeapCommit = hextoint(SizeOfHeapCommit, 8 + 1);
        printf("%-30s | %-11llu | %-#11llx\n", "SizeOfHeapCommit", ioh.SizeOfHeapCommit, ioh.SizeOfHeapCommit);

        BYTE LoaderFlags[ddl];
        fread(LoaderFlags, 1, dd, f);
        LoaderFlags[dd] = 0;
        ioh.LoaderFlags = hextoint(LoaderFlags, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "LoaderFlags", ioh.LoaderFlags, ioh.LoaderFlags);

        BYTE NumberOfRvaAndSizes[ddl];
        fread(NumberOfRvaAndSizes, 1, dd, f);
        NumberOfRvaAndSizes[dd] = 0;
        ioh.NumberOfRvaAndSizes = hextoint(NumberOfRvaAndSizes, ddl);
        printf("%-30s | %-11lu | %-#11lx\n", "NumberOfRvaAndSizes", ioh.NumberOfRvaAndSizes, ioh.NumberOfRvaAndSizes);

        for (int i = 0; i < 16; ++i) {
            char field[strlen(datadir[i]) + strlen(" VirtualAddress")];

            BYTE VirtualAddress[ddl];
            fread(VirtualAddress, 1, dd, f);
            VirtualAddress[dd] = 0;
            ioh.DataDirectory[i].VirtualAddress = hextoint(VirtualAddress, ddl);
            strcpy(field, datadir[i]);
            strcat(field, " VirtualAddress");
            printf("%-30s | %-11lu | %-#11lx\n", field,
                   ioh.DataDirectory[i].VirtualAddress, ioh.DataDirectory[i].VirtualAddress);

            BYTE Size[ddl];
            fread(Size, 1, dd, f);
            Size[dd] = 0;
            strcpy(field, datadir[i]);
            strcat(field, " Size");
            ioh.DataDirectory[i].Size = hextoint(Size, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", field, ioh.DataDirectory[i].Size, ioh.DataDirectory[i].Size);
        }

        for (int i = 0; i < ifh.NumberOfSections; ++i) {
            printf("\n");
            fread(section[i].Name, 1,IMAGE_SIZEOF_SHORT_NAME, f);
            section[i].Name[IMAGE_SIZEOF_SHORT_NAME] = 0;
            printf("%-30s | %-11s | %-#11llx\n", section[i].Name,
                   "", hextoint(section[i].Name, IMAGE_SIZEOF_SHORT_NAME + 1));

            // Either PhysicalAddress or VirtualSize
            BYTE PhysicalAddress[ddl];
            fread(PhysicalAddress, 1, dd, f);
            PhysicalAddress[dd] = 0;
            section[i].Misc.PhysicalAddress = hextoint(PhysicalAddress, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "PhysicalAddress/VirtualSize", section[i].Misc.PhysicalAddress,
                   section[i].Misc.PhysicalAddress);


            BYTE VirtualAddress[ddl];
            fread(VirtualAddress, 1, dd, f);
            VirtualAddress[dd] = 0;
            section[i].VirtualAddress = hextoint(VirtualAddress, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "VirtualAddress", section[i].VirtualAddress,
                   section[i].VirtualAddress);

            BYTE SizeOfRawData[ddl];
            fread(SizeOfRawData, 1, dd, f);
            SizeOfRawData[dd] = 0;
            section[i].SizeOfRawData = hextoint(SizeOfRawData, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "SizeOfRawData", section[i].SizeOfRawData, section[i].SizeOfRawData);

            BYTE PointerToRawData[ddl];
            fread(PointerToRawData, 1, dd, f);
            PointerToRawData[dd] = 0;
            section[i].PointerToRawData = hextoint(PointerToRawData, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "PointerToRawData", section[i].PointerToRawData,
                   section[i].PointerToRawData);

            BYTE PointerToRelocations[ddl];
            fread(PointerToRelocations, 1, dd, f);
            PointerToRelocations[dd] = 0;
            section[i].PointerToRelocations = hextoint(PointerToRelocations, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "PointerToRelocations", section[i].PointerToRelocations,
                   section[i].PointerToRelocations);

            BYTE PointerToLinenumbers[ddl];
            fread(PointerToLinenumbers, 1, dd, f);
            PointerToLinenumbers[dd] = 0;
            section[i].PointerToLinenumbers = hextoint(PointerToLinenumbers, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "PointerToLinenumbers", section[i].PointerToLinenumbers,
                   section[i].PointerToLinenumbers);

            BYTE NumberOfRelocations[dwl];
            fread(NumberOfRelocations, 1, dw, f);
            NumberOfRelocations[dw] = 0;
            section[i].NumberOfRelocations = (WORD) hextoint(NumberOfRelocations, dwl);
            printf("%-30s | %-11u | %-#11x\n", "NumberOfRelocations", section[i].NumberOfRelocations,
                   section[i].NumberOfRelocations);

            BYTE NumberOfLinenumbers[dwl];
            fread(NumberOfLinenumbers, 1, dw, f);
            NumberOfLinenumbers[dw] = 0;
            section[i].NumberOfLinenumbers = (WORD) hextoint(NumberOfLinenumbers, dwl);
            printf("%-30s | %-11u | %-#11x\n", "NumberOfLinenumbers", section[i].NumberOfLinenumbers,
                   section[i].NumberOfLinenumbers);

            BYTE characteristics[ddl];
            fread(characteristics, 1, dd, f);
            characteristics[dd] = 0;
            section[i].Characteristics = hextoint(characteristics, dd);
            printf("%-30s | %-11lu | %-#11lx\n", "Characteristics", section[i].Characteristics,
                   section[i].Characteristics);
        }

        // Export Table
        if (ioh.DataDirectory[0].VirtualAddress != 0) {
            fseek(f, ioh.DataDirectory[0].VirtualAddress, SEEK_SET);
            IMAGE_EXPORT_DIRECTORY export;
            printf("\n");
            printf("Export table: \n");

            BYTE Characteristics2[ddl];
            fread(Characteristics2, 1, dd, f);
            Characteristics2[dd] = 0;
            export.Characteristics = hextoint(Characteristics2, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "Characteristics", export.Characteristics, export.Characteristics);

            BYTE TimeDateStamp2[ddl];
            fread(TimeDateStamp2, 1, dd, f);
            TimeDateStamp2[dd] = 0;
            export.TimeDateStamp = hextoint(TimeDateStamp2, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "TimeDateStamp", export.TimeDateStamp, export.TimeDateStamp);

            BYTE MajorVersion[dwl];
            fread(MajorVersion, 1, dw, f);
            MajorVersion[dw] = 0;
            export.MajorVersion = (WORD) hextoint(MajorVersion, dwl);
            printf("%-30s | %-11u | %-#11x\n", "MajorVersion", export.MajorVersion, export.MajorVersion);

            BYTE MinorVersion[dwl];
            fread(MinorVersion, 1, dw, f);
            MinorVersion[dw] = 0;
            export.MinorVersion = (WORD) hextoint(MinorVersion, dwl);
            printf("%-30s | %-11u | %-#11x\n", "MinorVersion", export.MinorVersion, export.MinorVersion);

            BYTE nName[ddl];
            fread(nName, 1, dd, f);
            nName[dd] = 0;
            export.nName = hextoint(nName, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "nName", export.nName, export.nName);

            BYTE nBase[ddl];
            fread(nBase, 1, dd, f);
            nBase[dd] = 0;
            export.nBase = hextoint(nBase, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "nBase", export.nBase, export.nBase);

            BYTE NumberOfFunctions[ddl];
            fread(NumberOfFunctions, 1, dd, f);
            NumberOfFunctions[dd] = 0;
            export.NumberOfFunctions = hextoint(NumberOfFunctions, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "NumberOfFunctions", export.NumberOfFunctions,
                   export.NumberOfFunctions);

            BYTE NumberOfNames[ddl];
            fread(NumberOfNames, 1, dd, f);
            NumberOfNames[dd] = 0;
            export.NumberOfNames = hextoint(NumberOfNames, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "NumberOfNames", export.NumberOfNames, export.NumberOfNames);

            BYTE AddressOfFunctions[ddl];
            fread(AddressOfFunctions, 1, dd, f);
            AddressOfFunctions[dd] = 0;
            export.AddressOfFunctions = hextoint(AddressOfFunctions, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "AddressOfFunctions", export.AddressOfFunctions,
                   export.AddressOfFunctions);


            BYTE AddressOfNames[ddl];
            fread(AddressOfNames, 1, dd, f);
            AddressOfNames[dd] = 0;
            export.AddressOfNames = hextoint(AddressOfNames, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "AddressOfNames", export.AddressOfNames, export.AddressOfNames);

            BYTE AddressOfNameOrdinals[ddl];
            fread(AddressOfNameOrdinals, 1, dd, f);
            AddressOfNameOrdinals[dd] = 0;
            export.AddressOfNameOrdinals = hextoint(AddressOfNameOrdinals, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "AddressOfNameOrdinals", export.AddressOfNameOrdinals,
                   export.AddressOfNameOrdinals);
        }

        // Import table
        if (ioh.DataDirectory[1].VirtualAddress != 0) {
            fseek(f, ioh.DataDirectory[1].VirtualAddress, SEEK_SET);
            IMAGE_IMPORT_DIRECTORY import;
            printf("\n");
            printf("Import table:\n");

            BYTE Characteristics2[ddl];
            fread(Characteristics2, 1, dd, f);
            Characteristics2[dd] = 0;
            import.Misc.Characteristics = hextoint(Characteristics2, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "Characteristics/OG1stThunk", import.Misc.Characteristics,
                   import.Misc.Characteristics);

            BYTE TimeDateStamp2[ddl];
            fread(TimeDateStamp2, 1, dd, f);
            TimeDateStamp2[dd] = 0;
            import.TimeDateStamp = hextoint(TimeDateStamp2, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "TimeDateStamp", import.TimeDateStamp, import.TimeDateStamp);

            BYTE ForwarderChain[ddl];
            fread(ForwarderChain, 1, dd, f);
            ForwarderChain[dd] = 0;
            import.ForwarderChain = hextoint(ForwarderChain, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "ForwarderChain", import.ForwarderChain, import.ForwarderChain);

            BYTE Name1[ddl];
            fread(Name1, 1, dd, f);
            Name1[dd] = 0;
            import.Name1 = hextoint(Name1, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "Name1", import.Name1, import.Name1);

            BYTE FirstThunk[ddl];
            fread(FirstThunk, 1, dd, f);
            FirstThunk[dd] = 0;
            import.FirstThunk = hextoint(FirstThunk, ddl);
            printf("%-30s | %-11lu | %-#11lx\n", "FirstThunk", import.FirstThunk, import.FirstThunk);
        }
    } else {
        printf("Invalid magic in optional header.");
        end(f, 1);
    }

    end(f, 0);
}
