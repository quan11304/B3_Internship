include \Masm32\include\masm32rt.inc

toStack MACRO pos:REQ, value:=<eax>
	LOCAL temp
	temp = - pos * regSz
    mov [ebp + temp], value
ENDM

fromStack MACRO pos:REQ
	LOCAL temp
	temp = - pos * regSz
	EXITM <[ebp+temp]>
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
	
	
