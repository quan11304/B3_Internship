include \Masm32\include\masm32rt.inc

toStack MACRO pos:REQ, value:REQ
	mov eax, pos
    imul eax, regSz
    neg eax
    mov [ebp + eax], value ; eax is expected to be a negative value
ENDM

fromStack MACRO pos:REQ, reg:REQ
	mov eax, pos
	imul eax, regSz
	neg eax
	mov reg, [ebp + eax]
ENDM

k32import MACRO pFunc:REQ
	fromStack(k32NumFunc, edx)
	xor eax, eax
	loopback:
	mov edi, [ebp + NamePtrTbl]
	mov edi, [edi + eax*4]
	add edi, ebx
	mov esi, pFunc
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
	mov ecx, [ebp + OrdinalTbl]
	mov edx, [ebp + AddrTbl]
	mov ax, [ecx + eax * 2]
	mov eax, [edx + eax * 4]
	EXITM
ENDM
	
	
