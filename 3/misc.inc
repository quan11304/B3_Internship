include \Masm32\include\masm32rt.inc

toStack MACRO pos:REQ, value:=<eax>
	push value
	mov eax, pos
    imul eax, 4
    neg eax
    pop [ebp + eax] ; eax is expected to be a negative value
ENDM
; eax will NOT be reserved after MACRO
; eax can be used as input value

fromStack MACRO pos:REQ, reg:REQ
	mov reg, pos
	imul reg, regSz
	neg reg
	mov reg, [ebp + reg]
ENDM

k32import MACRO pFunc:REQ
	; Input the offset to a string that is the name of the queried function
	fromStack kernel32dll, ebx
	fromStack k32NumFunc, edx
	xor eax, eax
	
	loopback:
		fromStack NamePtrTbl, edi
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
	fromStack OrdinalTbl, edx
	mov ax, [edx + eax * 2]
	fromStack AddrTbl, edx
	mov eax, [edx + eax * 4]
	fromStack kernel32dll, edx
	add eax, edx
	; eax now hold mem addr of function pointed to by pFunc
ENDM
	
	
