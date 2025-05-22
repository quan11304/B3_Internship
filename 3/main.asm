include \masm64\include64\masm64rt.inc

.data
    strCaption db 'Notice', 0
    strContent db 'You have been infected!', 0
    strLLA db 'LoadLibraryA', 0
    strGPA db 'GetProcAddress', 0
    stru32dll db 'user32.dll', 0
    strMBA db 'MessageBoxA', 0
    intTest dd ?

.code
main PROC
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    ret
main ENDP

entry_point PROC
    call main           ; entry_point + 1 + dd (size of instruction) stored in stack
    rcall StdOut, chr$(0ah)
    invoke ExitProcess, 0
entry_point ENDP

end
