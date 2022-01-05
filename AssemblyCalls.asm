.code
MyGetTickCount64Kernel32 proc
                mov     ecx, 7FFE0004h
                mov     eax, 7FFE0320h
                shl     rcx, 20h
                mov     rax, [rax]
                shl     rax, 8
                mul     rcx
                mov     rax, rdx
                ret
MyGetTickCount64Kernel32 endp
end