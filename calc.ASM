start:
        push eax        ;save aa registers
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push ebp

        ;establish new stack frame
        push ebp
        mov ebp, esp
        sub esp, 18h    ;allocate memory on stack for local variables

        ;push function name on the stack
        xor esi, esi
        push 00636578h
        push 456e6957h
        mov [ebp - 4], esp       ; var4 = WinExec\0x00

        xor esi, esi
        mov ebx, [fs:30h]       ; Get pointer to PEB
        mov ebx, [ebx + 0x0C]   ; Get pointer to PEB_LDR_DATA
        mov ebx, [ebx + 0x14]   ; Get pointer to first entry in InMemoryOrderModuleList
        mov ebx, [ebx]          ; Get pointer to second (ntdll.dll) entry in InMemoryOrderModuleList
        mov ebx, [ebx]          ; Get pointer to third (kernel32.dll) entry in InMemoryOrderModuleList
        mov ebx, [ebx + 0x10]   ; Get kernel32.dll base address
        mov [ebp - 8], ebx      ; var8 = kernel32.dll base address

        mov eax, [ebx + 0x3C]   ; RVA of PE signature
        add eax, ebx            ; Address of PE signature = base address + RVA of PE signature
        mov eax, [eax + 0x78]   ; RVA of Export Table
        add eax, ebx            ; address of Export Table

        mov ecx, [eax + 24h]    ; RVA of Ordinal Table
        add ecx, ebx            ; address of Ordinal Table
        mov [ebp - 0Ch], ecx    ; var12 = address of Ordinal Table

        mov edi, [eax + 20h]    ; RVA of Name Pointer Table
        add edi, ebx            ; address of Name Pointer Table
        mov [ebp - 10h], edi    ; var16 = address of Name Pointer Table

        mov edx, [eax + 1Ch]    ; RVA of Address Table
        add edx, ebx            ; Address of Address Table
        mov [ebp - 14h], edx    ; var20 = address of Address Table

        mov edx, [eax + 14h]    ; number of exported functions

        xor eax, eax            ; counter = 0

        .loop:
                mov edi, [ebp - 10h]    ; var16 = address of Name Pointer Table
                mov esi, [ebp - 4]      ; WinExec\0xcc
                xor ecx, ecx

                cld                     ; set DF = 0 => process strings from left to right
                mov edi, [edi + eax*4]
                add edi, ebx
                add ecx, 8
                repe cmpsb

                jz start.found

                inc eax
                cmp eax, edx            ; check if last function is reached
                jb start.loop           ; if not the last -> loop

                add esp, 26h
                std
                jmp start.end           ; if function is not found, jump to end

        .found:
                ; the counter (eax) now holds the position of WinExec
                mov ecx, [ebp - 0Ch]    ; ecx = var12 = Address of Ordinal Table
                mov edx, [ebp - 14h]    ; edx = var20 = Address of Address Table
                mov ax, [ecx + eax*2]   ; ax = ordinal number of WinExec() = var12 + (counter * 2)
                mov eax, [edx + eax*4]  ; eax = RVA of function WinExec() = var20 + (ordinal * 4)
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
                mov esi, esp            ; esi -> "C:\Windows\System32\calc.exe"

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