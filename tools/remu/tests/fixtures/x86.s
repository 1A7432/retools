# 32-bit Windows-style test code. Import slots (IAT) live at 0x405000:
#   +00 lstrlenA  +04 GetProcessHeap  +08 HeapAlloc  +0c memcpy (msvcrt, cdecl)
#   +10 MysteryStd (stdcall, purge 8)  +14 NoProto (no prototype)
#   +18 MultiByteToWideChar  +1c GetTickCount  +20 GetProcAddress
#   +24 GetModuleHandleA  +28 RaiseException
# Data at 0x406000: "kernel32.dll" @0, "GetTickCount" @0x10, global buffer @0x100.
.intel_syntax noprefix
.text

# char *heap_dec(const char *src): heap copy of src with every byte ^ 0x20,
# also copied to the global at 0x406100. Exercises IAT calls, a thunk, a cdecl
# import with caller clean-up and stdcall clean-up from the prototype.
heap_dec:
    push ebx
    push esi
    push edi
    mov esi, [esp+16]
    push esi
    call dword ptr [0x405000]
    mov ebx, eax
    call dword ptr [0x405004]
    lea ecx, [ebx+1]
    push ecx
    push 8
    push eax
    call thunk_heapalloc
    mov edi, eax
    xor ecx, ecx
1:
    cmp ecx, ebx
    jge 2f
    mov dl, [esi+ecx]
    xor dl, 0x20
    mov [edi+ecx], dl
    inc ecx
    jmp 1b
2:
    lea ecx, [ebx+1]
    push ecx
    push edi
    push 0x406100
    call dword ptr [0x40500c]
    add esp, 12
    push 2
    push 1
    call dword ptr [0x405010]
    mov eax, edi
    pop edi
    pop esi
    pop ebx
    ret

thunk_heapalloc:
    jmp dword ptr [0x405008]

# int noproto_call(void): calls an import without a prototype, frame-based so
# the unknown clean-up does not matter.
noproto_call:
    push ebp
    mov ebp, esp
    push 8
    push 7
    call dword ptr [0x405014]
    mov esp, ebp
    pop ebp
    ret

# Delphi register convention, 5 args: a1..a3 in eax, edx, ecx; a4, a5 pushed
# in order (so a5 is nearest), callee pops. Returns a1+2a2+3a3+4a4+5a5.
delphi5:
    imul edx, edx, 2
    add eax, edx
    imul ecx, ecx, 3
    add eax, ecx
    mov edx, [esp+8]
    imul edx, edx, 4
    add eax, edx
    mov edx, [esp+4]
    imul edx, edx, 5
    add eax, edx
    ret 8

# usercall: esi*10 + [esp+4]; callee pops 4.
user_esi:
    imul eax, esi, 10
    add eax, [esp+4]
    ret 4

# PEB->ImageBaseAddress through fs:[0x18] (TEB self) and TEB+0x30.
teb_image:
    mov eax, fs:[0x18]
    mov eax, [eax+0x30]
    mov eax, [eax+8]
    ret

# Delphi-style SEH frame set-up and tear-down; returns the old chain head.
seh_frame:
    xor eax, eax
    push ebp
    push 0x401000
    push dword ptr fs:[eax]
    mov fs:[eax], esp
    pop edx
    pop ecx
    pop ecx
    mov fs:[eax], edx
    mov eax, edx
    ret

bad_read:
    mov eax, dword ptr [0x12345678]
    ret
bad_write:
    mov dword ptr [0x12345678], 1
    ret
bad_fetch:
    mov eax, 0x13370000
    jmp eax
bad_insn:
    nop
    ud2
spin:
    inc eax
    jmp spin
int3_fn:
    int3
    ret

# int mb2wc(const char *src, wchar_t *dst, int cap): MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, cap)
mb2wc:
    push ebp
    mov ebp, esp
    push dword ptr [ebp+16]
    push dword ptr [ebp+12]
    push -1
    push dword ptr [ebp+8]
    push 0
    push 65001
    call dword ptr [0x405018]
    pop ebp
    ret

# GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount")(), via a dynamic stub
dyn_call:
    push 0x406000
    call dword ptr [0x405024]
    push 0x406010
    push eax
    call dword ptr [0x405020]
    call eax
    ret

raise_fn:
    push 0
    push 0
    push 0
    push 0xE0434352
    call dword ptr [0x405028]
    ret

# void write_global(void): writes "SECRET" into the global buffer at 0x406100
write_global:
    mov dword ptr [0x406100], 0x52434553
    mov word ptr [0x406104], 0x5445
    ret

# int calls_leaf(void): calls a local function twice (for the call trace)
calls_leaf:
    call leaf
    call leaf
    ret
leaf:
    inc eax
    ret
