# 64-bit Windows-style test code. IAT at 0x405000: +0 memset, +8 memcpy.
.intel_syntax noprefix
.text
gs_image:
    mov rax, gs:[0x30]
    mov rax, [rax+0x60]
    mov rax, [rax+0x10]
    ret

# char *x64_imports(char *dst): memset(dst, 'A', 8) via the IAT, then
# memcpy(dst+8, dst, 8) via a thunk; returns dst.
x64_imports:
    push rbx
    sub rsp, 0x20
    mov rbx, rcx
    mov edx, 0x41
    mov r8d, 8
    call qword ptr [0x405000]
    lea rcx, [rbx+8]
    mov rdx, rbx
    mov r8d, 8
    call thunk_memcpy
    mov rax, rbx
    add rsp, 0x20
    pop rbx
    ret
thunk_memcpy:
    jmp qword ptr [0x405008]

bad_read64:
    mov rax, 0x123456789
    mov rax, [rax]
    ret
