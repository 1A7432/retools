// arm64 ELF-style test code. Extern symbols at 0x405000 (memset), 0x405008 (malloc).
.text
// char *a64_imports(char *dst): memset(dst, 'B', 8) through the extern address,
// then p = malloc(16) through a PLT-like thunk, copies dst[0..8) to p, returns p.
a64_imports:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]
    mov x19, x0
    mov w1, #0x42
    mov x2, #8
    ldr x16, =0x405000
    blr x16
    mov x0, #16
    bl thunk_malloc
    ldr x1, [x19]
    str x1, [x0]
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
thunk_malloc:
    ldr x16, =0x405008
    ldr x16, [x16]
    br x16
.ltorg

tls_self:
    mrs x0, tpidr_el0
    ldr x0, [x0]
    ret

bad_read_a64:
    ldr x0, =0x12345678
    ldr x0, [x0]
    ret
.ltorg

udf_a64:
    nop
    .inst 0x00000000

brk_a64:
    brk #1
    ret

boundary_forward:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    ldr x16, =0x405010
    blr x16
    ldp x29, x30, [sp], #16
    ret
.ltorg
