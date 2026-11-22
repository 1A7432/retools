/* Start-up state for the init tests: a table built by a loop, a function that
   reads it, a key derived through the table, and an allocator that only works
   when replaced. Globals live at fixed addresses in the image's .data page
   (0x406800 up), so the extracted .text needs no relocation. */
typedef unsigned char u8;
typedef unsigned int u32;

#define SBOX ((u8 *)0x406800)
#define TABLE_PTR ((u8 **)0x406900)

#ifdef __i386__
#define STDCALL __attribute__((stdcall))
#else
#define STDCALL
#endif

/* SBOX[i] = 7*i + 3 (mod 256), a permutation */
void build_sbox(void)
{
    for (int i = 0; i < 256; i++)
        SBOX[i] = (u8)(7 * i + 3);
}

void sbox_apply(const u8 *in, u8 *out, int n)
{
    for (int i = 0; i < n; i++)
        out[i] = SBOX[in[i]];
}

/* out[i] = SBOX[(seed + 13*i) & 255]; returns the byte sum */
int derive_key(int seed, u8 *out, int n)
{
    int s = 0;
    for (int i = 0; i < n; i++) {
        out[i] = SBOX[(seed + 13 * i) & 255];
        s += out[i];
    }
    return s;
}

/* Stands for a runtime allocator that start-up never initialised: it faults
   on its own state unless it is replaced. */
__attribute__((noinline)) static STDCALL u8 *alloc_table(u32 n)
{
    if (n > 0x100000)
        return 0;
    return *(u8 *volatile *)0x10;
}

void build_heap_table(u32 n)
{
    u8 *p = alloc_table(n);
    for (u32 i = 0; i < n; i++)
        p[i] = (u8)(i ^ 0x5a);
    *TABLE_PTR = p;
}

int heap_table_sum(int n)
{
    int s = 0;
    for (int i = 0; i < n; i++)
        s += (*TABLE_PTR)[i];
    return s;
}

int never_returns(void)
{
    return *(volatile int *)0x20;
}
