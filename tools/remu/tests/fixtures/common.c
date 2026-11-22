/* Leaf functions compiled for every target (no calls, no globals, so the
   extracted .text needs no relocation). */
typedef unsigned char u8;
typedef unsigned short u16;

int add3(int a, int b, int c) { return a + 2 * b + 3 * c; }

long f10(long a, long b, long c, long d, long e, long f, long g, long h, long i, long j)
{
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i + 10 * j;
}

int count_char(const char *s, char ch)
{
    int n = 0;
    for (; *s; s++)
        if (*s == ch)
            n++;
    return n;
}

int wlen(const u16 *s)
{
    int n = 0;
    while (s[n])
        n++;
    return n;
}

void upcase(char *s)
{
    for (; *s; s++)
        if (*s >= 'a' && *s <= 'z')
            *s -= 32;
}

void xor_dec(const u8 *in, u8 *out, int n, u8 key)
{
    for (int i = 0; i < n; i++)
        out[i] = in[i] ^ (u8)(key + i);
}

void rc4(const u8 *key, int klen, u8 *buf, int n)
{
    u8 S[256];
    int i, j = 0;
    for (i = 0; i < 256; i++)
        S[i] = (u8)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 255;
        u8 t = S[i]; S[i] = S[j]; S[j] = t;
    }
    i = j = 0;
    for (int k = 0; k < n; k++) {
        i = (i + 1) & 255;
        j = (j + S[i]) & 255;
        u8 t = S[i]; S[i] = S[j]; S[j] = t;
        buf[k] ^= S[(S[i] + S[j]) & 255];
    }
}

struct inner { int len; int *vals; };
struct outer { int scale; struct inner *in; };

int sum_nested(const struct outer *o)
{
    int s = 0;
    for (int i = 0; i < o->in->len; i++)
        s += o->in->vals[i];
    return s * o->scale;
}
