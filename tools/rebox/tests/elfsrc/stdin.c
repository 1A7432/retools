/* Harmless stdin test program for rebox. Only ever run inside rebox's emulator.
 *
 * Modes (argv[1]):
 *   none  prompt on stdout, read one line with fgets, report it on stderr and
 *         stdout, then try a second fgets, which must see end-of-file; the
 *         last word ("eof") has no trailing newline
 *   raw   read(0) until it returns 0, echo every byte to stdout unchanged,
 *         then report the byte count and the final read's result on stderr
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "raw")) {
        unsigned char buf[7];   /* small, so several reads are needed */
        long total = 0;
        ssize_t n;
        while ((n = read(0, buf, sizeof buf)) > 0) {
            write(1, buf, (size_t)n);
            total += n;
        }
        fprintf(stderr, "raw total=%ld last=%ld\n", total, (long)n);
        return 3;
    }
    char line[256];
    printf("prompt: ");
    fflush(stdout);
    if (!fgets(line, sizeof line, stdin)) {
        puts("no input");
        return 1;
    }
    line[strcspn(line, "\n")] = 0;
    fprintf(stderr, "err: got %zu\n", strlen(line));
    printf("line=[%s]\n", line);
    fflush(stdout);
    if (!fgets(line, sizeof line, stdin))
        fputs("eof", stdout);
    else
        printf("more=[%s]", line);
    return 0;
}
