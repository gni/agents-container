#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>

static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static FILE *(*real_fopen)(const char *, const char *) = NULL;
static FILE *(*real_fopen64)(const char *, const char *) = NULL;
static int (*real_open64)(const char *, int, ...) = NULL;
static int (*real_openat64)(int, const char *, int, ...) = NULL;
static int (*real_execve)(const char *, char *const [], char *const []) = NULL;
static long (*real_syscall)(long, ...) = NULL;

static void init_hooks() {
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!real_fopen64) real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    if (!real_open64) real_open64 = dlsym(RTLD_NEXT, "open64");
    if (!real_openat64) real_openat64 = dlsym(RTLD_NEXT, "openat64");
    if (!real_execve) real_execve = dlsym(RTLD_NEXT, "execve");
    if (!real_syscall) real_syscall = dlsym(RTLD_NEXT, "syscall");
}

int is_blocked(const char *pathname) {
    if (!pathname) return 0;
    
    // Harden path checks to block relative paths and directory boundary bypasses
    int match = 0;
    if (strstr(pathname, "/run/secrets") != NULL ||
        strcmp(pathname, "run/secrets") == 0 ||
        strncmp(pathname, "run/secrets/", 12) == 0 ||
        strstr(pathname, "/vault") != NULL ||
        strcmp(pathname, "vault") == 0 ||
        strncmp(pathname, "vault/", 6) == 0 ||
        strstr(pathname, ".secrets") != NULL ||
        strstr(pathname, "auth.json") != NULL) {
        match = 1;
    }
    
    if (match) {
        if (geteuid() == 0) return 0;
        if (strstr(pathname, "auth.json") != NULL && getpid() == 1) {
            return 0;
        }
        return 1;
    }
    return 0;
}

int open(const char *pathname, int flags, ...) {
    if (is_blocked(pathname)) {
        errno = EACCES;
        return -1;
    }
    init_hooks();
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return real_open(pathname, flags, mode);
    }
    return real_open(pathname, flags);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    if (is_blocked(pathname)) {
        errno = EACCES;
        return -1;
    }
    init_hooks();
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return real_openat(dirfd, pathname, flags, mode);
    }
    return real_openat(dirfd, pathname, flags);
}

FILE *fopen(const char *pathname, const char *mode) {
    if (is_blocked(pathname)) {
        errno = EACCES;
        return NULL;
    }
    init_hooks();
    return real_fopen(pathname, mode);
}

FILE *fopen64(const char *pathname, const char *mode) {
    if (is_blocked(pathname)) {
        errno = EACCES;
        return NULL;
    }
    init_hooks();
    return real_fopen64(pathname, mode);
}

int open64(const char *pathname, int flags, ...) {
    if (is_blocked(pathname)) {
        errno = EACCES;
        return -1;
    }
    init_hooks();
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return real_open64(pathname, flags, mode);
    }
    return real_open64(pathname, flags);
}

int openat64(int dirfd, const char *pathname, int flags, ...) {
    if (is_blocked(pathname)) {
        errno = EACCES;
        return -1;
    }
    init_hooks();
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return real_openat64(dirfd, pathname, flags, mode);
    }
    return real_openat64(dirfd, pathname, flags);
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (argv) {
        for (int i = 0; argv[i] != NULL; i++) {
            if (is_blocked(argv[i])) {
                errno = EACCES;
                return -1;
            }
        }
    }
    init_hooks();
    return real_execve(pathname, argv, envp);
}

long syscall(long number, ...) {
    va_list args;
    va_start(args, number);
    long a1 = va_arg(args, long);
    long a2 = va_arg(args, long);
    long a3 = va_arg(args, long);
    long a4 = va_arg(args, long);
    long a5 = va_arg(args, long);
    long a6 = va_arg(args, long);
    va_end(args);

#ifdef SYS_open
    if (number == SYS_open) {
        const char *pathname = (const char *)a1;
        if (pathname && is_blocked(pathname)) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_openat
    if (number == SYS_openat) {
        const char *pathname = (const char *)a2;
        if (pathname && is_blocked(pathname)) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_openat2
    if (number == SYS_openat2) {
        const char *pathname = (const char *)a2;
        if (pathname && is_blocked(pathname)) { errno = EACCES; return -1; }
    }
#else
    if (number == 437) {
        const char *pathname = (const char *)a2;
        if (pathname && is_blocked(pathname)) { errno = EACCES; return -1; }
    }
#endif
    
    init_hooks();
    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}