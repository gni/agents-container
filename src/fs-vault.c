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

static void init_hooks() {
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
    }
}

int is_blocked(const char *pathname) {
    if (!pathname) return 0;
    
    if (strstr(pathname, "/run/secrets/") != NULL || strstr(pathname, "/vault/") != NULL || strstr(pathname, ".secrets") != NULL || strstr(pathname, "auth.json") != NULL) {
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
    int (*orig)(int, const char*, int, ...) = dlsym(RTLD_NEXT, "openat");
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return orig(dirfd, pathname, flags, mode);
    }
    return orig(dirfd, pathname, flags);
}

FILE *fopen(const char *pathname, const char *mode) {
    if (is_blocked(pathname)) {
        errno = EACCES;
        return NULL;
    }
    FILE* (*orig)(const char*, const char*) = dlsym(RTLD_NEXT, "fopen");
    return orig(pathname, mode);
}

FILE *fopen64(const char *pathname, const char *mode) {
    if (is_blocked(pathname)) {
        errno = EACCES;
        return NULL;
    }
    FILE* (*orig)(const char*, const char*) = dlsym(RTLD_NEXT, "fopen64");
    return orig(pathname, mode);
}

int open64(const char *pathname, int flags, ...) {
    if (is_blocked(pathname)) {
        errno = EACCES;
        return -1;
    }
    int (*orig)(const char*, int, ...) = dlsym(RTLD_NEXT, "open64");
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return orig(pathname, flags, mode);
    }
    return orig(pathname, flags);
}

int openat64(int dirfd, const char *pathname, int flags, ...) {
    if (is_blocked(pathname)) {
        errno = EACCES;
        return -1;
    }
    int (*orig)(int, const char*, int, ...) = dlsym(RTLD_NEXT, "openat64");
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return orig(dirfd, pathname, flags, mode);
    }
    return orig(dirfd, pathname, flags);
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
    int (*orig)(const char*, char* const*, char* const*) = dlsym(RTLD_NEXT, "execve");
    return orig(pathname, argv, envp);
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
    
    long (*orig)(long, ...) = dlsym(RTLD_NEXT, "syscall");
    return orig(number, a1, a2, a3, a4, a5, a6);
}