#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <limits.h>

static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static FILE *(*real_fopen)(const char *, const char *) = NULL;
static FILE *(*real_fopen64)(const char *, const char *) = NULL;
static int (*real_open64)(const char *, int, ...) = NULL;
static int (*real_openat64)(int, const char *, int, ...) = NULL;
static int (*real_execve)(const char *, char *const [], char *const []) = NULL;
static long (*real_syscall)(long, ...) = NULL;

static __thread int hook_lock = 0;

static long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(number), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static void init_hooks() {
    if (real_open) return;
    if (hook_lock) return;
    hook_lock = 1;
    real_open = dlsym(RTLD_NEXT, "open");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    real_open64 = dlsym(RTLD_NEXT, "open64");
    real_openat64 = dlsym(RTLD_NEXT, "openat64");
    real_execve = dlsym(RTLD_NEXT, "execve");
    real_syscall = dlsym(RTLD_NEXT, "syscall");
    hook_lock = 0;
}

static int is_blocked(const char *pathname) {
    if (!pathname) return 0;
    
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

static void normalize_absolute_path(const char *src, char *dst, size_t dst_len) {
    if (!src || src[0] != '/' || dst_len == 0) {
        if (src) strncpy(dst, src, dst_len - 1);
        return;
    }
    
    char *stack[1024];
    int top = 0;
    
    char *buf = strdup(src);
    char *token = strtok(buf, "/");
    while (token != NULL) {
        if (strcmp(token, ".") == 0) {
            // Ignore
        } else if (strcmp(token, "..") == 0) {
            if (top > 0) top--;
        } else if (strlen(token) > 0) {
            if (top < 1024) {
                stack[top++] = token;
            }
        }
        token = strtok(NULL, "/");
    }
    
    dst[0] = '/';
    dst[1] = '\0';
    size_t offset = 1;
    
    for (int i = 0; i < top; i++) {
        size_t len = strlen(stack[i]);
        if (offset + len + 2 > dst_len) break;
        strcpy(dst + offset, stack[i]);
        offset += len;
        if (i < top - 1) {
            dst[offset++] = '/';
        }
        dst[offset] = '\0';
    }
    free(buf);
}

static int is_path_blocked(int dirfd, const char *pathname) {
    if (!pathname) return 0;
    
    char abs_path[PATH_MAX * 2] = {0};
    
    if (pathname[0] == '/') {
        strncpy(abs_path, pathname, sizeof(abs_path) - 1);
    } else {
        char base_path[PATH_MAX] = {0};
        if (dirfd == AT_FDCWD) {
            if (!getcwd(base_path, sizeof(base_path))) {
                return is_blocked(pathname);
            }
        } else {
            char fd_path[64];
            snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", dirfd);
            ssize_t len = readlink(fd_path, base_path, sizeof(base_path) - 1);
            if (len == -1) {
                return is_blocked(pathname);
            }
            base_path[len] = '\0';
        }
        snprintf(abs_path, sizeof(abs_path), "%s/%s", base_path, pathname);
    }
    
    char norm_path[PATH_MAX * 2] = {0};
    normalize_absolute_path(abs_path, norm_path, sizeof(norm_path));
    
    return is_blocked(norm_path);
}

int open(const char *pathname, int flags, ...) {
    if (is_path_blocked(AT_FDCWD, pathname)) {
        errno = EACCES;
        return -1;
    }
    init_hooks();
    if (!real_open) {
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t);
            va_end(args);
        }
        return (int)raw_syscall(SYS_open, (long)pathname, (long)flags, (long)mode, 0, 0, 0);
    }
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
    if (is_path_blocked(dirfd, pathname)) {
        errno = EACCES;
        return -1;
    }
    init_hooks();
    if (!real_openat) {
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t);
            va_end(args);
        }
        return (int)raw_syscall(SYS_openat, (long)dirfd, (long)pathname, (long)flags, (long)mode, 0, 0);
    }
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
    if (is_path_blocked(AT_FDCWD, pathname)) {
        errno = EACCES;
        return NULL;
    }
    init_hooks();
    if (!real_fopen) {
        return NULL;
    }
    return real_fopen(pathname, mode);
}

FILE *fopen64(const char *pathname, const char *mode) {
    if (is_path_blocked(AT_FDCWD, pathname)) {
        errno = EACCES;
        return NULL;
    }
    init_hooks();
    if (!real_fopen64) {
        return NULL;
    }
    return real_fopen64(pathname, mode);
}

int open64(const char *pathname, int flags, ...) {
    if (is_path_blocked(AT_FDCWD, pathname)) {
        errno = EACCES;
        return -1;
    }
    init_hooks();
    if (!real_open64) {
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t);
            va_end(args);
        }
        return (int)raw_syscall(SYS_open, (long)pathname, (long)flags, (long)mode, 0, 0, 0);
    }
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
    if (is_path_blocked(dirfd, pathname)) {
        errno = EACCES;
        return -1;
    }
    init_hooks();
    if (!real_openat64) {
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t);
            va_end(args);
        }
        return (int)raw_syscall(SYS_openat, (long)dirfd, (long)pathname, (long)flags, (long)mode, 0, 0);
    }
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
    if (is_path_blocked(AT_FDCWD, pathname)) {
        errno = EACCES;
        return -1;
    }
    if (argv) {
        for (int i = 0; argv[i] != NULL; i++) {
            if (is_path_blocked(AT_FDCWD, argv[i])) {
                errno = EACCES;
                return -1;
            }
        }
    }
    init_hooks();
    if (!real_execve) {
        return (int)raw_syscall(SYS_execve, (long)pathname, (long)argv, (long)envp, 0, 0, 0);
    }
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
        if (pathname && is_path_blocked(AT_FDCWD, pathname)) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_openat
    if (number == SYS_openat) {
        int dirfd = (int)a1;
        const char *pathname = (const char *)a2;
        if (pathname && is_path_blocked(dirfd, pathname)) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_openat2
    if (number == SYS_openat2) {
        int dirfd = (int)a1;
        const char *pathname = (const char *)a2;
        if (pathname && is_path_blocked(dirfd, pathname)) { errno = EACCES; return -1; }
    }
#endif

    init_hooks();
    if (!real_syscall) {
        return raw_syscall(number, a1, a2, a3, a4, a5, a6);
    }
    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}