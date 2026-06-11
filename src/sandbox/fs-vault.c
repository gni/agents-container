/*
 * Copyright 2026 Lucian BLETAN
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
#include <sys/stat.h>
#include <dirent.h>

static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static FILE *(*real_fopen)(const char *, const char *) = NULL;
static FILE *(*real_fopen64)(const char *, const char *) = NULL;
static int (*real_open64)(const char *, int, ...) = NULL;
static int (*real_openat64)(int, const char *, int, ...) = NULL;
static int (*real_execve)(const char *, char *const [], char *const []) = NULL;
static ssize_t (*real_readlink)(const char *, char *, size_t) = NULL;
static ssize_t (*real_readlinkat)(int, const char *, char *, size_t) = NULL;
static long (*real_syscall)(long, ...) = NULL;
static int (*real_stat)(const char *, struct stat *) = NULL;
static int (*real_lstat)(const char *, struct stat *) = NULL;
static int (*real_fstatat)(int, const char *, struct stat *, int) = NULL;
static DIR *(*real_opendir)(const char *) = NULL;
static DIR *(*real_fdopendir)(int) = NULL;
static int (*real_statx)(int, const char *, int, unsigned int, struct statx *) = NULL;

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
    real_readlink = dlsym(RTLD_NEXT, "readlink");
    real_readlinkat = dlsym(RTLD_NEXT, "readlinkat");
    real_syscall = dlsym(RTLD_NEXT, "syscall");
    real_stat = dlsym(RTLD_NEXT, "stat");
    real_lstat = dlsym(RTLD_NEXT, "lstat");
    real_fstatat = dlsym(RTLD_NEXT, "fstatat");
    real_opendir = dlsym(RTLD_NEXT, "opendir");
    real_fdopendir = dlsym(RTLD_NEXT, "fdopendir");
    real_statx = dlsym(RTLD_NEXT, "statx");
    hook_lock = 0;
}

static void __attribute__((constructor)) eager_init(void) {
    init_hooks();
}

#define MAX_CUSTOM_BLOCKED_PATHS 256
#define MAX_PATH_LEN 512

static char custom_blocked_paths[MAX_CUSTOM_BLOCKED_PATHS][MAX_PATH_LEN];
static int custom_blocked_paths_count = 0;
static int custom_paths_loaded = 0;

static void load_custom_blocked_paths() {
    if (custom_paths_loaded) return;
    custom_paths_loaded = 1;

    long fd = raw_syscall(SYS_open, (long)"/etc/sandbox/blocked_paths.txt", O_RDONLY, 0, 0, 0, 0);
    if (fd < 0) {
        return;
    }

    static char buf[8192];
    ssize_t total_bytes = 0;
    while (total_bytes < (ssize_t)sizeof(buf) - 1) {
        ssize_t n = raw_syscall(SYS_read, fd, (long)(buf + total_bytes), sizeof(buf) - 1 - total_bytes, 0, 0, 0);
        if (n <= 0) break;
        total_bytes += n;
    }
    buf[total_bytes] = '\0';
    raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0);

    char *line = buf;
    char *end = buf + total_bytes;
    while (line < end && custom_blocked_paths_count < MAX_CUSTOM_BLOCKED_PATHS) {
        char *next_line = line;
        while (next_line < end && *next_line != '\n' && *next_line != '\r') {
            next_line++;
        }
        char term = *next_line;
        *next_line = '\0';

        // Trim leading space/tabs
        while (*line == ' ' || *line == '\t') {
            line++;
        }

        // Skip comments and empty lines
        if (*line != '\0' && *line != '#') {
            // Trim trailing space/tabs
            char *tail = line + strlen(line) - 1;
            while (tail >= line && (*tail == ' ' || *tail == '\t' || *tail == '\r' || *tail == '\n')) {
                *tail = '\0';
                tail--;
            }

            if (strlen(line) > 0 && strlen(line) < MAX_PATH_LEN) {
                strncpy(custom_blocked_paths[custom_blocked_paths_count], line, MAX_PATH_LEN - 1);
                custom_blocked_paths[custom_blocked_paths_count][MAX_PATH_LEN - 1] = '\0';
                custom_blocked_paths_count++;
            }
        }

        if (term == '\0') {
            break;
        }
        line = next_line + 1;
    }
}

static int path_matches(const char *pathname, const char *blocked_path) {
    if (!pathname || !blocked_path) return 0;

    const char *bp = blocked_path;
    if (blocked_path[0] == '/' && pathname[0] != '/') {
        bp = blocked_path + 1;
    }

    size_t bp_len = strlen(bp);
    if (bp_len == 0) return 0;

    size_t match_len = bp_len;
    while (match_len > 1 && bp[match_len - 1] == '/') {
        match_len--;
    }

    size_t pn_len = strlen(pathname);
    size_t compare_len = pn_len;
    while (compare_len > 1 && pathname[compare_len - 1] == '/') {
        compare_len--;
    }

    if (compare_len == match_len && strncmp(pathname, bp, match_len) == 0) {
        return 1;
    }

    if (pn_len > match_len && strncmp(pathname, bp, match_len) == 0 && pathname[match_len] == '/') {
        return 1;
    }

    return 0;
}

static int is_blocked(const char *pathname) {
    if (!pathname) return 0;

    if (geteuid() != 0) {
        load_custom_blocked_paths();
        for (int i = 0; i < custom_blocked_paths_count; i++) {
            if (path_matches(pathname, custom_blocked_paths[i])) {
                return 1;
            }
        }
    }
    
    int match = 0;
    if (strcmp(pathname, "/run/secrets") == 0 ||
        strncmp(pathname, "/run/secrets/", 13) == 0 ||
        strcmp(pathname, "run/secrets") == 0 ||
        strncmp(pathname, "run/secrets/", 12) == 0 ||
        strcmp(pathname, "/vault") == 0 ||
        strncmp(pathname, "/vault/", 7) == 0 ||
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

    // Block reading environment of other processes
    if (strstr(pathname, "/proc/") != NULL && strstr(pathname, "/environ") != NULL) {
        char my_proc_path[64];
        snprintf(my_proc_path, sizeof(my_proc_path), "/proc/%d/environ", getpid());
        if (strcmp(pathname, "/proc/self/environ") != 0 && strcmp(pathname, my_proc_path) != 0) {
            return 1;
        }
    }

    // Block reading temp gh/glab credentials by other processes
    if ((strstr(pathname, "/tmp/gh-conf-") != NULL && (strstr(pathname, "hosts.yml") != NULL || strstr(pathname, "config.yml") != NULL)) ||
        (strstr(pathname, "/tmp/glab-conf-") != NULL && (strstr(pathname, "config.yml") != NULL || strstr(pathname, "config.json") != NULL))) {
        char exe_path[PATH_MAX] = {0};
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len != -1) {
            exe_path[len] = '\0';
            if (strcmp(exe_path, "/usr/bin/gh-original") != 0 && strcmp(exe_path, "/usr/bin/glab-original") != 0) {
                return 1;
            }
        } else {
            return 1; // Block if we cannot verify the caller
        }
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

static int is_trusted_system_path(const char *path) {
    if (!path || path[0] != '/') return 0;
    if (strncmp(path, "/sys/", 5) == 0 ||
        strncmp(path, "/lib/", 5) == 0 ||
        strncmp(path, "/lib64/", 7) == 0 ||
        strncmp(path, "/dev/", 5) == 0 ||
        strncmp(path, "/usr/", 5) == 0 ||
        strncmp(path, "/etc/", 5) == 0 ||
        strncmp(path, "/var/run/nscd/", 14) == 0) {
        return 1;
    }
    return 0;
}

static int is_path_blocked(int dirfd, const char *pathname) {
    if (!pathname) return 0;
    
    if (is_trusted_system_path(pathname)) {
        return 0;
    }
    
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
    
    if (is_trusted_system_path(norm_path)) {
        return 0;
    }
    
    // Resolve symlink target using realpath
    char resolved_path[PATH_MAX] = {0};
    if (realpath(norm_path, resolved_path) != NULL) {
        if (is_blocked(resolved_path)) {
            return 1;
        }
    }
    
    return is_blocked(norm_path);
}


int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (hook_lock) {
        if (real_open) {
            if (flags & O_CREAT) {
                return real_open(pathname, flags, mode);
            }
            return real_open(pathname, flags);
        }
        return (int)raw_syscall(SYS_open, (long)pathname, (long)flags, (long)mode, 0, 0, 0);
    }

    hook_lock = 1;
    int blocked = is_path_blocked(AT_FDCWD, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_open) {
        if (flags & O_CREAT) {
            return real_open(pathname, flags, mode);
        }
        return real_open(pathname, flags);
    }
    return (int)raw_syscall(SYS_open, (long)pathname, (long)flags, (long)mode, 0, 0, 0);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (hook_lock) {
        if (real_openat) {
            if (flags & O_CREAT) {
                return real_openat(dirfd, pathname, flags, mode);
            }
            return real_openat(dirfd, pathname, flags);
        }
        return (int)raw_syscall(SYS_openat, (long)dirfd, (long)pathname, (long)flags, (long)mode, 0, 0);
    }

    hook_lock = 1;
    int blocked = is_path_blocked(dirfd, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_openat) {
        if (flags & O_CREAT) {
            return real_openat(dirfd, pathname, flags, mode);
        }
        return real_openat(dirfd, pathname, flags);
    }
    return (int)raw_syscall(SYS_openat, (long)dirfd, (long)pathname, (long)flags, (long)mode, 0, 0);
}

FILE *fopen(const char *pathname, const char *mode) {
    if (hook_lock) {
        if (real_fopen) {
            return real_fopen(pathname, mode);
        }
        return NULL;
    }

    hook_lock = 1;
    int blocked = is_path_blocked(AT_FDCWD, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return NULL;
    }

    init_hooks();
    if (real_fopen) {
        return real_fopen(pathname, mode);
    }
    return NULL;
}

FILE *fopen64(const char *pathname, const char *mode) {
    if (hook_lock) {
        if (real_fopen64) {
            return real_fopen64(pathname, mode);
        }
        return NULL;
    }

    hook_lock = 1;
    int blocked = is_path_blocked(AT_FDCWD, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return NULL;
    }

    init_hooks();
    if (real_fopen64) {
        return real_fopen64(pathname, mode);
    }
    return NULL;
}

int open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (hook_lock) {
        if (real_open64) {
            if (flags & O_CREAT) {
                return real_open64(pathname, flags, mode);
            }
            return real_open64(pathname, flags);
        }
        return (int)raw_syscall(SYS_open, (long)pathname, (long)flags, (long)mode, 0, 0, 0);
    }

    hook_lock = 1;
    int blocked = is_path_blocked(AT_FDCWD, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_open64) {
        if (flags & O_CREAT) {
            return real_open64(pathname, flags, mode);
        }
        return real_open64(pathname, flags);
    }
    return (int)raw_syscall(SYS_open, (long)pathname, (long)flags, (long)mode, 0, 0, 0);
}

int openat64(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (hook_lock) {
        if (real_openat64) {
            if (flags & O_CREAT) {
                return real_openat64(dirfd, pathname, flags, mode);
            }
            return real_openat64(dirfd, pathname, flags);
        }
        return (int)raw_syscall(SYS_openat, (long)dirfd, (long)pathname, (long)flags, (long)mode, 0, 0);
    }

    hook_lock = 1;
    int blocked = is_path_blocked(dirfd, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_openat64) {
        if (flags & O_CREAT) {
            return real_openat64(dirfd, pathname, flags, mode);
        }
        return real_openat64(dirfd, pathname, flags);
    }
    return (int)raw_syscall(SYS_openat, (long)dirfd, (long)pathname, (long)flags, (long)mode, 0, 0);
}

int stat(const char *pathname, struct stat *statbuf) {
    if (hook_lock) {
        if (real_stat) {
            return real_stat(pathname, statbuf);
        }
#ifdef SYS_stat
        return (int)raw_syscall(SYS_stat, (long)pathname, (long)statbuf, 0, 0, 0, 0);
#else
        return (int)raw_syscall(SYS_newfstatat, AT_FDCWD, (long)pathname, (long)statbuf, 0, 0, 0);
#endif
    }

    hook_lock = 1;
    int blocked = is_path_blocked(AT_FDCWD, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_stat) {
        return real_stat(pathname, statbuf);
    }
#ifdef SYS_stat
    return (int)raw_syscall(SYS_stat, (long)pathname, (long)statbuf, 0, 0, 0, 0);
#else
    return (int)raw_syscall(SYS_newfstatat, AT_FDCWD, (long)pathname, (long)statbuf, 0, 0, 0);
#endif
}

int lstat(const char *pathname, struct stat *statbuf) {
    if (hook_lock) {
        if (real_lstat) {
            return real_lstat(pathname, statbuf);
        }
#ifdef SYS_lstat
        return (int)raw_syscall(SYS_lstat, (long)pathname, (long)statbuf, 0, 0, 0, 0);
#else
        return (int)raw_syscall(SYS_newfstatat, AT_FDCWD, (long)pathname, (long)statbuf, AT_SYMLINK_NOFOLLOW, 0, 0);
#endif
    }

    hook_lock = 1;
    int blocked = is_path_blocked(AT_FDCWD, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_lstat) {
        return real_lstat(pathname, statbuf);
    }
#ifdef SYS_lstat
    return (int)raw_syscall(SYS_lstat, (long)pathname, (long)statbuf, 0, 0, 0, 0);
#else
    return (int)raw_syscall(SYS_newfstatat, AT_FDCWD, (long)pathname, (long)statbuf, AT_SYMLINK_NOFOLLOW, 0, 0);
#endif
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    if (hook_lock) {
        if (real_fstatat) {
            return real_fstatat(dirfd, pathname, statbuf, flags);
        }
        return (int)raw_syscall(SYS_newfstatat, (long)dirfd, (long)pathname, (long)statbuf, (long)flags, 0, 0);
    }

    hook_lock = 1;
    int blocked = is_path_blocked(dirfd, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_fstatat) {
        return real_fstatat(dirfd, pathname, statbuf, flags);
    }
    return (int)raw_syscall(SYS_newfstatat, (long)dirfd, (long)pathname, (long)statbuf, (long)flags, 0, 0);
}

int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) {
    if (hook_lock) {
        if (real_statx) {
            return real_statx(dirfd, pathname, flags, mask, statxbuf);
        }
        return (int)raw_syscall(SYS_statx, (long)dirfd, (long)pathname, (long)flags, (long)mask, (long)statxbuf, 0);
    }

    hook_lock = 1;
    int blocked = is_path_blocked(dirfd, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_statx) {
        return real_statx(dirfd, pathname, flags, mask, statxbuf);
    }
    return (int)raw_syscall(SYS_statx, (long)dirfd, (long)pathname, (long)flags, (long)mask, (long)statxbuf, 0);
}

DIR *opendir(const char *name) {
    if (hook_lock) {
        if (real_opendir) {
            return real_opendir(name);
        }
        return NULL;
    }

    hook_lock = 1;
    int blocked = is_path_blocked(AT_FDCWD, name);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return NULL;
    }

    init_hooks();
    if (real_opendir) {
        return real_opendir(name);
    }
    return NULL;
}

DIR *fdopendir(int fd) {
    if (hook_lock) {
        if (real_fdopendir) {
            return real_fdopendir(fd);
        }
        return NULL;
    }

    hook_lock = 1;
    int blocked = is_path_blocked(fd, "");
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return NULL;
    }

    init_hooks();
    if (real_fdopendir) {
        return real_fdopendir(fd);
    }
    return NULL;
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (hook_lock) {
        if (real_execve) {
            return real_execve(pathname, argv, envp);
        }
        return (int)raw_syscall(SYS_execve, (long)pathname, (long)argv, (long)envp, 0, 0, 0);
    }

    hook_lock = 1;
    int blocked = is_path_blocked(AT_FDCWD, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_execve) {
        return real_execve(pathname, argv, envp);
    }
    return (int)raw_syscall(SYS_execve, (long)pathname, (long)argv, (long)envp, 0, 0, 0);
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    if (hook_lock) {
        if (real_readlink) {
            return real_readlink(pathname, buf, bufsiz);
        }
#ifdef SYS_readlink
        return (ssize_t)raw_syscall(SYS_readlink, (long)pathname, (long)buf, (long)bufsiz, 0, 0, 0);
#else
        return (ssize_t)raw_syscall(SYS_readlinkat, AT_FDCWD, (long)pathname, (long)buf, (long)bufsiz, 0, 0);
#endif
    }

    hook_lock = 1;
    int blocked = is_path_blocked(AT_FDCWD, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_readlink) {
        return real_readlink(pathname, buf, bufsiz);
    }
#ifdef SYS_readlink
    return (ssize_t)raw_syscall(SYS_readlink, (long)pathname, (long)buf, (long)bufsiz, 0, 0, 0);
#else
    return (ssize_t)raw_syscall(SYS_readlinkat, AT_FDCWD, (long)pathname, (long)buf, (long)bufsiz, 0, 0);
#endif
}

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    if (hook_lock) {
        if (real_readlinkat) {
            return real_readlinkat(dirfd, pathname, buf, bufsiz);
        }
        return (ssize_t)raw_syscall(SYS_readlinkat, (long)dirfd, (long)pathname, (long)buf, (long)bufsiz, 0, 0);
    }

    hook_lock = 1;
    int blocked = is_path_blocked(dirfd, pathname);
    hook_lock = 0;

    if (blocked) {
        errno = EACCES;
        return -1;
    }

    init_hooks();
    if (real_readlinkat) {
        return real_readlinkat(dirfd, pathname, buf, bufsiz);
    }
    return (ssize_t)raw_syscall(SYS_readlinkat, (long)dirfd, (long)pathname, (long)buf, (long)bufsiz, 0, 0);
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

    if (hook_lock) {
        if (real_syscall) {
            return real_syscall(number, a1, a2, a3, a4, a5, a6);
        }
        return raw_syscall(number, a1, a2, a3, a4, a5, a6);
    }

    int blocked = 0;
#ifdef SYS_open
    if (number == SYS_open) {
        const char *pathname = (const char *)a1;
        hook_lock = 1;
        blocked = pathname && is_path_blocked(AT_FDCWD, pathname);
        hook_lock = 0;
        if (blocked) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_openat
    if (number == SYS_openat) {
        int dirfd = (int)a1;
        const char *pathname = (const char *)a2;
        hook_lock = 1;
        blocked = pathname && is_path_blocked(dirfd, pathname);
        hook_lock = 0;
        if (blocked) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_openat2
    if (number == SYS_openat2) {
        int dirfd = (int)a1;
        const char *pathname = (const char *)a2;
        hook_lock = 1;
        blocked = pathname && is_path_blocked(dirfd, pathname);
        hook_lock = 0;
        if (blocked) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_readlink
    if (number == SYS_readlink) {
        const char *pathname = (const char *)a1;
        hook_lock = 1;
        blocked = pathname && is_path_blocked(AT_FDCWD, pathname);
        hook_lock = 0;
        if (blocked) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_readlinkat
    if (number == SYS_readlinkat) {
        int dirfd = (int)a1;
        const char *pathname = (const char *)a2;
        hook_lock = 1;
        blocked = pathname && is_path_blocked(dirfd, pathname);
        hook_lock = 0;
        if (blocked) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_stat
    if (number == SYS_stat) {
        const char *pathname = (const char *)a1;
        hook_lock = 1;
        blocked = pathname && is_path_blocked(AT_FDCWD, pathname);
        hook_lock = 0;
        if (blocked) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_lstat
    if (number == SYS_lstat) {
        const char *pathname = (const char *)a1;
        hook_lock = 1;
        blocked = pathname && is_path_blocked(AT_FDCWD, pathname);
        hook_lock = 0;
        if (blocked) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_newfstatat
    if (number == SYS_newfstatat) {
        int dirfd = (int)a1;
        const char *pathname = (const char *)a2;
        hook_lock = 1;
        blocked = pathname && is_path_blocked(dirfd, pathname);
        hook_lock = 0;
        if (blocked) { errno = EACCES; return -1; }
    }
#endif

#ifdef SYS_statx
    if (number == SYS_statx) {
        int dirfd = (int)a1;
        const char *pathname = (const char *)a2;
        hook_lock = 1;
        blocked = pathname && is_path_blocked(dirfd, pathname);
        hook_lock = 0;
        if (blocked) { errno = EACCES; return -1; }
    }
#endif

    init_hooks();
    if (!real_syscall) {
        return raw_syscall(number, a1, a2, a3, a4, a5, a6);
    }
    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}