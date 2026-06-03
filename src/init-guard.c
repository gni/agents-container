#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>

void copy_secure_token(const char *src_dir, const char *filename, const char *dst_dir) {
    char src_path[512], dst_path[512];
    snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, filename);
    snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, filename);

    int fd_in = open(src_path, O_RDONLY);
    if (fd_in < 0) return;

    int fd_out = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0400);
    if (fd_out < 0) { 
        close(fd_in); 
        return; 
    }

    char buf[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(fd_in, buf, sizeof(buf))) > 0) {
        if (write(fd_out, buf, bytes_read) != bytes_read) {
            break;
        }
    }
    
    close(fd_in);
    close(fd_out);
    chown(dst_path, 0, 0);
}

int validate_process_chain(pid_t client_pid, int is_git_helper) {
    pid_t cur_pid = client_pid;
    int legit_git_op = 0;
    
    while (cur_pid > 1) {
        char exe_link[128];
        char exe_path[512];
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", cur_pid);
        ssize_t len = readlink(exe_link, exe_path, sizeof(exe_path)-1);
        if (len == -1) {
            break;
        }
        exe_path[len] = '\0';
        
        int allowed = 0;
        if (strcmp(exe_path, "/usr/bin/git") == 0 ||
            strcmp(exe_path, "/usr/local/bin/git") == 0 ||
            strstr(exe_path, "/git-core/git") != NULL ||
            strcmp(exe_path, "/usr/bin/bash") == 0 ||
            strcmp(exe_path, "/bin/bash") == 0 ||
            strcmp(exe_path, "/usr/bin/sh") == 0 ||
            strcmp(exe_path, "/bin/sh") == 0 ||
            strcmp(exe_path, "/usr/bin/dash") == 0 ||
            strcmp(exe_path, "/bin/dash") == 0 ||
            strcmp(exe_path, "/usr/bin/gh-original") == 0 ||
            strcmp(exe_path, "/usr/local/bin/vault-wrapper") == 0 ||
            strcmp(exe_path, "/usr/bin/node") == 0 ||
            strcmp(exe_path, "/usr/local/bin/node") == 0) {
            allowed = 1;
        }
        
        if (!allowed) {
            return 0;
        }
        
        // If bash/sh/dash, check cmdline for metacharacters
        if (strcmp(exe_path, "/usr/bin/bash") == 0 ||
            strcmp(exe_path, "/bin/bash") == 0 ||
            strcmp(exe_path, "/usr/bin/sh") == 0 ||
            strcmp(exe_path, "/bin/sh") == 0 ||
            strcmp(exe_path, "/usr/bin/dash") == 0 ||
            strcmp(exe_path, "/bin/dash") == 0) {
            char cmdline_path[128];
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", cur_pid);
            FILE *f = fopen(cmdline_path, "r");
            if (f) {
                char cmdline[1024];
                size_t n = fread(cmdline, 1, sizeof(cmdline)-1, f);
                fclose(f);
                if (n > 0) {
                    cmdline[n] = '\0';
                    for (size_t i = 0; i < n; i++) {
                        char c = cmdline[i];
                        if (c == ',' || c == '<' || c == '>' || c == '|' || c == '&' || c == ';') {
                            return 0;
                        }
                    }
                }
            }
        }
        
        // If git, check if command is push/pull/fetch/clone/ls-remote/submodule/remote-https
        if (strcmp(exe_path, "/usr/bin/git") == 0 ||
            strcmp(exe_path, "/usr/local/bin/git") == 0 ||
            strstr(exe_path, "/git-core/git") != NULL) {
            char cmdline_path[128];
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", cur_pid);
            FILE *f = fopen(cmdline_path, "r");
            if (f) {
                char cmdline[2048];
                size_t n = fread(cmdline, 1, sizeof(cmdline)-1, f);
                fclose(f);
                if (n > 0) {
                    cmdline[n] = '\0';
                    char *ptr = cmdline;
                    while (ptr < cmdline + n) {
                        if (strcmp(ptr, "push") == 0 ||
                            strcmp(ptr, "pull") == 0 ||
                            strcmp(ptr, "fetch") == 0 ||
                            strcmp(ptr, "clone") == 0 ||
                            strcmp(ptr, "ls-remote") == 0 ||
                            strcmp(ptr, "submodule") == 0 ||
                            strcmp(ptr, "remote-https") == 0) {
                            legit_git_op = 1;
                            break;
                        }
                        ptr += strlen(ptr) + 1;
                    }
                }
            }
        }
        
        char stat_path[128];
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", cur_pid);
        FILE *sf = fopen(stat_path, "r");
        if (!sf) break;
        pid_t ppid = 0;
        char buf[1024];
        if (fgets(buf, sizeof(buf), sf)) {
            char *last_paren = strrchr(buf, ')');
            if (last_paren) {
                char state;
                if (sscanf(last_paren + 2, "%c %d", &state, &ppid) != 2) {
                    ppid = 0;
                }
            }
        }
        fclose(sf);
        
        if (ppid <= 0 || ppid == cur_pid) break;
        cur_pid = ppid;
    }
    
    if (is_git_helper) {
        return legit_git_op;
    }
    return 1;
}

void run_vault_daemon() {
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/vault/vault.sock", sizeof(addr.sun_path) - 1);

    unlink("/vault/vault.sock");

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return;
    }

    if (listen(server_fd, 10) < 0) {
        close(server_fd);
        return;
    }

    chmod("/vault/vault.sock", 0666);

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        struct ucred ucred;
        socklen_t len = sizeof(struct ucred);
        if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0) {
            close(client_fd);
            continue;
        }

        char request[64];
        memset(request, 0, sizeof(request));
        ssize_t n = read(client_fd, request, sizeof(request) - 1);
        if (n <= 0) {
            close(client_fd);
            continue;
        }

        int is_gh = (strncmp(request, "gh", 2) == 0);
        int is_gl = (strncmp(request, "gl", 2) == 0);
        int is_git = (strstr(request, ":git") != NULL);

        if (!is_gh && !is_gl) {
            close(client_fd);
            continue;
        }

        if (!validate_process_chain(ucred.pid, is_git)) {
            close(client_fd);
            continue;
        }

        char token[512];
        memset(token, 0, sizeof(token));
        int found = 0;

        DIR *d = opendir("/vault");
        if (d) {
            struct dirent *dir;
            while ((dir = readdir(d)) != NULL) {
                if ((is_gh && strncmp(dir->d_name, "gh_", 3) == 0) ||
                    (is_gl && strncmp(dir->d_name, "gl_", 3) == 0)) {
                    char path[512];
                    snprintf(path, sizeof(path), "/vault/%s", dir->d_name);
                    FILE *f = fopen(path, "r");
                    if (f) {
                        if (fgets(token, sizeof(token), f)) {
                            token[strcspn(token, "\r\n")] = 0;
                            found = 1;
                        }
                        fclose(f);
                    }
                    break;
                }
            }
            closedir(d);
        }

        if (found) {
            write(client_fd, token, strlen(token));
        }
        close(client_fd);
    }
}

int main(int argc, char **argv) {
    mkdir("/vault", 0711);
    chmod("/vault", 0711);
    chown("/vault", 0, 0);

    // Import custom CA certificates if they exist
    if (access("/usr/local/share/ca-certificates/custom", F_OK) == 0) {
        int res = system("update-ca-certificates 2>/dev/null || true");
        (void)res;
        setenv("NODE_EXTRA_CA_CERTS", "/etc/ssl/certs/ca-certificates.crt", 1);
        setenv("REQUESTS_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt", 1);
        setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt", 1);
    }

    DIR *d = opendir("/run/secrets");
    if (d) {
        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            if (strncmp(dir->d_name, "gh_", 3) == 0 || strncmp(dir->d_name, "gl_", 3) == 0) {
                copy_secure_token("/run/secrets", dir->d_name, "/vault");
            }
        }
        closedir(d);
    }

    chmod("/run/secrets", 0000);

    uid_t target_uid = 1000;
    gid_t target_gid = 1000;
    
    char *env_uid = getenv("HOST_UID");
    char *env_gid = getenv("HOST_GID");
    
    if (env_uid) target_uid = atoi(env_uid);
    if (env_gid) target_gid = atoi(env_gid);

    if (target_uid == 0) target_uid = 1000;
    if (target_gid == 0) target_gid = 1000;

    // Start background vault daemon as root before dropping privileges
    pid_t daemon_pid = fork();
    if (daemon_pid == 0) {
        close(0);
        close(1);
        close(2);
        run_vault_daemon();
        exit(0);
    }

    // Fix ownership of home directory and workspace before dropping privileges
    char chown_cmd[512];
    snprintf(chown_cmd, sizeof(chown_cmd), "chown -R %d:%d /home/node /workspace 2>/dev/null", target_uid, target_gid);
    int chown_res = system(chown_cmd);
    (void)chown_res;

    if (setgroups(1, &target_gid) != 0) return 1;
    if (setresgid(target_gid, target_gid, target_gid) != 0) return 1;
    if (setresuid(target_uid, target_uid, target_uid) != 0) return 1;

    if (argc > 1) {
        execvp(argv[1], &argv[1]);
    }
    return 1;
}