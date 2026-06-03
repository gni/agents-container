#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>

int main(int argc, char **argv) {
    uid_t uid = getuid();
    gid_t gid = getgid();

    char *base = strrchr(argv[0], '/');
    base = base ? base + 1 : argv[0];

    int is_gh = (strcmp(base, "gh") == 0);
    int is_gl = (strcmp(base, "glab") == 0);

    // Try setuid(0) but do not exit if it fails (e.g., under gVisor)
    setuid(0);

    int pfd[2];
    if (pipe(pfd) == -1) return 1;

    // Connect to the vault daemon socket
    int client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_fd >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/vault/vault.sock", sizeof(addr.sun_path) - 1);

        if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) >= 0) {
            // Determine if this is a git credential helper invocation
            int is_git = 0;
            for (int i = 1; i < argc; i++) {
                if (strcmp(argv[i], "git-credential") == 0) {
                    is_git = 1;
                    break;
                }
            }

            char req[32];
            snprintf(req, sizeof(req), "%s:%s", is_gh ? "gh" : "gl", is_git ? "git" : "direct");
            write(client_fd, req, strlen(req));

            char token[512];
            memset(token, 0, sizeof(token));
            ssize_t n = read(client_fd, token, sizeof(token) - 1);
            if (n > 0) {
                token[strcspn(token, "\r\n")] = 0;
                write(pfd[1], token, strlen(token));
            }
        }
        close(client_fd);
    }
    
    close(pfd[1]);

    // Drop privileges if we had them
    setresgid(gid, gid, gid);
    setresuid(uid, uid, uid);

    prctl(PR_SET_DUMPABLE, 0);

    if (is_gh) {
        char fd_str[16];
        snprintf(fd_str, sizeof(fd_str), "%d", pfd[0]);
        setenv("VAULT_FD", fd_str, 1);
        argv[0] = "/usr/local/bin/gh-guard";
        execv("/usr/local/bin/gh-guard", argv);
    } else if (is_gl) {
        char fd_str[16];
        snprintf(fd_str, sizeof(fd_str), "%d", pfd[0]);
        setenv("VAULT_FD", fd_str, 1);
        argv[0] = "/usr/local/bin/glab-guard";
        execv("/usr/local/bin/glab-guard", argv);
    }
    
    return 1;
}