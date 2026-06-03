#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_connect) {
        real_connect = dlsym(RTLD_NEXT, "connect");
    }

    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        struct in_addr proxy_addr;
        
        const char *env_ip = getenv("MESH_PROXY_IP");
        const char *proxy_ip_str = env_ip ? env_ip : "172.20.0.53";

        if (inet_pton(AF_INET, proxy_ip_str, &proxy_addr) == 1) {
            if (sin->sin_addr.s_addr != proxy_addr.s_addr && 
                sin->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                struct sockaddr_in proxy_sockaddr = *sin;
                proxy_sockaddr.sin_addr = proxy_addr;
                proxy_sockaddr.sin_port = (sin->sin_port == htons(443)) ? htons(443) : htons(80);
                return real_connect(sockfd, (struct sockaddr *)&proxy_sockaddr, addrlen);
            }
        }
    }

    return real_connect(sockfd, addr, addrlen);
}