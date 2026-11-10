// Public-API encrypted caller: send immediately after connect, then receive
// the Rust listener's independently keyed reverse DATA on the same socket.
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <srt/srt.h>

static int fail(const char* operation) {
    fprintf(stderr, "%s: %s\n", operation, srt_getlasterror_str());
    return 1;
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    if (srt_startup() == SRT_ERROR) return fail("srt_startup");
    SRTSOCKET socket = srt_create_socket();
    if (socket == SRT_INVALID_SOCK) return fail("srt_create_socket");
    const char secret[] = "interop-passphrase";
    const char payload[] = "bidirectional encrypted payload";
    int key_length = 16;
    int timeout = 5000;
    if (srt_setsockflag(socket, SRTO_PASSPHRASE, secret, (int)strlen(secret)) == SRT_ERROR ||
        srt_setsockflag(socket, SRTO_PBKEYLEN, &key_length, sizeof(key_length)) == SRT_ERROR ||
        srt_setsockflag(socket, SRTO_RCVTIMEO, &timeout, sizeof(timeout)) == SRT_ERROR ||
        srt_setsockflag(socket, SRTO_SNDTIMEO, &timeout, sizeof(timeout)) == SRT_ERROR)
        return fail("srt_setsockflag");
    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons((unsigned short)strtoul(argv[1], NULL, 10));
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (srt_connect(socket, (struct sockaddr*)&peer, sizeof(peer)) == SRT_ERROR)
        return fail("srt_connect");
    if (srt_sendmsg(socket, payload, (int)sizeof(payload) - 1, -1, 0) != (int)sizeof(payload) - 1)
        return fail("srt_sendmsg");
    char received[1500];
    int size = srt_recvmsg(socket, received, sizeof(received));
    if (size != (int)sizeof(payload) - 1 || memcmp(received, payload, sizeof(payload) - 1) != 0) {
        fprintf(stderr, "reverse DATA mismatch, size=%d: %s\n", size, srt_getlasterror_str());
        return 1;
    }
    if (fwrite(received, 1, (size_t)size, stdout) != (size_t)size) return 1;
    // Let receiver ACKs and the peer's TSBPD delivery complete before close.
    usleep(300 * 1000);
    srt_close(socket);
    srt_cleanup();
    return 0;
}
