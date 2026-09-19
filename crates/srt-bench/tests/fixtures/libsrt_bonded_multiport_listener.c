// libsrt listener for ONE receiving group reachable at TWO listening
// endpoints (two UDP ports of one process). This is the topology libsrt
// bonding actually supports across different network paths: both legs land
// in the same mirror group because the same libsrt instance answers them.
// Contrast with two independent listener processes, which libsrt rejects.
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <srt/srt.h>

static int fail(const char* operation) {
    fprintf(stderr, "%s: %s\n", operation, srt_getlasterror_str());
    return 1;
}

static SRTSOCKET listen_on(unsigned short port) {
    SRTSOCKET listener = srt_create_socket();
    if (listener == SRT_INVALID_SOCK) return SRT_INVALID_SOCK;
    int yes = 1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (srt_setsockflag(listener, SRTO_GROUPCONNECT, &yes, sizeof(yes)) == SRT_ERROR ||
        srt_bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == SRT_ERROR ||
        srt_listen(listener, 2) == SRT_ERROR) {
        return SRT_INVALID_SOCK;
    }
    return listener;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <port-a> <port-b>\n", argv[0]);
        return 2;
    }
    if (srt_startup() == SRT_ERROR) return fail("srt_startup");

    SRTSOCKET probe = srt_create_group(SRT_GTYPE_BROADCAST);
    if (probe == SRT_INVALID_SOCK) {
        int error_code = srt_getlasterror(NULL);
        if (error_code == 0) {
            fprintf(stderr, "libsrt was built without bonding support\n");
            srt_cleanup();
            return 77;
        }
        int result = fail("srt_create_group");
        srt_cleanup();
        return result;
    }
    srt_close(probe);

    SRTSOCKET a = listen_on((unsigned short)strtoul(argv[1], NULL, 10));
    SRTSOCKET b = listen_on((unsigned short)strtoul(argv[2], NULL, 10));
    if (a == SRT_INVALID_SOCK || b == SRT_INVALID_SOCK) {
        int result = fail("listen");
        srt_cleanup();
        return result;
    }

    // The first leg can arrive on either endpoint, so accept from whichever
    // becomes readable first. The second leg joins the same mirror group in
    // the background.
    int epoll = srt_epoll_create();
    int events = SRT_EPOLL_IN;
    srt_epoll_add_usock(epoll, a, &events);
    srt_epoll_add_usock(epoll, b, &events);
    SRTSOCKET group = SRT_INVALID_SOCK;
    for (int attempt = 0; attempt < 1500 && group == SRT_INVALID_SOCK; ++attempt) {
        SRT_EPOLL_EVENT ready[2];
        int count = srt_epoll_uwait(epoll, ready, 2, 10);
        if (count > 0) group = srt_accept(ready[0].fd, NULL, NULL);
    }
    if (group == SRT_INVALID_SOCK || (group & SRTGROUP_MASK) == 0) {
        fprintf(stderr, "no bonded group was accepted\n");
        srt_cleanup();
        return 1;
    }
    int no = 0;
    srt_setsockflag(group, SRTO_RCVSYN, &no, sizeof(no));

    int connected = 0;
    for (int attempt = 0; attempt < 1500 && !connected; ++attempt) {
        SRT_SOCKGROUPDATA members[2];
        size_t count = 2;
        if (srt_group_data(group, members, &count) != SRT_ERROR && count == 2 &&
            members[0].sockstate == SRTS_CONNECTED && members[1].sockstate == SRTS_CONNECTED) {
            connected = 1;
        } else {
            usleep(10 * 1000);
        }
    }
    if (!connected) {
        fprintf(stderr, "the receiving group never gained both endpoints' legs\n");
        srt_cleanup();
        return 1;
    }

    char payload[SRT_LIVE_MAX_PLSIZE];
    for (int attempt = 0; attempt < 1500; ++attempt) {
        SRT_SOCKGROUPDATA members[2];
        SRT_MSGCTRL control = srt_msgctrl_default;
        control.grpdata = members;
        control.grpdata_size = 2;
        int length = srt_recvmsg2(group, payload, SRT_LIVE_MAX_PLSIZE, &control);
        if (length > 0) {
            fwrite(payload, 1, (size_t)length, stdout);
            srt_close(group);
            srt_cleanup();
            return 0;
        }
        if (srt_getlasterror(NULL) != SRT_EASYNCRCV) break;
        usleep(10 * 1000);
    }
    fprintf(stderr, "no payload received: %s\n", srt_getlasterror_str());
    srt_cleanup();
    return 1;
}
