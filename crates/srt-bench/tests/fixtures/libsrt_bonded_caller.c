// Minimal black-box libsrt broadcast-group caller for Rust interop tests.
// It deliberately uses only the public C API: create a two-member group,
// wait for both links, then send one logical message through the group.
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
    if (argc != 3) {
        fprintf(stderr, "usage: %s <ipv4-address> <port>\n", argv[0]);
        return 2;
    }

    if (srt_startup() == SRT_ERROR) {
        return fail("srt_startup");
    }

    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons((unsigned short)strtoul(argv[2], NULL, 10));
    if (inet_pton(AF_INET, argv[1], &peer.sin_addr) != 1) {
        fprintf(stderr, "invalid IPv4 address: %s\n", argv[1]);
        srt_cleanup();
        return 2;
    }

    SRTSOCKET group = srt_create_group(SRT_GTYPE_BROADCAST);
    if (group == SRT_INVALID_SOCK) {
        int error_code = srt_getlasterror(NULL);
        // Debian's standard libsrt package exposes the group declarations but
        // compiles the implementation out. That path returns no SRT error.
        // Reserve the conventional "feature unavailable" exit code so the
        // Rust harness can skip only that known local limitation.
        if (error_code == 0) {
            fprintf(stderr, "libsrt was built without bonding support\n");
            srt_cleanup();
            return 77;
        }
        int result = fail("srt_create_group");
        srt_cleanup();
        return result;
    }

    SRT_SOCKGROUPCONFIG endpoints[2];
    endpoints[0] = srt_prepare_endpoint(NULL, (struct sockaddr*)&peer, sizeof(peer));
    endpoints[1] = srt_prepare_endpoint(NULL, (struct sockaddr*)&peer, sizeof(peer));
    if (srt_connect_group(group, endpoints, 2) == SRT_ERROR) {
        int result = fail("srt_connect_group");
        srt_close(group);
        srt_cleanup();
        return result;
    }

    SRT_SOCKGROUPDATA members[2];
    int connected = 0;
    for (int attempt = 0; attempt < 150; ++attempt) {
        size_t count = 2;
        if (srt_group_data(group, members, &count) == SRT_ERROR) {
            int result = fail("srt_group_data");
            srt_close(group);
            srt_cleanup();
            return result;
        }
        connected = 0;
        for (size_t index = 0; index < count; ++index) {
            if (members[index].sockstate == SRTS_CONNECTED) {
                ++connected;
            }
        }
        if (connected == 2) {
            break;
        }
        usleep(20 * 1000);
    }
    if (connected != 2) {
        fprintf(stderr, "only %d/2 broadcast group members connected\n", connected);
        srt_close(group);
        srt_cleanup();
        return 1;
    }

    static const char payload[] = "libsrt-bonded-group-payload";
    SRT_MSGCTRL message = srt_msgctrl_default;
    message.grpdata = members;
    message.grpdata_size = 2;
    if (srt_sendmsg2(group, payload, (int)sizeof(payload) - 1, &message) == SRT_ERROR) {
        int result = fail("srt_sendmsg2");
        srt_close(group);
        srt_cleanup();
        return result;
    }
    if (message.grpdata_size != 2 || message.grpdata[0].result == SRT_ERROR ||
        message.grpdata[1].result == SRT_ERROR) {
        fprintf(stderr, "broadcast send did not use both group members\n");
        srt_close(group);
        srt_cleanup();
        return 1;
    }

    usleep(100 * 1000);
    srt_close(group);
    srt_cleanup();
    return 0;
}
