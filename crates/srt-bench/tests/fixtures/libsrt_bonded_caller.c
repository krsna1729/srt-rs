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

static void report_legs(SRTSOCKET group, const char* when) {
    SRT_SOCKGROUPDATA members[2];
    size_t count = 2;
    if (srt_group_data(group, members, &count) == SRT_ERROR) return;
    for (size_t leg = 0; leg < count && leg < 2; ++leg) {
        fprintf(stderr, "leg %s [%zu]: id=%d sockstate=%d memberstate=%d weight=%d result=%d\n",
                when, leg, (int)members[leg].id, (int)members[leg].sockstate,
                (int)members[leg].memberstate, (int)members[leg].weight, members[leg].result);
    }
}

// Connect results arrive asynchronously; a leg rejected because it answered
// from a different receiving group reports SRT_REJ_GROUP here.
static volatile int group_collisions = 0;

static void on_connect_result(void* opaque, SRTSOCKET socket, int error_code,
                              const struct sockaddr* peer, int token) {
    (void)opaque;
    (void)peer;
    (void)token;
    if (error_code != 0 && srt_getrejectreason(socket) == SRT_REJ_GROUP) {
        ++group_collisions;
    }
}

static int fail(const char* operation) {
    fprintf(stderr, "%s: %s\n", operation, srt_getlasterror_str());
    return 1;
}

int main(int argc, char** argv) {
    // Two forms: `<ipv4> <port>` bonds both legs to one listener; `<ipv4> <port>
    // <ipv4> <port>` bonds one leg to each of two independent listeners.
    if (argc != 3 && argc != 5) {
        fprintf(stderr, "usage: %s <ipv4> <port> [<ipv4> <port>]\n", argv[0]);
        return 2;
    }

    if (srt_startup() == SRT_ERROR) {
        return fail("srt_startup");
    }

    struct sockaddr_in peers[2] = {{0}, {0}};
    for (int leg = 0; leg < 2; ++leg) {
        // With three arguments the second leg reuses the first endpoint.
        int arg = (argc == 5 && leg == 1) ? 3 : 1;
        peers[leg].sin_family = AF_INET;
        peers[leg].sin_port = htons((unsigned short)strtoul(argv[arg + 1], NULL, 10));
        if (inet_pton(AF_INET, argv[arg], &peers[leg].sin_addr) != 1) {
            fprintf(stderr, "invalid IPv4 address: %s\n", argv[arg]);
            srt_cleanup();
            return 2;
        }
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

    srt_connect_callback(group, on_connect_result, NULL);
    SRT_SOCKGROUPCONFIG endpoints[2];
    endpoints[0] = srt_prepare_endpoint(NULL, (struct sockaddr*)&peers[0], sizeof(peers[0]));
    endpoints[1] = srt_prepare_endpoint(NULL, (struct sockaddr*)&peers[1], sizeof(peers[1]));
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
        // A leg answered by a different receiving group is rejected by libsrt
        // with SRT_REJ_GROUP ("group settings collision"). Report it through a
        // dedicated exit code so callers can tell a bond that spans receivers
        // from a leg that was merely unreachable.
        int collided = group_collisions;
        report_legs(group, "failed");
        srt_close(group);
        srt_cleanup();
        return collided ? 3 : 1;
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

    report_legs(group, "after-send");
    // Let both legs' sender buffers drain (the peers ACK) before closing.
    for (int attempt = 0; attempt < 200; ++attempt) {
        int pending = 0;
        SRT_SOCKGROUPDATA legs[2];
        size_t count = 2;
        if (srt_group_data(group, legs, &count) == SRT_ERROR) break;
        for (size_t leg = 0; leg < count; ++leg) {
            int bytes = 0, len = sizeof(bytes);
            if (srt_getsockflag(legs[leg].id, SRTO_SNDDATA, &bytes, &len) != SRT_ERROR) pending += bytes;
        }
        if (pending == 0) break;
        usleep(10 * 1000);
    }
    report_legs(group, "drained");
    usleep(100 * 1000);
    srt_close(group);
    srt_cleanup();
    return 0;
}
