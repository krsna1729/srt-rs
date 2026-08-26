// Minimal black-box libsrt listener for Rust broadcast-group interop tests.
// srt-live-transmit deliberately closes its listener socket after one accept,
// so only this public-C-API fixture can receive both group legs.
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

static void report_members(SRTSOCKET group) {
    SRT_SOCKGROUPDATA members[2];
    size_t count = 2;
    if (srt_group_data(group, members, &count) == SRT_ERROR) {
        fprintf(stderr, "unable to report group members: %s\n", srt_getlasterror_str());
        return;
    }
    fprintf(stderr, "bonded receive member states (%zu):", count);
    for (size_t index = 0; index < count && index < 2; ++index) {
        fprintf(stderr, " [%zu: socket=%d group=%d result=%d]", index,
                (int)members[index].sockstate, (int)members[index].memberstate,
                members[index].result);
    }
    fputc('\n', stderr);
}

static int recv_payload(SRTSOCKET group, char* target) {
    // The accepted mirror group gains later physical members asynchronously.
    // Allow a bounded 15-second delivery window for a loaded CI runner to
    // finish that attachment before declaring the logical stream absent.
    for (int attempt = 0; attempt < 1500; ++attempt) {
        SRT_SOCKGROUPDATA members[2];
        SRT_MSGCTRL control = srt_msgctrl_default;
        // A group receive reports the state of every physical member through
        // this caller-provided array. Supplying it also makes this test prove
        // that both legs remained usable for the logical receive.
        control.grpdata = members;
        control.grpdata_size = 2;
        int length = srt_recvmsg2(group, target, SRT_LIVE_MAX_PLSIZE, &control);
        if (length > 0) {
            if (control.grpdata_size != 2 || members[0].result == SRT_ERROR ||
                members[1].result == SRT_ERROR) {
                fprintf(stderr, "bonded receive did not retain both group members\n");
                return -1;
            }
            return length;
        }
        // srt_getlasterror returns the SRT error code. Its optional out
        // parameter is the unrelated OS errno, which must not be compared
        // with SRT_EASYNCRCV.
        int error_code = srt_getlasterror(NULL);
        if (error_code != SRT_EASYNCRCV) return -1;
        usleep(10 * 1000);
    }
    return -1;
}

static int wait_for_two_connected_members(SRTSOCKET group) {
    for (int attempt = 0; attempt < 1500; ++attempt) {
        SRT_SOCKGROUPDATA members[2];
        size_t count = 2;
        if (srt_group_data(group, members, &count) == SRT_ERROR) return -1;
        if (count == 2 && members[0].sockstate == SRTS_CONNECTED &&
            members[1].sockstate == SRTS_CONNECTED) return 0;
        usleep(10 * 1000);
    }
    return -2;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 2;
    }
    if (srt_startup() == SRT_ERROR) return fail("srt_startup");

    // Debian's regular package exposes the group declarations while compiling
    // the implementation out. Detect that before binding so the Rust harness
    // can distinguish a locally unavailable optional feature from a failure.
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

    SRTSOCKET listener = srt_create_socket();
    if (listener == SRT_INVALID_SOCK) {
        srt_cleanup();
        return fail("srt_create_socket");
    }
    int yes = 1;
    int timeout = 5000;
    if (srt_setsockflag(listener, SRTO_GROUPCONNECT, &yes, sizeof(yes)) == SRT_ERROR ||
        srt_setsockflag(listener, SRTO_RCVTIMEO, &timeout, sizeof(timeout)) == SRT_ERROR) {
        int result = fail("srt_setsockflag");
        srt_close(listener);
        srt_cleanup();
        return result;
    }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)strtoul(argv[1], NULL, 10));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (srt_bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == SRT_ERROR ||
        srt_listen(listener, 2) == SRT_ERROR) {
        int result = fail("srt_bind/listen");
        srt_close(listener);
        srt_cleanup();
        return result;
    }

    SRTSOCKET group = srt_accept(listener, NULL, NULL);
    if (group == SRT_INVALID_SOCK) {
        int result = fail("srt_accept");
        srt_close(listener);
        srt_cleanup();
        return result;
    }
    if ((group & SRTGROUP_MASK) == 0) {
        fprintf(stderr, "srt_accept returned a socket instead of a bonded group\n");
        srt_close(group);
        srt_close(listener);
        srt_cleanup();
        return 1;
    }

    // srt_accept returns after the first leg and lets libsrt attach later
    // legs in the background. A blocking group receive holds its group lock
    // while waiting, delaying that attachment. Switch only the accepted
    // group to nonblocking mode; the listening socket remains blocking for
    // the initial accept above.
    int no = 0;
    if (srt_setsockflag(group, SRTO_RCVSYN, &no, sizeof(no)) == SRT_ERROR) {
        int result = fail("srt_setsockflag(SRTO_RCVSYN)");
        srt_close(group);
        srt_close(listener);
        srt_cleanup();
        return result;
    }

    // `srt_accept` creates the mirror group after its first leg. A member can
    // appear in group metadata before its data path is connected, so wait for
    // both background links to become usable before consuming the stream.
    int member_status = wait_for_two_connected_members(group);
    if (member_status != 0) {
        int result;
        if (member_status == -1) {
            result = fail("srt_group_data");
        } else {
            fprintf(stderr, "mirror group did not connect two members\n");
            result = 1;
        }
        srt_close(group);
        srt_close(listener);
        srt_cleanup();
        return result;
    }

    // Group reads combine the two physical legs into one logical stream.
    // libsrt validates the receive buffer against the live-mode maximum
    // payload size, not against the particular packet currently queued.
    char payload[SRT_LIVE_MAX_PLSIZE];
    int payload_len = recv_payload(group, payload);
    if (payload_len <= 0) {
        report_members(group);
        int result = fail("srt_recvmsg2");
        srt_close(group);
        srt_close(listener);
        srt_cleanup();
        return result;
    }

    fwrite(payload, 1, (size_t)payload_len, stdout);
    srt_close(group);
    srt_close(listener);
    srt_cleanup();
    return 0;
}
