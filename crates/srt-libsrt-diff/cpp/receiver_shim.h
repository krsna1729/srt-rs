/*
 * C ABI of the libsrt 1.5.7 receive-side oracle used by srt-libsrt-diff.
 *
 * One handle owns a real CUnitQueue, CRcvBuffer and CRcvLossList plus the
 * two pieces of CUDT state the buffer does not own (the highest received
 * sequence and the TLPKTDROP switch). Every entry point takes the current
 * time explicitly in microseconds since the synthetic epoch, so nothing here
 * reads a clock or starts a thread. A handle is single-thread-owned.
 *
 * Every function returns SRT_DIFF_OK or a negative SRT_DIFF_E_* code; native
 * libsrt outcomes travel in out-parameters so they never mix with ABI errors.
 * No C++ exception crosses this boundary.
 */
#ifndef SRT_LIBSRT_DIFF_RECEIVER_SHIM_H
#define SRT_LIBSRT_DIFF_RECEIVER_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SRT_DIFF_OK 0
#define SRT_DIFF_E_ARG (-1)
#define SRT_DIFF_E_EXCEPTION (-2)
#define SRT_DIFF_E_CAPACITY (-3)

/* Insert outcomes, mirroring CUDT::handleSocketPacketReception. */
#define SRT_DIFF_INSERT_ACCEPTED 0
/* CRcvBuffer::insert returned -1: the position already holds a packet. */
#define SRT_DIFF_INSERT_DUPLICATE 1
/* bufidx < 0: behind the buffer start (core.cpp:10763). */
#define SRT_DIFF_INSERT_BELATED 2
/* bufidx >= capacity with data still buffered (core.cpp:10807-10815). */
#define SRT_DIFF_INSERT_NO_ROOM 3
/* bufidx >= capacity on an empty live buffer: libsrt closes (core.cpp:10781-10805). */
#define SRT_DIFF_INSERT_DISCREPANCY 4

typedef struct SrtDiffRx SrtDiffRx;

typedef struct {
    uint32_t first;
    uint32_t last;
} SrtDiffRange;

typedef struct {
    uint32_t seq;
    uint32_t msgno;
    uint32_t timestamp;
    /* PB bits as on the wire: 3 = SOLO, 2 = FIRST, 0 = MIDDLE, 1 = LAST. */
    uint8_t boundary;
    uint8_t inorder;
    uint8_t retransmitted;
    uint8_t reserved;
} SrtDiffPacket;

typedef struct {
    /* Usable packet capacity; the ring is built with one extra slot. */
    uint32_t capacity;
    uint32_t initial_seq;
    uint32_t payload_limit;
    uint16_t latency_ms;
    uint8_t tlpktdrop;
    uint8_t reserved;
    /* TSBPD time base, microseconds since the synthetic epoch. */
    int64_t time_base_us;
} SrtDiffConfig;

typedef struct {
    uint32_t missing;
    uint32_t discarded;
    uint8_t changed;
    uint8_t reserved[3];
    /* Inclusive; valid only when changed. */
    SrtDiffRange range;
} SrtDiffDrop;

typedef struct {
    uint32_t seq;
    uint32_t msgno;
    /* Absolute TSBPD play time of the message (SRT_MSGCTRL::srctime). */
    int64_t play_time_us;
    size_t len;
} SrtDiffDelivered;

int32_t srt_diff_create(const SrtDiffConfig* config, SrtDiffRx** out);
void srt_diff_destroy(SrtDiffRx* rx);

int32_t srt_diff_insert(SrtDiffRx* rx, const SrtDiffPacket* packet, const uint8_t* payload,
                        size_t len, int32_t* outcome);
int32_t srt_diff_ready(SrtDiffRx* rx, int64_t now_us, uint8_t* ready);
int32_t srt_diff_read(SrtDiffRx* rx, int64_t now_us, uint8_t* buffer, size_t capacity,
                      SrtDiffDelivered* delivered, uint8_t* present);
int32_t srt_diff_service(SrtDiffRx* rx, int64_t now_us, SrtDiffDrop* drop);
int32_t srt_diff_ack_seq(SrtDiffRx* rx, uint32_t* ack_seq);
int32_t srt_diff_losses(SrtDiffRx* rx, SrtDiffRange* ranges, size_t capacity, size_t* needed);

#ifdef __cplusplus
}
#endif

#endif
