/*
 * libsrt 1.5.7 receive-side oracle for srt-libsrt-diff.
 *
 * CRcvBuffer, CTsbpdTime (owned by the buffer), CRcvLossList and CUnitQueue
 * are libsrt's own, compiled from LIBSRT_SRC. The few lines of CUDT that
 * connect them are mirrored below with the core.cpp anchors beside each
 * one; nothing else of CUDT is reproduced, and none of srt-rs's algorithms
 * are copied here.
 *
 * Time: every entry point receives `now` explicitly. Readiness goes through
 * CRcvBuffer::isRcvDataReady(now) and reading through readMessage, which
 * never reads a clock (buffer_rcv.cpp:393-473). readBuffer is deliberately
 * not used: it calls steady_clock::now() itself (buffer_rcv.cpp:528-553).
 *
 * Logging is compiled out (ENABLE_LOGGING undefined), so LOGC/HLOGC expand to
 * nothing (logging.h:81-95) and no logger global is touched.
 */
#include "platform_sys.h"

#include <cstring>
#include <exception>
#include <new>

#include "buffer_rcv.h"
#include "common.h"
#include "list.h"
#include "packet.h"
#include "queue.h"
#include "srt.h"
#include "sync.h"

#include "receiver_shim.h"

using srt::CPacket;
using srt::CRcvBuffer;
using srt::CRcvLossList;
using srt::CSeqNo;
using srt::CUnit;
using srt::CUnitQueue;
namespace srtsync = srt::sync;

namespace
{

typedef srtsync::steady_clock::time_point time_point;

time_point at(int64_t us)
{
    return time_point() + srtsync::microseconds_from(us);
}

const uint32_t SEQ_MASK = 0x7FFFFFFF;
const uint32_t MSGNO_MASK = 0x03FFFFFF;
/* CUnitQueue grows itself (queue.cpp:149-151); this is only the first block. */
const int UNIT_BLOCK = 128;

// The standard C++ clock commonly uses signed nanoseconds. Reject times
// before conversion, leaving room for timestamp wrap and latency arithmetic.
bool valid_time(int64_t us)
{
    const int64_t headroom = 2 * (int64_t(UINT32_MAX) + 1) + int64_t(UINT16_MAX) * 1000;
    const int64_t maximum = srtsync::count_microseconds(srtsync::steady_clock::duration::max());
    return us >= 0 && us <= maximum - headroom;
}

} // namespace

struct SrtDiffRx
{
    // Declaration order is destruction order reversed: the buffer returns
    // its units to the queue (buffer_rcv.cpp:138-148) before the queue frees
    // them (queue.cpp:86-103).
    CUnitQueue units;
    CRcvBuffer buffer;
    CRcvLossList losses;
    // CUDT::m_iRcvCurrSeqNo: highest sequence received. setInitialRcvSeq
    // starts it one before the ISN (core.cpp:5889).
    int32_t rcv_curr_seq;
    bool tlpktdrop;
    uint32_t payload_limit;

    // CUDT::prepareBuffers (core.cpp:5978-5982): the buffer starts at the
    // peer ISN, live mode uses the message API, and the loss list is sized
    // like the flight window. The ring gets one slot more than the usable
    // capacity (buffer_rcv.h:225-232, capacity() == m_szSize - 1).
    explicit SrtDiffRx(const SrtDiffConfig& c)
        : units(UNIT_BLOCK, int(c.payload_limit))
        , buffer(int32_t(c.initial_seq), size_t(c.capacity) + 1, &units, true)
        , losses(int(c.capacity))
        , rcv_curr_seq(CSeqNo::decseq(int32_t(c.initial_seq)))
        , tlpktdrop(c.tlpktdrop != 0)
        , payload_limit(c.payload_limit)
    {
        // core.cpp:9640, HSREQ: setTsbPdMode(m_tsRcvPeerStartTime, false, latency).
        buffer.setTsbPdMode(at(c.time_base_us), false, srtsync::milliseconds_from(c.latency_ms));
    }

    // CUDT::rcvDropTooLateUpTo (core.cpp:5856-5878), minus the statistics.
    void dropTooLateUpTo(int32_t seqno, SrtDiffDrop* drop)
    {
        // core.cpp:5859-5860: never drop over m_iRcvCurrSeqNo.
        if (CSeqNo::seqcmp(seqno, CSeqNo::incseq(rcv_curr_seq)) > 0)
            seqno = CSeqNo::incseq(rcv_curr_seq);

        const int32_t from = buffer.getStartSeqNo();
        // core.cpp:5862 dropFromLossLists(SRT_SEQNO_NONE, decseq(seqno)),
        // whose TLPKTDROP branch is removeUpTo (core.cpp:11555-11558).
        losses.removeUpTo(CSeqNo::decseq(seqno));

        // core.cpp:5864.
        const std::pair<int, int> counts = buffer.dropUpTo(seqno);
        if (CSeqNo::seqcmp(seqno, from) > 0)
        {
            drop->changed = 1;
            drop->range.first = uint32_t(from);
            drop->range.last = uint32_t(CSeqNo::decseq(seqno));
            drop->missing = uint32_t(counts.first);
            drop->discarded = uint32_t(counts.second);
        }
    }

    // One pass of the CUDT::tsbpd worker loop (core.cpp:5669-5703).
    void service(int64_t now_us, SrtDiffDrop* drop)
    {
        const time_point tnow = at(now_us);
        // core.cpp:5672 updRcvAvgDataSize(tnow) only feeds statistics; skipped.
        const CRcvBuffer::PacketInfo info = buffer.getFirstValidPacketInfo();
        const bool is_time_to_deliver = !srtsync::is_zero(info.tsbpd_time) && (tnow >= info.tsbpd_time);
        // core.cpp:5693-5703: with TLPKTDROP, a due first packet preceded by
        // a gap drops everything before it.
        if (tlpktdrop && is_time_to_deliver && info.seq_gap)
            dropTooLateUpTo(info.seqno, drop);
    }

    // CUDT::handleSocketPacketReception (core.cpp:10738-10972) for one
    // packet without a packet filter, followed by the loss recording of
    // CUDT::processData (core.cpp:11200-11214).
    int32_t insert(CUnit* u)
    {
        const CPacket& rpkt = u->m_Packet;
        const int32_t seq = rpkt.getSeqNo();
        const int32_t bufseq = buffer.getStartSeqNo();
        const int bufidx = CSeqNo::seqoff(bufseq, seq);

        // core.cpp:10763. The second operand, seq <% m_iRcvLastAck, is not
        // modelled: ACK transmission is not part of this oracle, and every
        // position in [start, last ACK) holds a received packet that is not
        // in the loss list, so insert() below reports it as a duplicate and
        // unlose() is a no-op for it -- the same observable outcome.
        if (bufidx < 0)
            return SRT_DIFF_INSERT_BELATED;

        // core.cpp:10778-10816.
        if (bufidx >= int(buffer.capacity()))
            return tlpktdrop && buffer.empty() ? SRT_DIFF_INSERT_DISCREPANCY : SRT_DIFF_INSERT_NO_ROOM;

        // core.cpp:10818-10828.
        const bool adding_successful = buffer.insert(u) >= 0;

        // core.cpp:10944-10956 detects the loss; processData records it
        // after the reception loop (core.cpp:11200-11214).
        bool have_loss = false;
        int32_t seqlo = 0;
        int32_t seqhi = 0;
        if (adding_successful && CSeqNo::seqcmp(seq, CSeqNo::incseq(rcv_curr_seq)) > 0)
        {
            have_loss = true;
            seqlo = CSeqNo::incseq(rcv_curr_seq);
            seqhi = CSeqNo::decseq(seq);
        }

        // core.cpp:10958-10971: advance the highest received, or unlose()
        // (core.cpp:11454-11458) a belated or retransmitted packet, whether
        // or not the buffer accepted it.
        if (CSeqNo::seqcmp(seq, rcv_curr_seq) > 0)
            rcv_curr_seq = seq;
        else
            losses.remove(seq);

        if (have_loss)
            losses.insert(seqlo, seqhi);

        return adding_successful ? SRT_DIFF_INSERT_ACCEPTED : SRT_DIFF_INSERT_DUPLICATE;
    }

    // CUDT::getFirstNoncontSequence, live TSBPD branch (core.cpp:8318-8336).
    int32_t ackSeq() const
    {
        int32_t seq = buffer.getFirstNonreadSeqNo();
        const int32_t next = CSeqNo::incseq(rcv_curr_seq);
        if (CSeqNo::seqcmp(seq, next) > 0)
            seq = next;
        return seq;
    }
};

namespace
{

bool fill_unit(CUnit* u, const SrtDiffPacket& p, const uint8_t* payload, size_t len)
{
    CPacket& pkt = u->m_Packet;
    uint32_t* h = pkt.getHeader();
    h[srt::SRT_PH_SEQNO] = p.seq & SEQ_MASK;
    // PH_MSGNO layout: PB(31-30) O(29) KK(28-27) R(26) msgno(25-0) (packet.h:136-176).
    h[srt::SRT_PH_MSGNO] = (uint32_t(p.boundary & 3) << 30) | (uint32_t(p.inorder != 0) << 29) |
                           (uint32_t(p.retransmitted != 0) << 26) | (p.msgno & MSGNO_MASK);
    h[srt::SRT_PH_TIMESTAMP] = p.timestamp;
    h[srt::SRT_PH_ID] = 0;
    if (len)
        memcpy(pkt.m_pcData, payload, len);
    pkt.setLength(len);
    return true;
}

template <class F>
int32_t guarded(F f)
{
    try
    {
        return f();
    }
    catch (const std::bad_alloc&)
    {
        return SRT_DIFF_E_CAPACITY;
    }
    catch (...)
    {
        return SRT_DIFF_E_EXCEPTION;
    }
}

} // namespace

extern "C" int32_t srt_diff_create(const SrtDiffConfig* config, SrtDiffRx** out)
{
    if (!config || !out || config->capacity == 0 || config->capacity > 65536 || config->payload_limit == 0 ||
        config->payload_limit > SRT_LIVE_MAX_PLSIZE || config->initial_seq > SEQ_MASK ||
        !valid_time(config->time_base_us))
        return SRT_DIFF_E_ARG;
    *out = NULL;
    struct Create
    {
        const SrtDiffConfig* c;
        SrtDiffRx** o;
        int32_t operator()() const
        {
            *o = new SrtDiffRx(*c);
            return SRT_DIFF_OK;
        }
    } create = {config, out};
    return guarded(create);
}

extern "C" void srt_diff_destroy(SrtDiffRx* rx)
{
    try
    {
        delete rx;
    }
    catch (...)
    {
    }
}

extern "C" int32_t srt_diff_insert(SrtDiffRx* rx, const SrtDiffPacket* packet, const uint8_t* payload,
                                   size_t len, int32_t* outcome)
{
    if (!rx || !packet || !outcome || (len && !payload) || len > rx->payload_limit || packet->seq > SEQ_MASK)
        return SRT_DIFF_E_ARG;
    struct Insert
    {
        SrtDiffRx* rx;
        const SrtDiffPacket* p;
        const uint8_t* payload;
        size_t len;
        int32_t* outcome;
        int32_t operator()() const
        {
            // The receive queue hands every datagram a free unit before
            // processData sees it (queue.cpp CRcvQueue::worker_RetrieveUnit).
            CUnit* u = rx->units.getNextAvailUnit();
            if (!u)
                return SRT_DIFF_E_CAPACITY;
            fill_unit(u, *p, payload, len);
            // A rejected unit was never taken and stays free (buffer_rcv.cpp:189-193).
            *outcome = rx->insert(u);
            return SRT_DIFF_OK;
        }
    } insert = {rx, packet, payload, len, outcome};
    return guarded(insert);
}

extern "C" int32_t srt_diff_ready(SrtDiffRx* rx, int64_t now_us, uint8_t* ready)
{
    if (!rx || !ready || !valid_time(now_us))
        return SRT_DIFF_E_ARG;
    *ready = rx->buffer.isRcvDataReady(at(now_us)) ? 1 : 0;
    return SRT_DIFF_OK;
}

extern "C" int32_t srt_diff_read(SrtDiffRx* rx, int64_t now_us, uint8_t* buffer, size_t capacity,
                                 SrtDiffDelivered* delivered, uint8_t* present)
{
    if (!rx || !delivered || !present || !valid_time(now_us) || (capacity && !buffer) ||
        capacity < rx->payload_limit)
        return SRT_DIFF_E_ARG;
    struct Read
    {
        SrtDiffRx* rx;
        int64_t now_us;
        uint8_t* buffer;
        size_t capacity;
        SrtDiffDelivered* delivered;
        uint8_t* present;
        int32_t operator()() const
        {
            *present = 0;
            // CUDT::receiveMessage reads only when isRcvDataReady(now)
            // (core.cpp:7310-7311).
            if (!rx->buffer.isRcvDataReady(at(now_us)))
                return SRT_DIFF_OK;
            // srt_msgctrl_default (srt_c_api.cpp:216-226), built here so
            // srt_c_api.cpp and the whole socket API stay out of the link.
            SRT_MSGCTRL ctrl;
            memset(&ctrl, 0, sizeof ctrl);
            ctrl.msgttl = SRT_MSGTTL_INF;
            ctrl.boundary = srt::PB_SUBSEQUENT;
            ctrl.pktseq = SRT_SEQNO_NONE;
            ctrl.msgno = SRT_MSGNO_NONE;
            const int n = rx->buffer.readMessage(reinterpret_cast<char*>(buffer), capacity, &ctrl);
            if (n < 0)
                return SRT_DIFF_E_EXCEPTION;
            *present = 1;
            delivered->seq = uint32_t(ctrl.pktseq);
            delivered->msgno = uint32_t(ctrl.msgno);
            delivered->play_time_us = ctrl.srctime;
            delivered->len = size_t(n);
            return SRT_DIFF_OK;
        }
    } read = {rx, now_us, buffer, capacity, delivered, present};
    return guarded(read);
}

extern "C" int32_t srt_diff_service(SrtDiffRx* rx, int64_t now_us, SrtDiffDrop* drop)
{
    if (!rx || !drop || !valid_time(now_us))
        return SRT_DIFF_E_ARG;
    memset(drop, 0, sizeof *drop);
    struct Service
    {
        SrtDiffRx* rx;
        int64_t now_us;
        SrtDiffDrop* drop;
        int32_t operator()() const
        {
            rx->service(now_us, drop);
            return SRT_DIFF_OK;
        }
    } service = {rx, now_us, drop};
    return guarded(service);
}

extern "C" int32_t srt_diff_ack_seq(SrtDiffRx* rx, uint32_t* ack_seq)
{
    if (!rx || !ack_seq)
        return SRT_DIFF_E_ARG;
    *ack_seq = uint32_t(rx->ackSeq());
    return SRT_DIFF_OK;
}

extern "C" int32_t srt_diff_losses(SrtDiffRx* rx, SrtDiffRange* ranges, size_t capacity, size_t* needed)
{
    if (!rx || !needed || (capacity && !ranges))
        return SRT_DIFF_E_ARG;
    // The public iterator (list.h:231-275) instead of getLossArray, which
    // truncates at its output capacity.
    size_t count = 0;
    for (CRcvLossList::iterator it = rx->losses.begin(); it != rx->losses.end(); ++it)
    {
        if (count < capacity)
        {
            const std::pair<int32_t, int32_t> r = *it;
            ranges[count].first = uint32_t(r.first);
            // A one-sequence node stores seqend == SRT_SEQNO_NONE (list.cpp:187,246).
            ranges[count].last = uint32_t(r.second == SRT_SEQNO_NONE ? r.first : r.second);
        }
        ++count;
    }
    *needed = count;
    return count > capacity ? SRT_DIFF_E_CAPACITY : SRT_DIFF_OK;
}
