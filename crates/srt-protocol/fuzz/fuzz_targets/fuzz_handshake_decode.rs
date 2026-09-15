#![no_main]

use libfuzzer_sys::fuzz_target;
use srt_proto::handshake::HandshakePacket;
use srt_proto::wire::SrtPacket;

fuzz_target!(|data: &[u8]| {
    // まず SrtPacket としてデコードを試行
    if let Ok(SrtPacket::Control(control_packet)) = SrtPacket::decode(data) {
        // 制御パケットならハンドシェイクとしてデコードを試行
        let _ = HandshakePacket::decode(&control_packet);
    }
});
