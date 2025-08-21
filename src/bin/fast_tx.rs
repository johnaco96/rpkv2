use bytes::BytesMut;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};
use rpkv2::fastpath::packet::{Header, HEADER_LEN};

fn main() -> anyhow::Result<()> {
    let target: std::net::SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9000".into())
        .parse()?;
    let pps: u64 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "200000".into())
        .parse()
        .unwrap_or(200_000);
    let payload: usize = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "256".into())
        .parse()
        .unwrap_or(256);

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_nonblocking(false)?;

    let mut nonce: u64 = 0;
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let sleep_ns = if pps > 0 { 1_000_000_000u64 / pps } else { 0 };

    println!("fast_tx -> {} pps={} payload={}", target, pps, payload);

    let start = Instant::now();
    let mut sent = 0u64;

    loop {
        // 1) Allocate buffer for header + payload
        let mut buf = BytesMut::with_capacity(HEADER_LEN + payload);
        buf.resize(HEADER_LEN, 0);

        // 2) Build header
        let h = Header {
            v: 1,
            msg_type: 1,
            flags: 0,
            slot: 1,
            nonce,
            key_id: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        h.encode_into(&mut buf[..HEADER_LEN])?;

        // 3) Append payload
        let mut body = vec![0u8; payload];
        rng.fill(&mut body[..]);
        buf.extend_from_slice(&body);

        // 4) Send
        let _ = sock.send_to(&buf, target)?;
        nonce = nonce.wrapping_add(1);
        sent += 1;

        if sleep_ns > 0 {
            std::thread::sleep(Duration::from_nanos(sleep_ns));
        }
        if sent % 100_000 == 0 {
            let dt = start.elapsed().as_secs_f64();
            println!("sent={} rate={:.1} kpps", sent, (sent as f64 / dt) / 1000.0);
        }
    }
}
