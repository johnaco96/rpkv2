use crate::tiles::Tile;
use crossbeam_queue::ArrayQueue;
use std::{net::UdpSocket, sync::Arc, thread, time::Duration};

use super::signing::SignedShred;

pub type TurbineInQueue = Arc<ArrayQueue<SignedShred>>;

/// Minimal "turbine": UDP fanout to a static set of peers.
/// (Real Turbine does erasure coding, neighborhoods, and retransmits.)
pub struct Turbine {
    pub rx: TurbineInQueue,
    pub peers: Vec<std::net::SocketAddr>,
    pub bind: std::net::SocketAddr, // local send socket bind
}

impl Tile for Turbine {
    fn start(self) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let sock = UdpSocket::bind(self.bind).expect("bind turbine socket");
            sock.set_nonblocking(true).ok();
            loop {
                if let Some(s) = self.rx.pop() {
                    let mut buf = Vec::with_capacity(2 + 1 + 4 + s.data.len() + 64 + 8);
                    buf.extend_from_slice(&(s.index as u16).to_le_bytes());
                    buf.push(s.last as u8);
                    buf.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
                    buf.extend_from_slice(&s.data);
                    buf.extend_from_slice(&s.sig.0);
                    // tiny trailer: slot
                    buf.extend_from_slice(&s.slot.to_le_bytes());
                    for p in &self.peers {
                        let _ = sock.send_to(&buf, p);
                    }
                } else {
                    thread::sleep(Duration::from_micros(50));
                }
            }
        })
    }
}
