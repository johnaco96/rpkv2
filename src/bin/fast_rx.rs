use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::{io::ErrorKind, net::SocketAddr, thread, time::Instant};

fn make_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    // Works on macOS with socket2's "all" feature enabled:
    s.set_reuse_port(true)?;
    s.bind(&addr.into())?;

    // Tune buffers HERE on socket2::Socket:
    s.set_recv_buffer_size(4 * 1024 * 1024)?;
    s.set_send_buffer_size(4 * 1024 * 1024)?;
    s.set_nonblocking(true)?;

    // Convert to std UDP socket last:
    Ok(s.into())
}

fn run_worker(idx: usize, addr: SocketAddr) -> Result<()> {
    let sock = make_socket(addr)?;

    // On Linux you can pin; on macOS this is a no-op even if you keep the dep.
    #[cfg(target_os = "linux")]
    {
        use core_affinity::CoreId;
        let _ = core_affinity::set_for_current(CoreId { id: idx });
    }

    let mut buf = vec![0u8; 65536];
    let mut cnt: u64 = 0;
    let mut last = Instant::now();

    loop {
        match sock.recv_from(&mut buf) {
            Ok((_n, _peer)) => {
                // If you want to parse your header, check n and decode here.
                cnt += 1;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // busy-poll; optionally tiny sleep if CPU is too high
            }
            Err(e) => eprintln!("[worker {idx}] recv error: {e}"),
        }

        if last.elapsed().as_secs() >= 1 {
            eprintln!("[worker {idx}] pps={}", cnt);
            cnt = 0;
            last = Instant::now();
        }
    }
}

fn main() -> Result<()> {
    let bind: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:9000".into())
        .parse()?;

    let workers: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.strip_prefix("--workers=").map(|n| n.parse().ok()))
        .flatten()
        .unwrap_or_else(|| num_cpus::get().min(4)); // macOS: 2–4; Linux: 8+ later

    eprintln!("fast_rx listening on {bind} (workers={workers})");

    for i in 0..workers {
        let addr = bind;
        thread::spawn(move || {
            if let Err(e) = run_worker(i, addr) {
                eprintln!("[worker {i}] exited: {e}");
            }
        });
    }

    // Keep the main thread alive AFTER spawning workers, and don't put code after this.
    loop {
        thread::park();
    }
}
