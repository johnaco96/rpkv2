use anyhow::Result;
use quinn::Endpoint;
use rpkv2::{tls, quic_cfg};
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Select TLS crypto provider (aws-lc) before building configs
    tls::install_provider();

    // Simple logging
    tracing_subscriber::fmt().with_env_filter("info").without_time().init();

    // Load pinned SPKI (DER) from PEM
    let spki = tls::load_spki_from_pem("server.pub")?;
    let tls_client = tls::build_client_rpk_pinned(spki);

    // Quinn client config with our tuned transport
    let client_cfg = quic_cfg::client_config(tls_client);

    // Bind a client endpoint and apply the client config
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut ep = Endpoint::client(bind_addr)?;
    ep.set_default_client_config(client_cfg);

    // Connect to the server (adjust if you changed the port)
    let server_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let conn = ep.connect(server_addr, "localhost")?.await?;
    info!("connected to {}", conn.remote_address());
    let _ = conn.send_datagram(bytes::Bytes::from_static(b"ping dgram"));


    // Send a message on a unidirectional stream
    let mut send = conn.open_uni().await?;
    send.write_all(b"hello from client").await?;
    let _ = send.finish(); // not async in quinn 0.11

    // Read the server's uni-stream echo/greeting (optional but nice)
    if let Ok(mut recv) = conn.accept_uni().await {
        let data = recv.read_to_end(64 * 1024).await?; // 64 KiB limit
        println!("client got: {}", String::from_utf8_lossy(&data));
    } else {
        eprintln!("client: no uni stream from server");
    }

    Ok(())
}
