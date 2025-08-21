use anyhow::Result;
use rpkv2::{tls, quic_cfg};
use quinn::{Endpoint, Connection};
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<()> {
    tls::install_provider();
    tracing_subscriber::fmt().with_env_filter("info").without_time().init();

    // Args (keep simple): server.key is PKCS#8; server.pub is SPKI for clients to pin
    let addr: SocketAddr = "0.0.0.0:4433".parse().unwrap();

    let tls = tls::build_server_rpk("server.key")?;
    let server_cfg = quic_cfg::server_config(tls);

    let endpoint = Endpoint::server(server_cfg, addr)?;
    info!("RPK QUIC server listening on {}", addr);

    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => handle_conn(conn).await,
                Err(e) => warn!("accept error: {e}"),
            }
        });
    }
    Ok(())
}

async fn handle_conn(conn: Connection) {
    info!("peer connected: {}", conn.remote_address());

    // Spawn DATAGRAM echo loop
    let dconn = conn.clone();
    tokio::spawn(async move {
        loop {
            match dconn.read_datagram().await {
                Ok(data) => {
                    // Echo back
                    let _ = dconn.send_datagram(data);
                }
                Err(e) => {
                    // Connection closed or error
                    break eprintln!("datagram loop end: {e}");
                }
            }
        }
    });

    // Spawn stream accept loop (uni-streams)
    let sconn = conn.clone();
    tokio::spawn(async move {
        loop {
            match sconn.accept_uni().await {
                Ok(mut recv) => {
                    match recv.read_to_end(64 * 1024 * 1024).await {
                        Ok(data) => {
                            // echo back via server->client uni stream
                            if let Ok(mut send) = sconn.open_uni().await {
                                let _ = send.write_all(&data).await;
                                let _ = send.finish();
                            }
                        }
                        Err(e) => eprintln!("stream read err: {e}"),
                    }
                }
                Err(_) => break, // connection closed
            }
        }
    });
}
