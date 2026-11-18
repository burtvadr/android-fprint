//! Wi-Fi transport: TCP, TLS 1.3, and DNS-SD advertisement.
//!
//! The layering is deliberate:
//!
//! ```text
//! mDNS/DNS-SD   discovery only: "something is at this address"
//! TCP           byte stream
//! TLS 1.3      confidentiality + a pinned transport credential
//! protocol      the actual authentication decision
//! ```
//!
//! A successful TLS handshake is **not** an authentication result. The device is
//! trusted because it holds a private key registered at pairing time, and it
//! proves that per request with a signature.

use std::sync::Arc;

use tokio::net::TcpListener;

use android_fprint_protocol::errors::{ProtocolError, Result};
use android_fprint_protocol::types::Transport;

use crate::config::Config;
use crate::engine::Engine;
use crate::tls;

/// Advertises the host over DNS-SD so devices can find it without a fixed
/// address. Publication contains only non-secret metadata (`PROTOCOL.md` §13.1).
pub fn advertise(
    config: &Config,
    host_name: &str,
    host_key_id: &str,
) -> Result<mdns_sd::ServiceDaemon> {
    let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| {
        ProtocolError::Internal(format!(
            "mDNS daemon unavailable (multicast may be filtered): {e}"
        ))
    })?;
    let props = [
        ("v", "1"),
        ("id", host_key_id),
        ("name", host_name),
        ("caps", "auth"),
    ];
    // The daemon needs a DNS hostname, not just a label. Host labels can contain
    // characters that mDNS rejects, and the crate requires the `.local.` suffix
    // explicitly, so derive one that is always valid.
    let mdns_host = {
        let label: String = host_name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .take(63)
            .collect();
        let label = label.trim_matches('-');
        if label.is_empty() {
            "phone-authd.local.".to_string()
        } else {
            format!("{label}.local.")
        }
    };
    // A wildcard bind address is not a routable address. Advertising `0.0.0.0`
    // would tell devices to connect nowhere, so let the daemon publish the host's
    // real interface addresses instead.
    let info = if config.bind_addr.ip().is_unspecified() {
        mdns_sd::ServiceInfo::new(
            android_fprint_protocol::SERVICE_TYPE,
            host_name,
            &mdns_host,
            (),
            config.tcp_port,
            &props[..],
        )
        .map_err(|e| ProtocolError::Internal(format!("mDNS service info: {e}")))?
        .enable_addr_auto()
    } else {
        mdns_sd::ServiceInfo::new(
            android_fprint_protocol::SERVICE_TYPE,
            host_name,
            &mdns_host,
            config.bind_addr.ip(),
            config.tcp_port,
            &props[..],
        )
        .map_err(|e| ProtocolError::Internal(format!("mDNS service info: {e}")))?
    };
    daemon
        .register(info)
        .map_err(|e| ProtocolError::Internal(format!("mDNS register: {e}")))?;
    Ok(daemon)
}

/// Resolves candidate devices of this service type on the local network.
pub fn discover(timeout: std::time::Duration) -> Result<Vec<String>> {
    let daemon =
        mdns_sd::ServiceDaemon::new().map_err(|e| ProtocolError::Internal(format!("mDNS: {e}")))?;
    let receiver = daemon
        .browse(android_fprint_protocol::SERVICE_TYPE)
        .map_err(|e| ProtocolError::Internal(format!("mDNS browse: {e}")))?;
    let mut found = Vec::new();
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        match receiver.recv_timeout(std::time::Duration::from_millis(250)) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                for addr in info.get_addresses() {
                    found.push(format!("{}:{}", addr, info.get_port()));
                }
            }
            Ok(_) => {}
            Err(e) => return Err(ProtocolError::Internal(format!("mDNS browse: {e}"))),
        }
    }
    Ok(found)
}

/// Binds the TCP listener and serves connections until `shutdown` resolves.
pub async fn serve(
    engine: Arc<Engine>,
    config: Config,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let tls_config = Arc::new(tls::server_config(&config)?);
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .map_err(|e| ProtocolError::Internal(format!("bind {}: {e}", config.bind_addr)))?;
    let pairing_timeout = android_fprint_protocol::types::PAIRING_TTL;

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let tls_cfg = tls_config.clone();
                let engine = engine.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    match tls::accept(stream, tls_cfg).await {
                        Ok(tls_stream) => {
                            let peer_label = peer.to_string();
                            let conn = crate::transport::open(engine.clone(), tls_stream, Transport::Wifi, peer_label);
                            if let Err(e) = conn.run(pairing_timeout).await {
                                let ev = crate::audit::Event::new("session_error")
                                    .denied(e.code().as_str())
                                    .detail(e.to_string());
                                engine.audit().write(&ev);
                            }
                        }
                        Err(e) => {
                            // A failed TLS handshake is not an authentication
                            // event; it may just be an unrelated scanner.
                            let _ = e;
                        }
                    }
                    let _ = shutdown;
                });
            }
        }
    }
}
