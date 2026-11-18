//! `phone-auth-sim`: a fake Android authenticator.
//!
//! It speaks the real protocol over real TLS and holds a real asymmetric key, so
//! the entire Linux-side path can be exercised without an Android device. It can
//! also be told to misbehave, which is how the host's defences are tested.
//!
//! ```text
//! phone-auth-sim pair  --host 127.0.0.1:47123 --name "Pixel 9"
//! phone-auth-sim serve --host 127.0.0.1:47123
//! phone-auth-sim serve --host 127.0.0.1:47123 --behaviour deny
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use android_fprint_protocol::errors::{ProtocolError, Result};
use android_fprint_protocol::messages::Message;
use phone_auth_sim::device::{load_hosts, save_hosts};
use phone_auth_sim::{Behaviour, Device, DeviceKey, Misbehaviour};

struct Args {
    command: String,
    host: String,
    name: String,
    trust_on_first_use: bool,
    ca_file: Option<String>,
    behaviour: Behaviour,
    on_request: Option<u64>,
    timeout_secs: u64,
    daemon_bin: String,
    daemon_args: Vec<String>,
    identity: Option<PathBuf>,
}

fn usage() -> ! {
    eprintln!(
        "phone-auth-sim {}\n\
         \n\
         A fake Android authenticator for end-to-end testing.\n\
         \n\
         USAGE:\n    phone-auth-sim <COMMAND> [OPTIONS]\n\
         \n\
         COMMANDS:\n\
         \x20   pair     connect and pair with a host\n\
         \x20   serve    connect and answer authentication requests\n\
         \x20   bench    pair, then answer requests until interrupted\n\
         \n\
         OPTIONS:\n\
         \x20   --host HOST:PORT      Linux host to connect to (default 127.0.0.1:47123)\n\
         \x20   --name NAME           device label shown on Linux (default Simulated Pixel)\n\
         \x20   --ca FILE             PEM certificate to pin the host to\n\
         \x20   --trust-on-first-use  accept any certificate (TESTING ONLY)\n\
         \x20   --behaviour B         approve|deny|biometric-failed|sign-wrong-request|\n\
         \x20                          corrupt-signature|wrong-device|replay|stall\n\
         \x20   --on-request N        apply --behaviour only to the Nth request\n\
         \x20   --timeout SECS        how long to keep serving (default 300)\n\
         \x20   --identity PATH       persist the device identity here (survives restarts)\n         \x20   --daemon PATH         phone-authd binary, used to read --ca\n\
         \x20   --daemon-arg ARG      extra argument for phone-authd --check\n\
         \x20   -h, --help            show this help\n\
         \n\
         The --trust-on-first-use option exists so the simulator can bootstrap\n\
         before a host certificate has been pinned. It removes the TLS pinning\n\
         check only. Protocol-level verification is always performed.\n",
        android_fprint_protocol::VERSION
    );
    std::process::exit(2)
}

fn parse_behaviour(s: &str) -> Behaviour {
    match s {
        "approve" => Behaviour::Approve,
        "deny" => Behaviour::Deny,
        "biometric-failed" => Behaviour::BiometricFailed,
        "sign-wrong-request" => Behaviour::SignWrongRequest,
        "corrupt-signature" => Behaviour::CorruptSignature,
        "wrong-device" => Behaviour::WrongDeviceId,
        "replay" => Behaviour::Replay,
        "stall" => Behaviour::Stall,
        other => {
            eprintln!("error: unknown behaviour {other:?}");
            usage()
        }
    }
}

fn parse() -> Args {
    let mut args = Args {
        command: String::new(),
        host: "127.0.0.1:47123".into(),
        name: "Simulated Pixel".into(),
        trust_on_first_use: false,
        ca_file: None,
        behaviour: Behaviour::Approve,
        on_request: None,
        timeout_secs: 300,
        daemon_bin: "phone-authd".into(),
        daemon_args: Vec::new(),
        identity: None,
    };
    let mut it = std::env::args().skip(1);
    args.command = it.next().unwrap_or_else(|| usage());
    while let Some(a) = it.next() {
        let mut v = |f: &str| {
            it.next().unwrap_or_else(|| {
                eprintln!("error: {f} needs a value");
                std::process::exit(2)
            })
        };
        match a.as_str() {
            "--host" => args.host = v("--host"),
            "--name" => args.name = v("--name"),
            "--ca" => args.ca_file = Some(v("--ca")),
            "--trust-on-first-use" => args.trust_on_first_use = true,
            "--behaviour" => args.behaviour = parse_behaviour(&v("--behaviour")),
            "--on-request" => args.on_request = Some(v("--on-request").parse().unwrap_or(1)),
            "--timeout" => args.timeout_secs = v("--timeout").parse().unwrap_or(300),
            "--daemon" => args.daemon_bin = v("--daemon"),
            "--identity" => args.identity = Some(PathBuf::from(v("--identity"))),
            "--daemon-arg" => args.daemon_args.push(v("--daemon-arg")),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("error: unknown option {other:?}");
                usage()
            }
        }
    }
    args
}

/// Builds a TLS client configuration.
///
/// The normal case pins the host certificate that was learned at pairing. The
/// `trust_on_first_use` case exists only so the very first pairing can happen;
/// it is never used for authentication runs.
fn client_config(args: &Args) -> Result<rustls::ClientConfig> {
    if args.trust_on_first_use {
        return Ok(rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth());
    }
    let path = args.ca_file.clone().ok_or_else(|| {
        ProtocolError::BadRequest(
            "--ca is required for pinning (or pass --trust-on-first-use for a first pairing)"
                .into(),
        )
    })?;
    let pem =
        std::fs::read(&path).map_err(|e| ProtocolError::BadRequest(format!("read {path}: {e}")))?;
    let mut cursor = std::io::Cursor::new(pem);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ProtocolError::BadRequest(format!("parse {path}: {e}")))?;
    let cert = certs
        .into_iter()
        .next()
        .ok_or_else(|| ProtocolError::BadRequest(format!("{path} has no certificate")))?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert)
        .map_err(|e| ProtocolError::BadRequest(format!("pin {path}: {e}")))?;
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

async fn connect(args: &Args) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let stream = tokio::net::TcpStream::connect(&args.host)
        .await
        .map_err(|e| ProtocolError::Internal(format!("connect {}: {e}", args.host)))?;
    let cfg = client_config(args)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let name = rustls::pki_types::ServerName::try_from("phone-authd")
        .map_err(|e| ProtocolError::Internal(format!("server name: {e}")))?;
    connector
        .connect(name, stream)
        .await
        .map_err(|e| ProtocolError::Internal(format!("TLS handshake with {}: {e}", args.host)))
}

/// Reads the host's certificate path by asking the daemon where it keeps state.
fn discover_host_cert(args: &Args) -> Result<String> {
    let out = std::process::Command::new(&args.daemon_bin)
        .args(["--check"])
        .args(&args.daemon_args)
        .output()
        .map_err(|e| ProtocolError::Internal(format!("run {} --check: {e}", args.daemon_bin)))?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("state dir") {
            let _ = rest;
        }
    }
    // `phone-authd --check` prints "state dir : <path>"; the certificate lives
    // beside the host key.
    for line in text.lines() {
        if line.contains("state dir") {
            if let Some((_, value)) = line.split_once(':') {
                let dir = value.trim();
                let cert = std::path::Path::new(dir).join("host.crt");
                if cert.exists() {
                    return Ok(cert.to_string_lossy().to_string());
                }
            }
        }
    }
    Err(ProtocolError::Internal(
        "could not determine the host certificate path; pass --ca explicitly".into(),
    ))
}

async fn run(mut args: Args) -> Result<()> {
    // First pairing has no pinned certificate yet, so find the host's certificate
    // from the daemon's own configuration before connecting.
    if args.ca_file.is_none() && !args.trust_on_first_use && args.command == "pair" {
        let discovered = discover_host_cert(&args)?;
        println!("[phone] pinning host certificate {discovered}");
        args.ca_file = Some(discovered);
    }

    let identity = args.identity.clone().unwrap_or_else(|| {
        let dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
        std::path::PathBuf::from(dir).join(format!(
            "phone-auth-sim-{}.json",
            args.name.replace(' ', "_")
        ))
    });
    let device = Arc::new(DeviceKey::load_or_create(&identity, &args.name)?);
    println!("[phone] identity {}", identity.display());
    // The private key is never written anywhere; only this public record is, which
    // is what a test compares against the host's registry.
    println!(
        "[phone] device {} key {} fingerprint {}",
        &device.device_id.to_hex()[..16],
        device.device_key_id_short(),
        device.public_key().short_fingerprint()
    );
    if std::env::var("PHONE_SIM_PRINT_RECORD").is_ok() {
        println!(
            "[phone] record {}",
            serde_json::to_string(&device.to_public_record()).expect("serialises")
        );
    }

    let stream = connect(&args).await?;
    let mut dev = Device::new(
        device,
        stream,
        Misbehaviour {
            on_request: args.on_request,
            behaviour: args.behaviour,
        },
    );
    // Remember previously paired hosts across invocations.
    let hosts_path = identity.with_extension("hosts.json");
    dev.hosts = load_hosts(&hosts_path);
    if !dev.hosts.is_empty() {
        println!(
            "[phone] {} host(s) paired with this device",
            dev.hosts.len()
        );
    }

    // 1. Answer the host's SESSION_HELLO.
    let Some(first) = dev.recv().await? else {
        return Err(ProtocolError::Internal("host closed immediately".into()));
    };
    let hello = match first {
        Message::SessionHello(h) => h,
        other => {
            return Err(ProtocolError::BadRequest(format!(
                "expected SESSION_HELLO, got {}",
                other.name()
            )))
        }
    };
    dev.hello_ack(&hello).await?;

    // 2. Pairing or authentication.
    let Some(second) = dev.recv().await? else {
        return Ok(());
    };
    match (args.command.as_str(), second) {
        ("pair", Message::PairingStart(start)) => {
            dev.pair(&start, true).await?;
            save_hosts(&hosts_path, &dev.hosts)?;
            println!("[phone] pairing complete");
            Ok(())
        }
        ("pair", other) => Err(ProtocolError::BadRequest(format!(
            "expected PAIRING_START, got {}. Start pairing on Linux first with: phone-authctl pair",
            other.name()
        ))),
        (_, Message::AuthRequest(request)) => serve_loop(&mut dev, request, &args).await,
        (_, other) => Err(ProtocolError::BadRequest(format!(
            "unexpected message {}",
            other.name()
        ))),
    }
}

/// Answers requests until the deadline.
async fn serve_loop<S>(
    dev: &mut Device<S>,
    first: android_fprint_protocol::types::AuthRequest,
    args: &Args,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(args.timeout_secs);
    let mut next = first;
    loop {
        let answered = dev.handle_auth(&next).await?;
        if !answered {
            println!("[phone] stalling; host should time out");
        }
        if tokio::time::Instant::now() >= deadline {
            println!("[phone] serve window elapsed");
            return Ok(());
        }
        match tokio::time::timeout_at(deadline, dev.recv()).await {
            Err(_) => {
                println!("[phone] idle until the serve window elapsed");
                return Ok(());
            }
            Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(Message::AuthRequest(r)))) => next = r,
            Ok(Ok(Some(Message::Error(e)))) => {
                println!("[phone] host error {}: {}", e.code, e.message);
                return Ok(());
            }
            Ok(Ok(Some(other))) => {
                println!("[phone] ignoring unexpected {}", other.name());
            }
            Ok(Err(e)) => return Err(e),
        }
    }
}

fn main() {
    let args = parse();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot start the async runtime: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(run(args)) {
        eprintln!("[phone] error: {e}");
        std::process::exit(1);
    }
}
