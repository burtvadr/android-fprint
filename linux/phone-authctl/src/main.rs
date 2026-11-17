//! `phone-authctl`: operator and integration interface to `phone-authd`.
//!
//! Every subcommand is a thin request to the daemon over its control socket. The
//! CLI performs no authentication decision of its own: it cannot, because it
//! holds no keys and trusts nothing.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use phone_authd::ipc::{ControlRequest, ControlResponse};

const DEFAULT_SOCKET: &str = phone_authd::config::DEFAULT_SOCKET;

fn usage() -> ! {
    eprintln!(
        "phone-authctl {}\n\
         \n\
         USAGE:\n    phone-authctl [--socket PATH] <COMMAND> [OPTIONS]\n\
         \n\
         COMMANDS:\n\
         \x20   list                      show paired authenticators\n\
         \x20   status                    daemon status\n\
         \x20   pair                      pair a phone; compare the displayed code on both screens\n\
         \x20   pair --code NNNNNN       pair using an operator-chosen code\n\
         \x20   authenticate --user U    ask a phone to authenticate a Linux user\n\
         \x20   revoke --device D        revoke an authenticator immediately (root only)\n\
         \n\
         OPTIONS:\n\
         \x20   --socket PATH    control socket (default {DEFAULT_SOCKET})\n\
         \x20   --user NAME      Linux user to authenticate (defaults to $USER)\n\
         \x20   --purpose P      purpose, e.g. sudo, login, polkit  (default authenticate)\n\
         \x20   --service S      PAM service / polkit action       (default phone-auth)\n\
         \x20   --operation O    authenticate or authorize         (default authenticate)\n\
         \x20   --device D       device name or id (default: any connected authenticator)\n\
         \x20   --timeout MS     how long to wait                     (default 90000)\n\
         \x20   --yes            skip the interactive code confirmation\n\
         \x20   -h, --help       show this help\n\
         \n\
         The 'authenticate' command performs no cryptography here: it asks the\n\
         daemon, which verifies a signature over a fresh challenge against the\n\
         registered device public key.\n",
        android_fprint_protocol::VERSION
    );
    std::process::exit(2)
}

struct Args {
    socket: PathBuf,
    command: String,
    user: Option<String>,
    purpose: String,
    service: String,
    operation: String,
    device: Option<String>,
    code: Option<String>,
    timeout_ms: u64,
    assume_yes: bool,
}

fn parse() -> Args {
    let mut args = Args {
        socket: PathBuf::from(DEFAULT_SOCKET),
        command: String::new(),
        user: None,
        purpose: "authenticate".into(),
        service: "phone-auth".into(),
        operation: "authenticate".into(),
        device: None,
        code: None,
        timeout_ms: phone_authd::server::DEFAULT_AUTH_TIMEOUT_MS,
        assume_yes: false,
    };
    let mut it = std::env::args().skip(1).peekable();
    if it.peek().is_none() {
        usage();
    }
    // The subcommand may appear anywhere, so that both
    // `phone-authctl pair --socket X` and `phone-authctl --socket X pair` work.
    while let Some(a) = it.next() {
        if !a.starts_with('-') {
            if args.command.is_empty() {
                args.command = a;
                continue;
            }
            eprintln!("error: unexpected argument {a:?}");
            usage();
        }
        let mut v = |f: &str| {
            it.next().unwrap_or_else(|| {
                eprintln!("error: {f} needs a value");
                std::process::exit(2)
            })
        };
        match a.as_str() {
            "--socket" => args.socket = PathBuf::from(v("--socket")),
            "--user" => args.user = Some(v("--user")),
            "--purpose" => args.purpose = v("--purpose"),
            "--service" => args.service = v("--service"),
            "--operation" => args.operation = v("--operation"),
            "--device" => args.device = Some(v("--device")),
            "--code" => args.code = Some(v("--code")),
            "--timeout" => args.timeout_ms = v("--timeout").parse().unwrap_or(90_000),
            "--yes" | "-y" => args.assume_yes = true,
            "-h" | "--help" => usage(),
            other => {
                eprintln!("error: unknown option {other:?}");
                usage()
            }
        }
    }
    args
}

/// Sends one control request and returns the response.
fn request(args: &Args, req: &ControlRequest) -> Result<ControlResponse, String> {
    let stream = std::os::unix::net::UnixStream::connect(&args.socket).map_err(|e| {
        format!(
            "cannot reach phone-authd at {}: {e}\nhint: is the service running? (systemctl status phone-authd)",
            args.socket.display()
        )
    })?;
    let mut stream = stream;
    let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(&stream);
    let mut reply = String::new();
    reader.read_line(&mut reply).map_err(|e| e.to_string())?;
    if reply.trim().is_empty() {
        return Err("the daemon closed the connection without replying".into());
    }
    serde_json::from_str(reply.trim()).map_err(|e| format!("malformed reply: {e}"))
}

fn fail(resp: &ControlResponse) -> ! {
    eprintln!(
        "error: {}",
        resp.error.as_deref().unwrap_or("request failed")
    );
    if let Some(code) = &resp.code {
        eprintln!("code: {code}");
    }
    std::process::exit(1)
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".into())
}

fn cmd_list(args: &Args) {
    let resp = request(args, &ControlRequest::List).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1)
    });
    if !resp.ok {
        fail(&resp);
    }
    let devices = resp
        .result
        .as_ref()
        .and_then(|r| r.get("devices"))
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    if devices.is_empty() {
        println!("No authenticators are paired.");
        println!();
        println!("Pair one with:  phone-authctl pair");
        return;
    }
    println!("Paired authenticators:");
    println!();
    for d in &devices {
        let status = d.get("status").and_then(|v| v.as_str()).unwrap_or("?");
        let avail = if d
            .get("available")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            "available"
        } else {
            "not connected"
        };
        println!(
            "  {}",
            d.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unnamed)")
        );
        println!(
            "    id:      {}",
            d.get("device_id").and_then(|v| v.as_str()).unwrap_or("-")
        );
        let key = d.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
        println!(
            "    key:     SHA256:{}...",
            &key.chars().take(16).collect::<String>()
        );
        println!("    status:  {status}");
        println!("    link:    {avail}");
        println!(
            "    paired:  {}",
            d.get("summary")
                .and_then(|v| v.as_str())
                .and_then(|s| s.lines().find(|l| l.contains("paired:")))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
                .unwrap_or_default()
        );
        println!();
    }
}

fn cmd_status(args: &Args) {
    let resp = request(args, &ControlRequest::Status).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1)
    });
    if !resp.ok {
        fail(&resp);
    }
    if let Some(r) = &resp.result {
        println!(
            "host          {}",
            r.get("host_name").and_then(|v| v.as_str()).unwrap_or("-")
        );
        println!(
            "host id       {}",
            r.get("host_id").and_then(|v| v.as_str()).unwrap_or("-")
        );
        println!(
            "host key      {}",
            r.get("host_key_id").and_then(|v| v.as_str()).unwrap_or("-")
        );
        println!(
            "paired        {}",
            r.get("paired_devices")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
        );
        println!(
            "connected     {}",
            r.get("connected_devices")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
        );
        match r.get("pairing") {
            Some(p) if p.get("seconds_remaining").is_some() => {
                println!(
                    "pairing       open, {}s remaining",
                    p.get("seconds_remaining")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                );
            }
            _ => println!("pairing       closed"),
        }
    }
}

/// Interactive pairing: open a session, show the code, require confirmation.
fn cmd_pair(args: &Args) {
    let resp = request(
        args,
        &ControlRequest::Pair {
            code: args.code.clone(),
            timeout_ms: Some(args.timeout_ms.max(1000)),
        },
    )
    .unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1)
    });
    if !resp.ok {
        fail(&resp);
    }
    let chosen = resp
        .result
        .as_ref()
        .and_then(|r| r.get("chosen_code"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string());
    let remaining = resp
        .result
        .as_ref()
        .and_then(|r| r.get("seconds_remaining"))
        .and_then(|v| v.as_i64())
        .unwrap_or(120);
    if let Some(c) = &chosen {
        println!("Pairing open for {remaining}s.");
        println!("You chose the code {c}. The phone must show the same code.");
    } else {
        println!("Pairing open for {remaining}s.");
        println!("Start pairing on the phone now.");
    }
    println!();

    // Wait for the device to submit, which is when the comparable code exists.
    let mut shown: Option<String> = None;
    #[allow(clippy::never_loop)]
    loop {
        let st = match request(args, &ControlRequest::PairingCode) {
            Ok(r) if r.ok => r,
            Ok(r) => fail(&r),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1)
            }
        };
        let code = st
            .result
            .as_ref()
            .and_then(|r| r.get("code"))
            .and_then(|c| c.as_str())
            .unwrap_or("");
        if !code.is_empty() && shown.as_deref() != Some(code) {
            shown = Some(code.to_string());
            let _ = &shown;
            println!("Pairing code shown on both screens:");
            println!();
            println!("      ┌────────────────┐");
            println!("      │  {code}  │");
            println!("      └────────────────┘");
            println!();
            println!("Compare it with the phone. If they match, confirm here.");
            if args.assume_yes {
                println!("--yes given: confirming without asking.");
                break;
            }
            print!("Do the codes match? [y/N] ");
            let _ = std::io::stdout().flush();
            let mut answer = String::new();
            if std::io::stdin().read_line(&mut answer).is_err() {
                println!("\nno confirmation read; aborting pairing");
                let _ = request(args, &ControlRequest::ConfirmPairing);
                std::process::exit(1);
            }
            if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                println!("Pairing not confirmed; nothing was stored.");
                let _ = request(args, &ControlRequest::ConfirmPairing);
                std::process::exit(1);
            }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    match request(args, &ControlRequest::ConfirmPairing) {
        Ok(r) if r.ok => {}
        Ok(r) => fail(&r),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1)
        }
    }
    println!("Confirming pairing…");

    // Wait for the daemon to persist the device. The device connection closes as
    // soon as pairing finishes, so success is "a new device exists", not "a
    // device is connected".
    for _ in 0..150 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let Ok(r) = request(args, &ControlRequest::Status) else {
            continue;
        };
        let Some(res) = &r.result else { continue };
        let paired = res
            .get("paired_devices")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if paired > 0 {
            println!("Paired.");
            return;
        }
    }
    println!("Pairing did not complete; check `phone-authctl status`.");
    std::process::exit(1);
}

fn cmd_authenticate(args: &Args) {
    let user = args.user.clone().unwrap_or_else(current_user);
    let req = ControlRequest::Authenticate {
        user: user.clone(),
        purpose: args.purpose.clone(),
        service: args.service.clone(),
        operation: args.operation.clone(),
        device: args.device.clone(),
        timeout_ms: Some(args.timeout_ms),
    };
    let device_label = args
        .device
        .clone()
        .unwrap_or_else(|| "any connected authenticator".into());
    eprintln!("Waiting for authentication on {device_label} for {user}…");
    let resp = match request(args, &req) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1)
        }
    };
    if !resp.ok {
        fail(&resp);
    }
    let r = resp.result.unwrap_or(serde_json::Value::Null);
    println!("Authenticated.");
    println!(
        "  device    {}",
        r.get("device").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "  user      {}",
        r.get("user").and_then(|v| v.as_str()).unwrap_or(&user)
    );
    println!("  purpose   {}", args.purpose);
    println!(
        "  request   {}",
        r.get("request_id").and_then(|v| v.as_str()).unwrap_or("-")
    );
}

fn cmd_revoke(args: &Args) {
    let Some(device) = args.device.clone() else {
        eprintln!("error: --device is required");
        std::process::exit(2);
    };
    match request(args, &ControlRequest::Revoke { device }) {
        Ok(r) if r.ok => println!("Revoked."),
        Ok(r) => fail(&r),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1)
        }
    }
}

fn main() {
    let args = parse();
    if args.command.is_empty() {
        usage();
    }
    match args.command.as_str() {
        "list" => cmd_list(&args),
        "status" => cmd_status(&args),
        "pair" => cmd_pair(&args),
        "authenticate" => cmd_authenticate(&args),
        "revoke" => cmd_revoke(&args),
        "version" => println!("phone-authctl {}", android_fprint_protocol::VERSION),
        other => {
            eprintln!("error: unknown command {other:?}");
            usage()
        }
    }
}
