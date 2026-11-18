# Roadmap

This is a living roadmap. It records what is supported **today**, what is
explicitly not promised, and the order in which new platform and protocol work
should happen. Security findings from [`security-audit.md`](security-audit.md)
take precedence over feature work.

## Current support

| Area | Today |
|---|---|
| Host OS | **Linux only**. Tested on Arch Linux. Debian/Ubuntu PAM instructions exist; Fedora/BSD/macOS/Windows are not supported. |
| Phone | **Android 9+** (`minSdk 28`), debug APK. Tested on a Motorola Edge 30 Ultra, API 37. No iOS app. |
| Transport | **Wi-Fi** end to end. BLE framing/segmentation is tested; BlueZ/central wiring is not. |
| Host integration | Linux-PAM; **sudo only** on the tested machine. Polkit/GDM/login/sshd are not wired by default. |
| Service manager | systemd unit + Unix control socket. |
| Build | Debug-signed APK; no release-signed/non-debuggable build. |
| Protocol | Canonical CBOR, P-256 signatures, pinned TLS, pairing code, revocation tokens. |

The real fingerprint reader works at GDM because `gdm-fingerprint` uses
`pam_fprintd`; it is not using this project. `pkexec` and `systemctl` use
polkit/`system-auth`; they are not using this project either. Any expansion to
those stacks is a deployment decision with a larger prompt-fatigue surface.

### Why the other prompts do not work yet

On the tested Arch machine, the installed phone line is only in
`/etc/pam.d/sudo`. The other paths are:

```text
pkexec / systemctl      -> /usr/lib/pam.d/polkit-1
                        -> include system-auth

GDM password login      -> /usr/lib/pam.d/gdm-password
                        -> system-local-login
                        -> system-login
                        -> include system-auth

GDM fingerprint login   -> /usr/lib/pam.d/gdm-fingerprint
                        -> pam_fprintd.so
```

Arch keeps vendor PAM files under `/usr/lib/pam.d`; local overrides belong in
`/etc/pam.d`. Editing the vendor files is not durable. Adding the phone module to
`system-auth` would affect many services at once and is deliberately not the
default. Adding it to polkit or GDM must be tested with a root TTY available.

## What "supported" means

A platform is supported only when it has:

1. a working host adapter for the platform's local authentication substrate;
2. a device app with platform-appropriate secure key storage and biometric
   consent;
3. shared conformance vectors passing on both sides;
4. an end-to-end test on real hardware;
5. a platform-specific threat model and audit entry;
6. a release artifact, not only a debug build.

Anything else is "experimental" or "not supported", regardless of whether the
protocol core compiles there.

## Capability negotiation

### Is a separate protocol valid?

**Yes**, with constraints. It is better to define it as a **new authenticated
message family in the existing session** than as a second socket, port or
unauthenticated discovery channel.

A capability exchange can answer:

- what operations a host can request (`sudo`, `su`, `login`, `polkit`, `gdm`,
  `screen-unlock`, `ssh`, `macos-authorization`, ...);
- what authentication factors a device can provide (`strong-biometric`,
  `device-credential`, `secure-enclave`, `tee`, `strongbox`, ...);
- which transports are available (`wifi`, `ble`);
- which display/consent modes are supported (`transparent-prompt`,
  `device-enters-code`, `host-enters-code`, number matching);
- which protocol features are supported (`revocation`, `unpair`,
  `pending-cleanup`, `attestation`, ...);
- implementation limits (name length, timeout range, concurrent requests).

Capabilities are **not** authorization. They describe what an endpoint can do,
not what it is allowed to do. The effective action is the intersection of:

1. **host capability** — the host can request it;
2. **device capability** — the phone can display/approve it;
3. **host policy** — this device is authorised for this Linux user/operation;
4. **device policy** — the user enabled that operation/factor;
5. **user consent** — biometric/approval at the time of the request.

A phone toggle can only narrow what the phone will accept. It must never grant a
host permission the host policy does not already allow. A host toggle can only
narrow what the host will request. Neither side may silently assume the other's
capability.

### Design requirements

- Capabilities are negotiated only after `SESSION_HELLO`/registration, on the same
  authenticated connection.
- The exchange is bound to the session and endpoint identity (signed transcript
  or TLS exporter). It must not be accepted from an unauthenticated peer.
- The message is versioned. Unknown **required** capabilities fail closed;
  unknown optional capabilities are ignored and not enabled.
- No secrets, private keys, tokens or credentials are included.
- A capability downgrade after authentication is not silently accepted. If the
  session is renegotiated, the host and device must both agree to the new set.
- The host enforces authorization server-side. Capability data from the phone is
  advisory input to policy, never the policy itself.
- Capability advertisements are privacy-sensitive: they can reveal OS, hardware
  class and enabled services. Prefer coarse values and keep them off mDNS.

### Suggested shape

This is a design sketch, not a frozen wire format:

```text
CAPABILITIES {
  version: 1,
  endpoint: "host" | "device",
  platform: "linux" | "android" | "macos" | "ios" | "bsd",
  operations: ["sudo", "polkit", "login", ...],
  factors: ["strong-biometric", "tee", "strongbox", ...],
  transports: ["wifi", "ble"],
  ui: ["transparent-prompt", "device-code", "host-code", "number-match"],
  features: ["revocation", "unpair", "cleanup", "attestation"],
  limits: { ... }
}
```

The host and device should exchange this once per session, cache only
non-sensitive summaries, and renegotiate when either side changes policy.

## Roadmap phases

### Phase 0 — Security remediation

Do these before expanding the platform surface:

- [ ] SEC-001: bind the pairing code to the public keys; commit/reveal or PAKE.
- [ ] SEC-003: stop recommending global `common-auth`; scope PAM integration and
      add number matching for authentication.
- [ ] SEC-004: bind each paired device to allowed Linux users; deny root by
      default.
- [ ] SEC-005: design opt-in Android Key Attestation and downgrade policy.
- [ ] SEC-006: verify the control-socket server from the PAM client.
- [ ] SEC-007: connection caps, handshake timeouts, persistent rate limits,
      parser fuzzing, explicit bind policy.
- [ ] SEC-009: panic containment and FFI review in the PAM module.
- [ ] Release-signed Android build and a test matrix beyond one debug device.

### Phase 1 — Linux production integration

- [ ] Provide distro-specific PAM documentation:
      Debian/Ubuntu `common-auth`; Arch `/etc/pam.d/sudo`, `polkit-1`,
      `gdm-password`; Fedora equivalents.
- [ ] Scope the default integration to `sudo` and `polkit`; make GDM/login
      opt-in and explicitly warn about prompt fatigue.
- [ ] Keep `/etc/pam.d` overrides in `/etc`, never edit vendor files under
      `/usr/lib/pam.d`.
- [ ] Add a root-shell recovery procedure and a PAM rollback test to every
      documented flow.
- [ ] Add device-user binding and per-user rate limits.

### Phase 2 — Capability protocol v1

- [ ] Specify the capability message family and canonical encoding.
- [ ] Add host/device policy intersection rules and tests.
- [ ] Add toggles in Android and the host CLI for supported operations.
- [ ] Add downgrade/mismatch tests and a "required capability missing" failure.
- [ ] Add shared vectors and a conformance run for the new messages.
- [ ] Keep capabilities separate from authorization; document the distinction.

### Phase 3 — Portability

These are separate adapters, not assumptions that the Linux code is portable.

#### BSD

- [ ] OpenPAM adapter instead of Linux-PAM-specific calls.
- [ ] Peer-credential check using `getpeereid`/`LOCAL_PEERCRED` equivalents.
- [ ] No systemd; use the platform service manager.
- [ ] Avahi/Bonjour discovery; no BlueZ central.
- [ ] Real hardware and PAM-stack tests before claiming support.

#### macOS host

- [ ] PAM/OpenPAM adapter for `sudo` and terminal auth.
- [ ] Authorization Plugin for GUI/login; do not pretend PAM alone covers the
      macOS login window.
- [ ] launchd service, Keychain, Bonjour discovery.
- [ ] Separate local-IPC peer validation.

#### iOS authenticator

- [ ] Swift app implementing the shared protocol vectors.
- [ ] Secure Enclave P-256 signing and LocalAuthentication/Face ID.
- [ ] Network.framework/Bonjour and BLE, with realistic background limits.
- [ ] Platform-specific attestation and storage review.
- [ ] App Store / distribution policy review.

#### Windows

- [ ] Not planned as part of the current roadmap. It needs a Credential
      Provider/Windows Hello design, not a PAM port.

### Phase 4 — Release and audit

- [ ] Release-signed, non-debuggable Android APK.
- [ ] Reproducible builds and release checksums.
- [ ] Packaging for the supported Linux distributions.
- [ ] Re-run the full audit after each platform adapter lands.
- [ ] Keep `docs/security-audit.md` updated; duplicate findings are linked, not
      deleted.

## Explicit non-goals

- A permanent pairing mode or "trust anything that connects".
- A phone capability that grants a Linux user permission the host policy denies.
- Silent downgrade when attestation, strong biometrics or a required transport
  is unavailable.
- Claiming macOS/BSD/iOS support by compiling the Rust core without a real
  platform adapter and hardware test.
- Global PAM installation as the default without a clear warning about prompt
  fatigue and recovery.

## Decision log

| Date | Decision |
|---|---|
| 2026-11-18 | Linux/Arch is the supported target for now. |
| 2026-11-18 | Capability negotiation is a valid separate authenticated message family, not a second unauthenticated protocol. |
| 2026-11-18 | Polkit/GDM/login integration is opt-in and must be scoped; `sudo` remains the tested integration. |
| 2026-11-18 | macOS/BSD/iOS are separate adapters with their own threat models; Windows is out of scope. |
