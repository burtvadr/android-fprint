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

## Known network issue: VPN / Tailscale

Observed on the test setup:

- The PC runs Tailscale all the time.
- The phone and PC are on the same Wi-Fi; pairing and authentication work with
  Tailscale off on the phone.
- Turning Tailscale **on** on the phone makes this app stop working.
- Syncthing on the same phone continues to work normally.

This is our bug, not a Tailscale bug. The network path is available; the app does
not choose it correctly.

Likely causes in the current code:

- The host binds `0.0.0.0` and mDNS uses `enable_addr_auto()`, so it publishes
  **every** host address, including the Tailscale `100.x` address. The phone may
  resolve the service to the Tailscale address, the LAN address, or both.
- Android `NsdServiceInfo` is reduced to a single `host` in
  `WifiTransport.discover()`. The app tries that one address and has no fallback
  to the other A/AAAA records.
- `WifiTransport.connect()` creates an unbound `Socket()`, so Android selects the
  default network/VPN route. The app never requests the Wi-Fi `Network` or binds
  the socket to it.
- There is no `NetworkCallback`. Addresses and connections are not re-resolved
  when Wi-Fi, VPN or the default network changes.
- Syncthing works because it binds/listens on multiple interfaces, retries
  addresses, and reconnects; the fact that it continues does not mean Tailscale
  permits arbitrary LAN traffic.

Required behavior:

- Enumerate every resolved host address and try them in a defined order, with a
  short per-address timeout. The default order should be **LAN first**, then
  Tailscale, unless policy says otherwise.
- Use `ConnectivityManager` to obtain the Wi-Fi and VPN `Network` objects and
  bind the data socket with `Network.bindSocket()` before connecting. Choose the
  network that matches the address being tried.
- Register `NetworkCallback` and re-resolve/reconnect on `onAvailable`,
  `onLost`, `onCapabilitiesChanged` and VPN changes.
- Do not publish the Tailscale interface over mDNS by default for local pairing.
  Add a host option such as `--advertise-address` / `--mdns-interface`, or bind
  the daemon to a specific LAN address when that is the intended deployment.
- Make the path policy explicit, for example `--transport-preference lan`,
  `tailscale` or `auto`. Address selection must never weaken TLS pinning or the
  signed transcript; it only decides where bytes are sent.
- Surface diagnostics: the phone should log which address/network it chose and
  why, and `phone-authctl status`/`devices` should show the host's listen
  addresses.

Do not make “disable Tailscale” or “allow local network access” the only
documented fix. Those are workarounds; the app should coexist with a VPN.

Acceptance criteria:

- [ ] Pairing and authentication work with the PC's Tailscale up and the phone's
      Tailscale on, over the LAN.
- [ ] Authentication works over Tailscale `100.x` when policy allows it and the
      phone has Tailscale on.
- [ ] Toggling Tailscale or switching Wi-Fi reconnects without restarting the app.
- [ ] mDNS does not advertise unintended interfaces by default.
- [ ] All resolved addresses are tried, with a bounded timeout each.
- [ ] Tests cover VPN on/off on the phone and Tailscale up on the host; address
      choice remains a routing decision, not an authentication decision.

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

## Security options and policy layers

The proposed Settings → **Security options** section is the right place for
device-side consent, but it must not become the host's authorization policy. Use
three independent layers.

| Layer | Stored where | Who may change it | What it can do |
|---|---|---|---|
| Device consent | Android app-private settings | The phone user, gated by biometric/app lock if enabled | Narrow which negotiated operations/factors the phone will accept |
| Per-user host policy | Per-UID daemon state or `$XDG_CONFIG_HOME/phone-auth/policy.json`, mode `0600` | The same Linux user through the local control socket (`SO_PEERCRED`) | Allow/narrow operations for that user's own account |
| Global host policy | `/etc/phone-auth/policy.json`, root-owned `0600` | root only | Device-to-user binding, root/privileged operations, machine-wide integrations |
| Integration installation | PAM/polkit/GDM files, systemd unit, socket ownership | root only | Makes the mechanism available at all |

### Device-side Security options

Suggested toggles, all of which can only **narrow** host policy:

- **Require biometric to open Settings** (or to open the app manually).
- **Require biometric to change security options / unpair a host.**
- Per-host operation toggles, populated from capability negotiation:
  `sudo`, `su`, `polkit`, `systemctl`/`org.freedesktop.systemd1.manage-units`,
  `login`, `gdm`, `sshd`, `screen-unlock`, future actions.
- Per-transport toggles where meaningful: Wi-Fi, BLE.

The app lock is a local UX/consent gate, not a cryptographic boundary. The real
authentication control remains the `BIOMETRIC_STRONG` signature prompt. An
auto-opened request must **not** require a second app-unlock first: the system
biometric prompt is already the authentication. Use the app lock for manual
launch/settings/unpair, not for the transparent request prompt.

Store these settings in app-private `DataStore`/preferences with backup disabled.
They contain no secrets, but their integrity matters. A Keystore HMAC can detect
casual tampering; it cannot protect against a rooted or compromised OS.

### Host-side settings

The PC does not need `sudo` to change a user's own policy if the daemon enforces
peer identity:

- A local client connects to the root/`phone-auth` control socket.
- The daemon reads `SO_PEERCRED` and only permits that UID to change its own
  policy.
- Per-user policy is stored atomically with mode `0600` and audited.
- root-only settings cover global enablement, device-to-user binding, root
  operations, and integration installation.

Do not use one world-writable policy file. It turns "settings" into a privilege
escalation surface. Do not let an unprivileged user enable a global integration
or bind their device to another Linux account.

### Installation versus runtime policy

Installing a PAM/polkit/GDM line requires root. That is expected and separate
from the toggle:

- **Installed but disabled:** the module is present, returns unavailable/ignore,
  and the normal password path continues.
- **Installed and enabled:** the phone may be asked for the operations allowed by
  both host policy and phone consent.
- **Not installed:** the phone cannot authenticate that service, regardless of
  app toggles.

Use `sufficient`, not `required`, for the phone line unless the operator
explicitly wants a phone-or-lockout policy. Keep an integration-specific rollback
file and a root TTY while changing PAM.

### Disable, mask, or uninstall?

"Masking" is systemd terminology for units; PAM has no equivalent. Once an
integration is installed, prefer disabling it through policy rather than editing
PAM files again:

| State / action | What it means | Root needed? | Effect |
|---|---|---|---|
| Install integration | Add the PAM/polkit/GDM line, module and service | Yes | Makes the mechanism available |
| Enable integration | Policy allows the action for a user/device | No for your own policy; yes for global/other users | Phone may authenticate this action |
| Disable integration | Policy denies the action, or the phone masks it | No for your own policy / phone mask; yes for global/other users | Module is present but the action is not approved |
| Phone mask | This phone refuses the action | No | Host may still ask; with `sufficient` it falls through to password |
| Daemon stopped/masked | `phone-authd` is not running; PAM line remains | Yes for systemd mask/stop | Module cannot reach the daemon; password path continues |
| Uninstall | Remove `/etc/pam.d` override, module and, if desired, package | Yes | The integration no longer exists |

Runtime policy should be the normal switch. It is reversible, auditable, and does
not risk a broken PAM stack. Uninstall is for cleaning the machine, not for daily
toggling.

A **phone-side mask** is the narrowest switch of all: no sudo, no PAM edit. It
only means this phone will refuse requests for that action. The host may still
invoke the PAM module; with `sufficient`, a refusal or unavailable daemon falls
through to the password. A host per-user policy disable also needs no sudo for
that user's own actions. Removing the line globally, changing another user's
policy, or uninstalling the module/package needs root.

The phone can hide or grey out an action it has masked; that is only a UI hint.
The host must still enforce its own policy, and the phone must still refuse an
unexpected request for a masked action.

Recommendations for implementation:

- Track `installed` (packaging/manifest) separately from `enabled` (policy).
  Do not infer installation by parsing PAM files at runtime.
- Add a `phone-authctl integrations` view showing installed, available, enabled
  and disabled actions.
- Let a user disable their own actions without root; require root for global
  actions or device-to-user binding changes.
- Keep a documented uninstall/rollback procedure that restores the original
  `/etc/pam.d` override from the backup created during installation.

### Multi-user hosts

The host identity is the **machine** (`archlinux`), not a Linux account. The
Linux username is a separate signed field on each request. Pairing should stay
per host and device; re-pairing the same host with the same device key would
currently replace the same host record, not create a useful per-user record.

Recommended model:

- The host registry stores an allow-list of Linux users/UIDs per paired device.
- Pairing defaults to the account that started the host-side pairing; root or a
  host administrator can add another account later.
- The phone shows the host as `archlinux` plus **Accounts: desktop, alice** (or
  the configured labels).
- The host enforces the allow-list on every request.
- The phone displays the signed username and may keep a per-account consent
  toggle. A phone-side deny only narrows; it does not grant another account.
- A user who wants an independent trust relationship should pair their own phone
  (a separate device record), not reuse another user's phone silently.

Account scope is a policy dimension, not a new host identity. Support all of these
without duplicating `host_id`:

| Scope | Pairing | Who authorises | App shows |
|---|---|---|---|
| `self` (default) | The pairing user only | User + host operator | `archlinux` / `desktop` |
| `selected` | A list of accounts | Host admin/root, phone confirms the list | `archlinux` / `desktop, alice` |
| `all` | Every normal account, **excluding root** | root, explicit warning | `archlinux` / all accounts |
| `all+root` | Every account including root | root, separate explicit flag | strong root warning |
| Per-user device | One phone/key per user | That user pairs independently | separate device records |

The recommended defaults are `self` and a separate phone per user when independent
compromise domains are wanted. `selected` and `all` are convenience modes for a
shared phone; they do not change the device key. `all+root` should be treated as a
deliberate, strongly discouraged policy.

If the phone must enforce the allow-list locally, the host needs to advertise it:
a `PAIRING_RESULT` account list, a capability/policy message after pairing, or a
signed `SESSION_HELLO` extension. The host policy remains authoritative even if
the phone list is stale. A sensible wire shape is:

```text
account_scope: "self" | "selected" | "all"
accounts: ["desktop", "alice"]   // only for selected
allow_root: false                // separate, default false
```

The scope and accounts must be bound to the pairing transcript or a signed policy
message; the device displays the final scope and the host enforces it. Expanding
the scope later should require host authorisation and, ideally, a fresh phone
confirmation. Shrinking the scope can be host-side.

A shared device key across accounts means a compromised phone can approve any
account in its scope. Per-account toggles are consent filters, not separate
security domains. Users who need independent compromise domains should pair
separate phones/keys.

Do not model this as `host_id = archlinux/alice`. That would duplicate host
identity and TLS pins per account and make the machine look like many hosts.

### Worked multi-user scenarios

**One PC, two users, two phones.** This is the recommended independent-trust
model:

```text
host: archlinux
  phone A -> device record A, account_scope=self, accounts=[desktop]
  phone B -> device record B, account_scope=self, accounts=[alice]

desktop is in wheel; alice is not.
```

- Phone A can authenticate `desktop` for login, unlock, polkit and `sudo`.
  Whether `sudo` actually succeeds is still decided by `sudoers`; the phone
  proves *who* desktop is, it does not grant the privilege.
- Phone B can authenticate `alice` for login, unlock and user-level polkit
  prompts. It cannot make `sudo` succeed because `alice` is not in `sudoers`.
  The host should also refuse to send `auth.sudo` requests to a device whose
  account scope does not include an account allowed to use it.
- A request for `desktop` from phone B must be refused by the host before the
  phone is asked. The phone is not a second authorization system.
- The two phones have separate device keys; compromise of one does not become
  compromise of the other.

**One phone, two users.** Supported through `selected` scope, but it is one
compromise domain:

```text
phone A -> account_scope=selected, accounts=[desktop, alice]
```

The phone shows both accounts. The host still enforces each account's normal
rights. A phone compromise can approve any account in its scope; use separate
phones if that matters.

**One phone, all normal accounts.** `account_scope=all`, excluding root. This is
convenience for a shared device and a larger blast radius. It does not make every
account an administrator.

**Root.** `allow_root` is separate and defaults to false. `all+root` is a
deliberate, strongly discouraged policy; root can already change `sudoers`,
polkit and PAM, so treating a phone as a root factor deserves its own warning and
audit entry.

### Per-account and per-device policy matrix

A device is not just “allowed” or “not allowed”. The host policy needs four
separate questions:

1. **Device principal** — whose phone is it? (`desktop`'s phone, `alice`'s phone)
2. **Target account** — which Linux user is being authenticated? (`desktop` or
   `alice`)
3. **Operation** — login, unlock, user-level auth, polkit action, `sudo`, root?
4. **Device consent** — does the phone user approve this specific request now?

The effective decision is the intersection of all four, plus the account's normal
`sudoers`/polkit rights. A phone can never grant a right the account does not
already have.

Example configuration for 1 PC, 2 phones, 2 accounts:

```text
account desktop  (in wheel)
  phone A -> principal desktop
  phone B -> principal alice

account alice    (not in wheel)
```

| Target account | Operation | Phone A (desktop) | Phone B (alice) |
|---|---|---|---|
| desktop | login / unlock / user auth | allowed, configurable | **denied by default**; can be enabled as delegated login |
| desktop | `sudo` / elevated polkit | allowed by host policy; still checked by sudoers/polkit | **never** |
| alice | login / unlock / user auth | **denied by default**; can be enabled as delegated login | allowed, configurable |
| alice | `sudo` / elevated polkit | no; alice has no sudo rights | **never** |

This gives every combination you described:

- **Phone login for the non-root user can be disabled entirely.** Set
  `phone_login=false` for `alice`; PAM ignores the phone module for that account
  and the password is required.
- **Phone login for the non-root user can be enabled** for alice's own phone,
  limited to login/unlock/user-level auth.
- **The sudo user's phone can be allowed to log in as alice** as a delegated
  login, or denied. Default: denied.
- **The non-root phone can never get elevated rights**, even if its owner asks.
  The host should not send `sudo`/root requests to it; sudoers/polkit still deny
  if one somehow arrives.
- **The non-root phone cannot log in as the sudo user** unless the host
  administrator explicitly enables that delegation; default: denied.

Suggested policy fields:

```text
account alice:
  phone_login: false | true
  allowed_phones: [phone-B]           # or a device-id list
  allow_delegated_login_from: [phone-A]  # default empty
  allowed_operations: [login, unlock, user-auth]
  allow_elevated: false               # always false unless root policy says otherwise

account desktop:
  phone_login: true
  allowed_phones: [phone-A]
  allow_delegated_login_from: []
  allowed_operations: [login, unlock, user-auth, sudo, polkit-admin]
  allow_elevated: true                # still constrained by sudoers/polkit
```

Cross-account authentication is **delegation**, not identity sharing: the phone
prompt must show both “who is approving” and “which account is being signed in”.
Audit it as a delegated decision. Default it to off. A shared phone or a phone
allowed to log in as another account is one compromise domain; separate phones
remain the stronger model.

Do not implement this by reusing an admin session or by silently switching the
signed username. The target account is always in the signed request; the host
policy decides whether that device is permitted to name it.

### Authentication is not authorization

| Layer | Decides | Phone role |
|---|---|---|
| Pairing | Is this device/host key trusted? | Consent + code entry |
| Account scope | Which Linux accounts may this device approve? | Displays and may narrow |
| PAM authentication | Is this the claimed user? | Strong-biometric signature |
| `sudoers` | May this user run `sudo`? | None |
| polkit | Is this action allowed for this user? | None; the prompt may use PAM |
| Phone consent | Does the human approve this request? | Final accept/deny |

A phone for a non-admin user is therefore useful without any root access: it
replaces password entry for login, screen unlock and user-level authentication
prompts. It cannot turn that user into an administrator, and the host must never
present it as if it could.

### Installation and account scope

Installing a PAM/polkit/GDM line is machine-wide and needs root. The account
scope and per-user enable/disable policy are separate:

- a user can enable/disable their own operations without root;
- a phone can mask an operation without root;
- adding an account to a phone's scope, enabling global actions, or allowing root
  needs host administrator/root authorization;
- uninstalling the integration needs root.


### Capability IDs, not generic labels

A toggle for "systemctl" is too broad. Negotiate the actual action identifiers,
for example:

- `auth.sudo`
- `auth.su`
- `org.freedesktop.policykit.exec`
- `org.freedesktop.systemd1.manage-units`
- `login.gdm`
- `login.console`
- `login.sshd`
- `unlock.screen`

The phone displays only actions the host advertises, and the host still enforces
its own policy. A stale toggle for an action the host no longer advertises is
ignored, not treated as consent.

## CLI and pairing UX

The current `phone-authctl pair` flow is secure enough to finish a pairing, but
the interaction is awkward and misleading. It should feel like `adb`, not like a
guided wizard.

### What it does today

```text
$ sudo phone-authctl pair
Pairing open for 120s.
Start pairing on the phone now.

Pairing code (shown only here; enter it on the phone):

      ┌────────────────┐
      │  198168  │
      └────────────────┘

Send this pairing to the phone? [y/N] y
Confirming pairing…
Host record saved. Enter the code on the phone to finish pairing.
Host side pairing finished.
```

Problems:

- The host asks `Send this pairing to the phone?` **after** already showing the
  code and receiving the phone's submission. The question describes an action
  that already happened.
- `Host record saved` appears before the phone has confirmed anything. The host
  has persisted its side; the phone may still reject, timeout or lose the link.
  This reads like success when the pairing is not finished.
- The boxed code is noisy, and the important value is buried in prose.
- The command exits as soon as the host side is done, without saying whether the
  phone stored the host. A user has to guess from the app.
- `sudo` or a fresh group login is needed for the control socket, and the error
  does not explain the stale-group case. `phone-authctl pair` should work as the
  desktop user, and a permission failure should print the exact `newgrp`/re-login
  hint.
- `list` is a prose dump, not a stable table, and there is no single place to see
  `paired / connected / pending / revoked`.
- `--yes` is a footgun that exists only to skip a redundant prompt.

### Target: adb-like behavior

One explicit command opens a short-lived pairing session, prints one code, waits,
and reports one final result:

```text
$ phone-authctl pair
Waiting for phone... (120s)
Code: 198168  type this on the phone

Paired  Pixel 9
  host    archlinux
  device  91620145
```

- No host-side `[y/N]`. Running `pair` is already the operator's decision; the
  phone's typed code or Allow is the human gate. If a host confirmation is ever
  wanted, make it an explicit `--confirm`, not the default.
- Print the code as a plain line, not box art. Keep it out of logs.
- Do not print `Paired` until the phone has persisted the host and acknowledged
  it. Before that, say `Waiting for phone confirmation`.
- On failure, print one line and a non-zero exit:
  `Pairing failed: code mismatch` / `Pairing timed out` / `Pairing cancelled on phone`.
- Stable exit codes: `0` paired, `1` failure, `2` usage/cannot connect.
- Ctrl-C cancels the session; the host must delete the pending record.
- `--json` emits one machine-readable object with `state`, `code`, `device`,
  `host`, `expires_at` and `error`; human text goes to stderr when `--json` is on.
- `--timeout` changes the session lifetime; it does not change the protocol
  maximum.

A device view should be boring and scriptable, like `adb devices`:

```text
$ phone-authctl devices
DEVICE                    MODEL                 STATE       LAST SEEN
Pixel 9 (91620145)        motorola edge 30 ultra connected   12:08
```

`phone-authctl list` can remain as an alias for one release, then be retired.

### Protocol change needed for honest completion

Right now the host persists its device record before it sends `PAIRING_RESULT`,
while the phone persists only after its human gate. That is why the CLI can say
`Host record saved` while the phone still has not accepted.

To make the CLI truthful, add a final device-to-host acknowledgement after the
phone persists, for example `PAIRING_CONFIRMED`:

1. Host verifies `device_mac`, stores the record as **pending**, sends
   `PAIRING_RESULT`.
2. Phone verifies `host_mac`, asks the operator, then persists.
3. Phone sends `PAIRING_CONFIRMED` (bound to the same session/transcript).
4. Host promotes the record to **paired** and the CLI prints `Paired`.
5. Timeout, rejection, code mismatch or link loss deletes the pending record.

Until that exists, the CLI must not claim the pairing is complete; it should say
`Host side complete; waiting for the phone` and leave the final state to
`phone-authctl devices`.

### Acceptance criteria

- [ ] `phone-authctl pair` is one command, one code line, one final result.
- [ ] No default `[y/N]` and no `--yes` requirement.
- [ ] No `Paired`/`Host record saved` text before the phone confirms.
- [ ] Pending records are separate from paired records and are cleaned on
      timeout, rejection, mismatch or disconnect.
- [ ] Device-to-host `PAIRING_CONFIRMED` is specified, implemented in Rust and
      Kotlin, and covered by vectors.
- [ ] `phone-authctl devices` prints a stable table; `--json` prints one object.
- [ ] Permission denied explains `newgrp phone-auth` / re-login, and normal
      pairing works without `sudo` for a user in the `phone-auth` group.
- [ ] `phone-authctl unpair <device>` is a first-class command, not only a hidden
      daemon operation.
- [ ] README and `docs/pairing.md` use the real command transcript.

## Roadmap phases

### Phase 0 — Security remediation

Do these before expanding the platform surface:

- [x] SEC-001: bind the pairing code to an ephemeral ECDH secret and the full
      transcript; add the MITM regression test. A PAKE remains a future upgrade.
- [ ] Pairing upgrade: replace the six-digit SAS with CPace/SPAKE2 or a
      high-entropy QR/NFC secret. Keep ECDH + SAS until a reviewed implementation
      ships; do not hand-roll a PAKE in Kotlin.
- [ ] SEC-003: stop recommending global `common-auth`; scope PAM integration and
      add number matching for authentication.
- [ ] SEC-004: bind each paired device to allowed Linux users; deny root by
      default.
- [ ] SEC-005: design opt-in Android Key Attestation and downgrade policy.
- [ ] SEC-006: verify the control-socket server from the PAM client.
- [ ] SEC-007: persistent rate limits and parser fuzzing remain; connection
      caps, handshake/frame deadlines and the explicit bind policy are done.
- [ ] SEC-009: panic containment and FFI review in the PAM module.
- [x] SEC-021/022/023/024: bounded IPC reads and deadlines, timeout clamp,
      trusted prompt context, connection caps and frame deadlines.
- [ ] Release-signed Android build and a test matrix beyond one debug device.

### Phase 1 — Linux production integration

- [ ] Implement the adb-like pairing and device UX described in
      [CLI and pairing UX](#cli-and-pairing-ux): one code line, no default
      confirmation prompt, truthful completion, `devices --json`, `unpair`.
- [ ] Fix VPN/Tailscale coexistence as described in
      [Known network issue](#known-network-issue-vpn--tailscale): try all resolved
      addresses, bind sockets to the chosen `Network`, reconnect on VPN/Wi-Fi
      changes, and stop advertising unintended interfaces by default.
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
- [ ] Store an account allow-list per paired device; default to the pairing user,
      add other accounts through host policy, and show them in the app.
- [ ] Do not require re-pairing the same host for each Linux user; keep host
      identity machine-scoped and user identity per request.
- [ ] Document install/enable/disable/phone-mask/uninstall as distinct states.
- [ ] Implement the per-account/per-device matrix: `phone_login`,
      `allowed_phones`, `allow_delegated_login_from`, `allowed_operations`, and
      `allow_elevated`.
- [ ] Show both the approving principal and the target account on the phone;
      audit delegated login separately.
- [ ] Refuse to send `sudo`/elevated requests to a device whose policy cannot
      approve them, before the phone is prompted.

### Phase 2 — Capability protocol v1

- [ ] Specify the capability message family and canonical encoding.
- [ ] Add host/device policy intersection rules and tests.
- [ ] Add toggles in Android and the host CLI for supported operations.
- [ ] Add downgrade/mismatch tests and a "required capability missing" failure.
- [ ] Add shared vectors and a conformance run for the new messages.
- [ ] Keep capabilities separate from authorization; document the distinction.
- [ ] Add `account_scope`/`accounts`/`allow_root` to pairing or policy exchange,
      with scope expansion requiring host authorization and phone confirmation.

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
