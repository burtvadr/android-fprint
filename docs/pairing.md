# Pairing

Pairing is the one moment where a stranger's key becomes trusted. Everything else
in the protocol can be replayed, refused or revoked; getting this wrong is how a
system like this is subverted.

## The flow

```text
host                                   device
 │  PAIRING_START { session_id,         │
 │                  host_id, host_pubkey,│
 │                  code?, expires_at,   │
 │                  host_nonce }         │
 ├──────────────────────────────────────►│
 │                                       │  derive p from both nonces
 │                                       │  display the six-digit code
 │  PAIRING_SUBMIT { session_id,         │
 │                   device_id,          │
 │                   device_name,        │
 │                   device_pubkey,      │
 │                   device_nonce,       │
 │                   mac }               │
 │◄──────────────────────────────────────┤
 │  derive the same p                     │
 │  display the code                     │
 │  ── operator confirms both match ──   │
 │  verify mac                           │
 │  persist the device                   │
 │  PAIRING_RESULT { status, host_mac }  │
 ├──────────────────────────────────────►│  verify host_mac
```

Two properties are worth calling out.

**The code is derived, not transported.** It is a function of *both* nonces. The
host cannot compute it before the device contributes its nonce, and the device
must not reveal its nonce before it knows an operator is deliberately pairing. So
the exchange is necessarily two rounds, and both sides compute the code
independently.

**The MACs are reciprocal.** Each side proves it derived the same secret. The
operator's comparison is therefore not just a human ritual: if the MACs verify,
the codes the operator compared really did cover this exchange.

## Operator-chosen codes

`phone-authctl pair --code 123456` puts the code in `PAIRING_START`. The device
checks its own derived value against it and refuses immediately on a mismatch;
the host verifies the same equality before persisting.

This turns "compare two screens and trust a human" into "compare one screen and
trust a commitment", and is the safer option where it is practical. Prefer it.

## What the operator is protected against

| Attack | Outcome |
|---|---|
| A different device is substituted in transit | Its MAC differs, so the host rejects it. The operator's code comparison cannot succeed. |
| A different host is substituted | It cannot produce `host_mac`, so the device rejects it. |
| Replay of an earlier pairing | Both nonces are fresh CSPRNG output per attempt, so the derived code and MACs differ. |
| Passive capture of the exchange | The transcript yields the session secret, but that secret is short-lived and no long-term key is transmitted. Only public keys are retained. |
| An attacker who races the real device | Only one pairing session can be open at a time, and it expires. The second attempt is refused. |

## What the operator is *not* protected against

Stated plainly, because the limitation is inherent to the design rather than a
bug:

* **No forward secrecy.** The session secret is derived from two nonces with
  HKDF, and the MACs are plain HMAC. An attacker who records the pairing
  transcript and *later* obtains the device private key can recompute everything
  and forge a pairing they never participated in. A PAKE (SPAKE2, or an OPAQUE-style
  construction) would prevent this; this design does not use one, and the trade-off
  is documented rather than implied away.
* **No protection from a dishonest operator.** Someone with physical access to both
  screens can approve anything. That is inherent: the person approving is the trust
  anchor.
* **No protection against a compromised device.** A rooted phone can lie about its
  biometric and sign whatever it likes during pairing.

## Why there is no unattended path

There is no mode in which a device that merely *appears* on the network becomes
trusted. `phone-authctl pair` must be run, it expires, a second attempt is refused
while one is open, and the host cannot persist anything until the operator has
confirmed the code. There is deliberately no code path that skips that.

## Revocation

```bash
sudo phone-authctl revoke --device "Pixel 9"
```

Revocation takes effect immediately: the registry entry is marked revoked, the live
connection is dropped, and the next attempt is refused with `REVOKED`. Replacing a
phone requires a new pairing with a new key, and the registry refuses to
re-register a `device_id` against a different key without an explicit revocation
first, so a stale identifier cannot be silently taken over.

## Rate limiting

Pairing is limited to 5 attempts per peer address per 5 minutes, and a live session
cannot be re-opened while another is active. Together these mean a network attacker
cannot use pairing as a way to make a phone display a stream of prompts.