//! Pairing: explicit, short-lived, and bound to a code the operator verifies on
//! both screens (`PROTOCOL.md` §6).

use zeroize::Zeroize;

use crate::cbor::{self, Value};
use crate::crypto::{self, PublicKey};
use crate::errors::{ProtocolError, Result};
use crate::types::{
    opt_text, req_bytes, req_id, req_text, req_uint, Id, CHALLENGE_LEN, ID_LEN,
    PAIRING_CODE_DIGITS, PAIRING_TTL,
};

/// `PROTOCOL.md` §6.4. Holds the session secret between `PAIRING_START` and
/// `PAIRING_RESULT`, and is zeroized on drop.
pub struct PairingSession {
    pub session_id: Id,
    pub host_nonce: [u8; CHALLENGE_LEN],
    pub device_nonce: [u8; CHALLENGE_LEN],
    secret: [u8; 32],
}

impl PairingSession {
    /// Host side: derive the session secret before the device nonce is known.
    /// `derive_with_device_nonce` completes it once the device responds.
    pub fn new(session_id: Id, host_nonce: [u8; CHALLENGE_LEN]) -> PairingSession {
        let mut secret = [0u8; 32];
        // With an all-zero device nonce this is only a placeholder; the real
        // secret is computed in `derive_with_device_nonce`.
        secret.fill(0);
        PairingSession {
            session_id,
            host_nonce,
            device_nonce: [0u8; CHALLENGE_LEN],
            secret,
        }
    }

    /// Computes the true session secret once both nonces exist.
    pub fn derive_with_device_nonce(&mut self, device_nonce: [u8; CHALLENGE_LEN]) -> Result<()> {
        self.device_nonce = device_nonce;
        let mut ikm = Vec::with_capacity(CHALLENGE_LEN * 2);
        ikm.extend_from_slice(&self.host_nonce);
        ikm.extend_from_slice(&device_nonce);
        crypto::hkdf_sha256(
            &ikm,
            crypto::SALT_PAIR,
            &self.session_id.0,
            &mut self.secret,
        )?;
        ikm.zeroize();
        Ok(())
    }

    /// `p = HMAC(pairing_secret, "ALP-PAIR-V1" || 0x00 || session_id)`.
    pub fn confirmation_key(&self) -> Result<[u8; 32]> {
        let mut msg = Vec::with_capacity(crypto::DOMAIN_PAIR.len() + 1 + ID_LEN);
        msg.extend_from_slice(crypto::DOMAIN_PAIR);
        msg.push(0x00);
        msg.extend_from_slice(&self.session_id.0);
        Ok(crypto::hmac_sha256(&self.secret, &msg))
    }

    /// The six-digit code the operator types on the other endpoint.
    ///
    /// This is rejection sampling, not a modulo reduction. A 32-bit word has
    /// `4_294_967_296` values; `4_294_000_000` is the largest multiple of
    /// `1_000_000` below that, so rejecting words at or above it leaves every
    /// code 000000..999999 with exactly 4,294 chances. The first eight words of
    /// the HMAC are tried; if all are rejected (probability about 6e-30), another
    /// block is expanded under a separate domain.
    pub fn code(&self) -> Result<String> {
        let p = self.confirmation_key()?;
        let v = code_from_material(&p);
        Ok(format!("{:0width$}", v, width = PAIRING_CODE_DIGITS))
    }

    /// The transcript bound into both confirmation MACs.
    fn transcript(
        &self,
        host_id: &Id,
        device_id: &Id,
        host_pub: &PublicKey,
        device_pub: &PublicKey,
    ) -> Vec<u8> {
        let mut t = Vec::with_capacity(ID_LEN * 2 + crypto::PUBKEY_LEN * 2 + CHALLENGE_LEN * 2);
        t.extend_from_slice(&self.session_id.0);
        t.extend_from_slice(&host_id.0);
        t.extend_from_slice(&device_id.0);
        t.extend_from_slice(host_pub.as_bytes());
        t.extend_from_slice(device_pub.as_bytes());
        t.extend_from_slice(&self.host_nonce);
        t.extend_from_slice(&self.device_nonce);
        t
    }

    pub fn device_mac(
        &self,
        host_id: &Id,
        device_id: &Id,
        host_pub: &PublicKey,
        device_pub: &PublicKey,
    ) -> Result<[u8; 32]> {
        let p = self.confirmation_key()?;
        let mut msg = Vec::with_capacity(crypto::DOMAIN_DEVICE_CONFIRM.len() + 1 + 512);
        msg.extend_from_slice(crypto::DOMAIN_DEVICE_CONFIRM);
        msg.push(0x00);
        msg.extend_from_slice(&self.transcript(host_id, device_id, host_pub, device_pub));
        Ok(crypto::hmac_sha256(&p, &msg))
    }

    pub fn host_mac(
        &self,
        host_id: &Id,
        device_id: &Id,
        host_pub: &PublicKey,
        device_pub: &PublicKey,
    ) -> Result<[u8; 32]> {
        let p = self.confirmation_key()?;
        let mut msg = Vec::with_capacity(crypto::DOMAIN_HOST_CONFIRM.len() + 1 + 512);
        msg.extend_from_slice(crypto::DOMAIN_HOST_CONFIRM);
        msg.push(0x00);
        msg.extend_from_slice(&self.transcript(host_id, device_id, host_pub, device_pub));
        Ok(crypto::hmac_sha256(&p, &msg))
    }

    /// Constant-time check of a MAC received from a peer.
    pub fn verify_mac(received: &[u8], expected: &[u8]) -> Result<()> {
        if !crypto::ct_eq_slice(received, expected) {
            return Err(ProtocolError::SignatureInvalid);
        }
        Ok(())
    }
}

impl Drop for PairingSession {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.host_nonce.zeroize();
        self.device_nonce.zeroize();
    }
}

impl std::fmt::Debug for PairingSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the session secret or either nonce.
        f.debug_struct("PairingSession")
            .field("session_id", &self.session_id.to_hex())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Rejection-samples a uniform six-digit code from the confirmation key.
///
/// `4_294_000_000` is `4_294 * 1_000_000`; rejecting words at or above it makes
/// every residue `0..1_000_000` equally likely. The first block is the 256-bit
/// HMAC; the expansion below is only reached with probability about 6e-30.
fn code_from_material(p: &[u8; 32]) -> u64 {
    const LIMIT: u64 = 4_294_000_000;
    let mut block = *p;
    let mut counter: u64 = 0;
    loop {
        for chunk in block.chunks_exact(4) {
            let v = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
            if v < LIMIT {
                return v % 1_000_000;
            }
        }
        counter += 1;
        let mut msg = Vec::with_capacity(crypto::DOMAIN_PAIR_CODE.len() + 1 + 8);
        msg.extend_from_slice(crypto::DOMAIN_PAIR_CODE);
        msg.push(0x00);
        msg.extend_from_slice(&counter.to_be_bytes());
        block = crypto::hmac_sha256(p, &msg);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CodeEntry {
    /// The Linux host displays the code; the phone must not display it and must
    /// require the operator to type it.
    #[default]
    Device,
    /// The phone displays the code; the Linux host must not display it and must
    /// require the operator to type it.
    Host,
}

impl CodeEntry {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Host => "host",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "device" => Ok(Self::Device),
            "host" => Ok(Self::Host),
            other => Err(ProtocolError::BadRequest(format!(
                "unknown code_entry {other:?}; expected device or host"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingStart {
    pub session_id: Id,
    pub host_id: Id,
    pub host_pubkey: PublicKey,
    pub host_key_id: String,
    /// The operator-chosen code, or the empty string when the host did not
    /// choose one.
    ///
    /// A six-digit code cannot be derived from the host nonce alone: it depends
    /// on the device nonce as well, and the device only produces that nonce after
    /// receiving this message. So when the operator chose a code, the device
    /// checks its own derived value against it and fails fast; when the operator
    /// chose nothing, both sides derive the same code independently.
    pub code: String,
    /// Which endpoint must type the derived code.
    ///
    /// The other endpoint displays it, and the displaying endpoint MUST NOT also
    /// accept a bare confirmation tap.
    pub code_entry: CodeEntry,
    pub expires_at: u64,
    pub host_nonce: [u8; CHALLENGE_LEN],
}

impl PairingStart {
    #[allow(clippy::too_many_arguments)]
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map([
            ("code", Value::text(self.code.clone())),
            ("code_entry", Value::text(self.code_entry.as_str())),
            ("expires_at", Value::Uint(self.expires_at)),
            ("host_id", Value::Bytes(self.host_id.0.to_vec())),
            ("host_key_id", Value::text(self.host_key_id.clone())),
            ("host_nonce", Value::Bytes(self.host_nonce.to_vec())),
            (
                "host_pubkey",
                Value::Bytes(self.host_pubkey.as_bytes().to_vec()),
            ),
            ("session_id", Value::Bytes(self.session_id.0.to_vec())),
        ]))
    }

    pub fn from_payload(payload: &[u8]) -> Result<PairingStart> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("pairing_start payload: {e}")))?;
        let code = req_text(&v, "code")?;
        // Empty means "the host did not choose a code"; otherwise it must be six
        // ASCII digits.
        if !code.is_empty()
            && (code.len() != PAIRING_CODE_DIGITS || !code.chars().all(|c| c.is_ascii_digit()))
        {
            return Err(ProtocolError::BadRequest(
                "code must be empty or exactly six ASCII digits".into(),
            ));
        }
        // Absent means the recommended mode: the host displays, the phone types.
        let code_entry = opt_text(&v, "code_entry")?
            .as_deref()
            .map(CodeEntry::parse)
            .transpose()?
            .unwrap_or_default();
        let expires_at = req_uint(&v, "expires_at")?;
        let now = crate::unix_now();
        if expires_at < now || expires_at > now + PAIRING_TTL {
            return Err(ProtocolError::BadRequest(
                "pairing_start expiry outside the permitted window".into(),
            ));
        }
        let nb = req_bytes(&v, "host_nonce")?;
        if nb.len() != CHALLENGE_LEN {
            return Err(ProtocolError::BadRequest(
                "host_nonce must be 32 bytes".into(),
            ));
        }
        let mut host_nonce = [0u8; CHALLENGE_LEN];
        host_nonce.copy_from_slice(nb);
        Ok(PairingStart {
            session_id: req_id(&v, "session_id")?,
            host_id: req_id(&v, "host_id")?,
            host_pubkey: PublicKey::from_bytes(req_bytes(&v, "host_pubkey")?)?,
            host_key_id: req_text(&v, "host_key_id")?,
            code,
            code_entry,
            expires_at,
            host_nonce,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingSubmit {
    pub session_id: Id,
    pub device_id: Id,
    pub device_name: String,
    pub device_pubkey: PublicKey,
    pub device_key_id: String,
    pub device_nonce: [u8; CHALLENGE_LEN],
    pub mac: [u8; 32],
    /// Revocation tokens for older pairings this phone wants the host to clean up.
    ///
    /// These are bearer capabilities, not proof of same-installation identity.
    /// The host processes them after `mac` verifies and before it commits the new
    /// record, so a new key can replace an old one without an operator revoke.
    pub cleanup_tokens: Vec<[u8; 32]>,
}

impl PairingSubmit {
    pub fn to_payload(&self) -> Vec<u8> {
        let mut e: Vec<(&str, Value)> = vec![
            ("device_id", Value::Bytes(self.device_id.0.to_vec())),
            ("device_key_id", Value::text(self.device_key_id.clone())),
            ("device_name", Value::text(self.device_name.clone())),
            ("device_nonce", Value::Bytes(self.device_nonce.to_vec())),
            (
                "device_pubkey",
                Value::Bytes(self.device_pubkey.as_bytes().to_vec()),
            ),
            ("mac", Value::Bytes(self.mac.to_vec())),
            ("session_id", Value::Bytes(self.session_id.0.to_vec())),
        ];
        if !self.cleanup_tokens.is_empty() {
            e.push((
                "cleanup_tokens",
                Value::Array(
                    self.cleanup_tokens
                        .iter()
                        .map(|t| Value::Bytes(t.to_vec()))
                        .collect(),
                ),
            ));
        }
        cbor::encode(&Value::map(e))
    }

    pub fn from_payload(payload: &[u8]) -> Result<PairingSubmit> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("pairing_submit payload: {e}")))?;
        let mb = req_bytes(&v, "mac")?;
        if mb.len() != 32 {
            return Err(ProtocolError::BadRequest("mac must be 32 bytes".into()));
        }
        let mut mac = [0u8; 32];
        mac.copy_from_slice(mb);
        let nb = req_bytes(&v, "device_nonce")?;
        if nb.len() != CHALLENGE_LEN {
            return Err(ProtocolError::BadRequest(
                "device_nonce must be 32 bytes".into(),
            ));
        }
        let mut device_nonce = [0u8; CHALLENGE_LEN];
        device_nonce.copy_from_slice(nb);
        let cleanup_tokens = match v.get("cleanup_tokens") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| match item {
                    Value::Bytes(b) if b.len() == 32 => {
                        let mut token = [0u8; 32];
                        token.copy_from_slice(b);
                        Ok(token)
                    }
                    _ => Err(ProtocolError::BadRequest(
                        "cleanup_tokens entries must be 32-byte strings".into(),
                    )),
                })
                .collect::<Result<Vec<_>>>()?,
            Some(_) => {
                return Err(ProtocolError::BadRequest(
                    "cleanup_tokens must be an array".into(),
                ))
            }
        };
        Ok(PairingSubmit {
            session_id: req_id(&v, "session_id")?,
            device_id: req_id(&v, "device_id")?,
            device_name: req_text(&v, "device_name")?,
            device_pubkey: PublicKey::from_bytes(req_bytes(&v, "device_pubkey")?)?,
            device_key_id: req_text(&v, "device_key_id")?,
            device_nonce,
            mac,
            cleanup_tokens,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingResult {
    pub session_id: Id,
    pub status: u64,
    pub host_mac: Option<[u8; 32]>,
    /// Bearer capability the device uses to revoke this pairing later.
    ///
    /// Sent only over the pinned TLS channel, stored by the device, and stored by
    /// the host only as a SHA-256 hash. It authorizes revocation, not
    /// authentication.
    pub revocation_token: Option<[u8; 32]>,
}

impl PairingResult {
    pub fn to_payload(&self) -> Vec<u8> {
        let mut e: Vec<(&str, Value)> = vec![
            ("session_id", Value::Bytes(self.session_id.0.to_vec())),
            ("status", Value::Uint(self.status)),
        ];
        if let Some(m) = &self.host_mac {
            e.push(("host_mac", Value::Bytes(m.to_vec())));
        }
        if let Some(t) = &self.revocation_token {
            e.push(("revocation_token", Value::Bytes(t.to_vec())));
        }
        cbor::encode(&Value::map(e))
    }

    pub fn from_payload(payload: &[u8]) -> Result<PairingResult> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("pairing_result payload: {e}")))?;
        let status = req_uint(&v, "status")?;
        if status > 1 {
            return Err(ProtocolError::BadRequest("status must be 0 or 1".into()));
        }
        let host_mac = match v.get("host_mac") {
            Some(Value::Bytes(b)) if b.len() == 32 => {
                let mut m = [0u8; 32];
                m.copy_from_slice(b);
                Some(m)
            }
            Some(_) => {
                return Err(ProtocolError::BadRequest(
                    "host_mac must be 32 bytes".into(),
                ))
            }
            None => None,
        };
        if status == 0 && host_mac.is_none() {
            return Err(ProtocolError::BadRequest(
                "a successful pairing result must carry host_mac".into(),
            ));
        }
        let revocation_token = match v.get("revocation_token") {
            Some(Value::Bytes(b)) if b.len() == 32 => {
                let mut t = [0u8; 32];
                t.copy_from_slice(b);
                Some(t)
            }
            Some(_) => {
                return Err(ProtocolError::BadRequest(
                    "revocation_token must be 32 bytes".into(),
                ))
            }
            None => None,
        };
        Ok(PairingResult {
            session_id: req_id(&v, "session_id")?,
            status,
            host_mac,
            revocation_token,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpair {
    pub token: [u8; 32],
}

impl Unpair {
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map([("token", Value::Bytes(self.token.to_vec()))]))
    }

    pub fn from_payload(payload: &[u8]) -> Result<Unpair> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("unpair payload: {e}")))?;
        let bytes = req_bytes(&v, "token")?;
        if bytes.len() != 32 {
            return Err(ProtocolError::BadRequest(
                "revocation token must be 32 bytes".into(),
            ));
        }
        let mut token = [0u8; 32];
        token.copy_from_slice(bytes);
        Ok(Unpair { token })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;

    fn session() -> PairingSession {
        let mut s = PairingSession::new(Id::from_slice(&[1u8; 16]).unwrap(), [2u8; 32]);
        s.derive_with_device_nonce([3u8; 32]).unwrap();
        s
    }

    #[test]
    fn code_is_six_digits_and_stable() {
        let s = session();
        let c = s.code().unwrap();
        assert_eq!(c.len(), 6);
        assert!(c.chars().all(|x| x.is_ascii_digit()));
        assert_eq!(c, s.code().unwrap());
    }

    #[test]
    fn code_uses_more_than_one_byte_of_the_hmac() {
        // A one-byte truncation can only produce 000000..000255. The new code
        // must escape that range for at least one deterministic session.
        for i in 0u8..64 {
            let mut s = PairingSession::new(Id::from_slice(&[i; 16]).unwrap(), [i; 32]);
            s.derive_with_device_nonce([i.wrapping_add(1); 32]).unwrap();
            if s.code().unwrap().parse::<u32>().unwrap() > 255 {
                return;
            }
        }
        panic!("all codes were <= 255; the code is still truncated to one byte");
    }

    #[test]
    fn code_changes_with_the_device_nonce() {
        let a = session().code().unwrap();
        let mut s2 = PairingSession::new(Id::from_slice(&[1u8; 16]).unwrap(), [2u8; 32]);
        s2.derive_with_device_nonce([9u8; 32]).unwrap();
        assert_ne!(a, s2.code().unwrap());
    }

    #[test]
    fn macs_verify_and_detect_substitution() {
        let host_sk = PrivateKey::from_bytes(&[0xA1; 32]).unwrap();
        let dev_sk = PrivateKey::from_bytes(&[0xB2; 32]).unwrap();
        let hid = Id::from_slice(&[0x10; 16]).unwrap();
        let did = Id::from_slice(&[0x20; 16]).unwrap();
        let s = session();

        let mac = s
            .device_mac(&hid, &did, &host_sk.public_key(), &dev_sk.public_key())
            .unwrap();
        assert!(PairingSession::verify_mac(&mac, &mac).is_ok());

        // An attacker substituting its own device key must fail, even though
        // everything else about the transcript is unchanged.
        let evil_sk = PrivateKey::from_bytes(&[0xCC; 32]).unwrap();
        let evil_mac = s
            .device_mac(&hid, &did, &host_sk.public_key(), &evil_sk.public_key())
            .unwrap();
        assert!(PairingSession::verify_mac(&mac, &evil_mac).is_err());

        // Substituting the host key must also fail.
        let evil_host = PrivateKey::from_bytes(&[0xDD; 32]).unwrap();
        let mac2 = s
            .device_mac(&hid, &did, &evil_host.public_key(), &dev_sk.public_key())
            .unwrap();
        assert!(PairingSession::verify_mac(&mac, &mac2).is_err());

        // Device and host MACs use different domain separators.
        let hm = s
            .host_mac(&hid, &did, &host_sk.public_key(), &dev_sk.public_key())
            .unwrap();
        assert_ne!(mac, hm);
    }

    #[test]
    fn message_roundtrips() {
        let host_sk = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let dev_sk = PrivateKey::from_bytes(&[2u8; 32]).unwrap();
        let s = session();

        let start = PairingStart {
            session_id: Id::from_slice(&[1u8; 16]).unwrap(),
            host_id: Id::from_slice(&[2u8; 16]).unwrap(),
            host_pubkey: host_sk.public_key(),
            host_key_id: host_sk.public_key().key_id_hex(),
            code: s.code().unwrap(),
            code_entry: CodeEntry::Device,
            expires_at: crate::unix_now() + 30,
            host_nonce: [3u8; 32],
        };
        assert_eq!(
            PairingStart::from_payload(&start.to_payload()).unwrap(),
            start
        );

        let submit = PairingSubmit {
            session_id: start.session_id,
            device_id: Id::from_slice(&[4u8; 16]).unwrap(),
            device_name: "Pixel 9".into(),
            device_pubkey: dev_sk.public_key(),
            device_key_id: dev_sk.public_key().key_id_hex(),
            device_nonce: [5u8; 32],
            mac: [6u8; 32],
            cleanup_tokens: vec![[8u8; 32]],
        };
        assert_eq!(
            PairingSubmit::from_payload(&submit.to_payload()).unwrap(),
            submit
        );

        let result = PairingResult {
            session_id: start.session_id,
            status: 0,
            host_mac: Some([7u8; 32]),
            revocation_token: Some([9u8; 32]),
        };
        assert_eq!(
            PairingResult::from_payload(&result.to_payload()).unwrap(),
            result
        );

        let rej = PairingResult {
            session_id: start.session_id,
            status: 1,
            host_mac: None,
            revocation_token: None,
        };
        assert_eq!(PairingResult::from_payload(&rej.to_payload()).unwrap(), rej);
    }

    #[test]
    fn unpair_roundtrips() {
        let unpair = Unpair { token: [0x5A; 32] };
        assert_eq!(Unpair::from_payload(&unpair.to_payload()).unwrap(), unpair);
        let short = cbor::encode(&Value::map([("token", Value::Bytes(vec![0u8; 31]))]));
        assert!(Unpair::from_payload(&short).is_err());
    }

    #[test]
    fn pairing_start_rejects_out_of_window_expiry() {
        let host_sk = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let mk = |expires_at| PairingStart {
            session_id: Id::random().unwrap(),
            host_id: Id::random().unwrap(),
            host_pubkey: host_sk.public_key(),
            host_key_id: host_sk.public_key().key_id_hex(),
            code: "123456".into(),
            code_entry: CodeEntry::Host,
            expires_at,
            host_nonce: [3u8; 32],
        };
        let now = crate::unix_now();
        // Expired.
        assert!(PairingStart::from_payload(&mk(now.saturating_sub(5)).to_payload()).is_err());
        // Too far in the future.
        assert!(PairingStart::from_payload(&mk(now + PAIRING_TTL + 60).to_payload()).is_err());
        // Valid.
        assert!(PairingStart::from_payload(&mk(now + 30).to_payload()).is_ok());
    }

    #[test]
    fn pairing_start_accepts_an_empty_code() {
        // The common case: the operator did not choose a code, so the host sends
        // an empty one and both sides derive and display their own.
        let host_sk = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let start = PairingStart {
            session_id: Id::random().unwrap(),
            host_id: Id::random().unwrap(),
            host_pubkey: host_sk.public_key(),
            host_key_id: host_sk.public_key().key_id_hex(),
            code: String::new(),
            code_entry: CodeEntry::Device,
            expires_at: crate::unix_now() + 30,
            host_nonce: [3u8; 32],
        };
        assert!(PairingStart::from_payload(&start.to_payload()).is_ok());
    }

    #[test]
    fn pairing_start_code_entry_roundtrips_and_defaults_to_device() {
        let host_sk = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let start = PairingStart {
            session_id: Id::random().unwrap(),
            host_id: Id::random().unwrap(),
            host_pubkey: host_sk.public_key(),
            host_key_id: host_sk.public_key().key_id_hex(),
            code: String::new(),
            code_entry: CodeEntry::Host,
            expires_at: crate::unix_now() + 30,
            host_nonce: [3u8; 32],
        };
        let payload = start.to_payload();
        assert_eq!(
            PairingStart::from_payload(&payload).unwrap().code_entry,
            CodeEntry::Host
        );

        // An older payload without the field means the recommended mode: the
        // host displays the code and the device types it.
        let value = cbor::decode_canonical(&payload).unwrap();
        let pairs = match value {
            Value::Map(pairs) => pairs,
            _ => panic!("pairing_start is not a map"),
        };
        let without = Value::Map(
            pairs
                .into_iter()
                .filter(|(k, _)| k.as_text() != Some("code_entry"))
                .collect(),
        );
        let payload_without = cbor::encode(&without);
        assert_eq!(
            PairingStart::from_payload(&payload_without)
                .unwrap()
                .code_entry,
            CodeEntry::Device
        );

        // Unknown modes are rejected rather than silently treated as a default.
        let mut pairs = match cbor::decode_canonical(&payload).unwrap() {
            Value::Map(pairs) => pairs,
            _ => unreachable!(),
        };
        for (k, v) in &mut pairs {
            if k.as_text() == Some("code_entry") {
                *v = Value::text("bogus");
            }
        }
        let bad = cbor::encode(&Value::Map(pairs));
        assert!(PairingStart::from_payload(&bad).is_err());
    }

    #[test]
    fn pairing_start_rejects_malformed_code() {
        let host_sk = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let mk = |code: &str| PairingStart {
            session_id: Id::random().unwrap(),
            host_id: Id::random().unwrap(),
            host_pubkey: host_sk.public_key(),
            host_key_id: host_sk.public_key().key_id_hex(),
            code: code.into(),
            code_entry: CodeEntry::Device,
            expires_at: crate::unix_now() + 30,
            host_nonce: [3u8; 32],
        };
        assert!(PairingStart::from_payload(&mk("12345").to_payload()).is_err());
        assert!(PairingStart::from_payload(&mk("1234567").to_payload()).is_err());
        assert!(PairingStart::from_payload(&mk("12a456").to_payload()).is_err());
        assert!(PairingStart::from_payload(&mk("12345a").to_payload()).is_err());
    }

    #[test]
    fn debug_output_leaks_no_secret() {
        let s = session();
        let text = format!("{s:?}");
        let code = s.code().unwrap();
        assert!(
            !text.contains(&code),
            "pairing code leaked into Debug output"
        );
        assert!(!text.contains("secret"));
    }
}
