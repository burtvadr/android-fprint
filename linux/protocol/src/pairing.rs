//! Pairing: explicit, short-lived, and bound to a code the operator verifies on
//! both screens (`PROTOCOL.md` §6).

use zeroize::Zeroize;

use crate::cbor::{self, Value};
use crate::crypto::{self, PublicKey};
use crate::errors::{ProtocolError, Result};
use crate::types::{
    req_bytes, req_id, req_text, req_uint, Id, CHALLENGE_LEN, ID_LEN, PAIRING_CODE_DIGITS,
    PAIRING_TTL,
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

    /// The six-digit code the operator compares on both screens.
    pub fn code(&self) -> Result<String> {
        let p = self.confirmation_key()?;
        let v = p[0] as u64 % 1_000_000u64;
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
    /// chose nothing, both sides derive a code and the operator compares the two
    /// screens by eye.
    pub code: String,
    pub expires_at: u64,
    pub host_nonce: [u8; CHALLENGE_LEN],
}

impl PairingStart {
    #[allow(clippy::too_many_arguments)]
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map([
            ("code", Value::text(self.code.clone())),
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
}

impl PairingSubmit {
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map([
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
        ]))
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
        Ok(PairingSubmit {
            session_id: req_id(&v, "session_id")?,
            device_id: req_id(&v, "device_id")?,
            device_name: req_text(&v, "device_name")?,
            device_pubkey: PublicKey::from_bytes(req_bytes(&v, "device_pubkey")?)?,
            device_key_id: req_text(&v, "device_key_id")?,
            device_nonce,
            mac,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingResult {
    pub session_id: Id,
    pub status: u64,
    pub host_mac: Option<[u8; 32]>,
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
        Ok(PairingResult {
            session_id: req_id(&v, "session_id")?,
            status,
            host_mac,
        })
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
        };
        assert_eq!(
            PairingSubmit::from_payload(&submit.to_payload()).unwrap(),
            submit
        );

        let result = PairingResult {
            session_id: start.session_id,
            status: 0,
            host_mac: Some([7u8; 32]),
        };
        assert_eq!(
            PairingResult::from_payload(&result.to_payload()).unwrap(),
            result
        );

        let rej = PairingResult {
            session_id: start.session_id,
            status: 1,
            host_mac: None,
        };
        assert_eq!(PairingResult::from_payload(&rej.to_payload()).unwrap(), rej);
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
            expires_at: crate::unix_now() + 30,
            host_nonce: [3u8; 32],
        };
        assert!(PairingStart::from_payload(&start.to_payload()).is_ok());
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
