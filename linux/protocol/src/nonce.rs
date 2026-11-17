//! Replay protection (`PROTOCOL.md` §10).
//!
//! The important ordering property: a `challenge` is recorded as consumed
//! **before** the signature is verified. If it were recorded afterwards, a
//! replayed but byte-identical response could be re-verified against a new
//! outstanding request whose signature had not yet been checked.

use std::collections::{HashMap, VecDeque};

use crate::errors::{ProtocolError, Result};
use crate::types::{AuthRequest, Challenge, Id, MAX_NONCE_AGE};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Request([u8; 16]),
    Challenge([u8; 32]),
}

#[derive(Debug, Clone)]
struct DeviceState {
    outstanding: Option<(AuthRequest, u64)>,
    consumed: HashMap<Key, u64>,
    order: VecDeque<(u64, Key)>,
}

impl DeviceState {
    fn new() -> Self {
        DeviceState {
            outstanding: None,
            consumed: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn consume(&mut self, k: Key, now: u64) -> bool {
        if self.consumed.contains_key(&k) {
            return false;
        }
        self.consumed.insert(k.clone(), now);
        self.order.push_back((now, k));
        true
    }

    fn was_consumed(&self, k: &Key) -> bool {
        self.consumed.contains_key(k)
    }

    fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(MAX_NONCE_AGE);
        while let Some((t, _)) = self.order.front() {
            if *t > cutoff {
                break;
            }
            let (_, k) = self.order.pop_front().expect("front exists");
            // Only drop if this is the oldest record for that key.
            let still_referenced = self
                .consumed
                .iter()
                .any(|(kk, vv)| *kk == k && *vv >= cutoff);
            if !still_referenced {
                self.consumed.remove(&k);
            }
        }
    }
}

/// Per-device single-use nonce tracking and outstanding-request bookkeeping.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    devices: HashMap<Id, DeviceState>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        ReplayGuard {
            devices: HashMap::new(),
        }
    }

    /// Registers a request as the single outstanding one for `device_id`.
    ///
    /// Fails if a request is already outstanding (one in flight per device) or
    /// if the `request_id` has been used before.
    pub fn begin(&mut self, request: &AuthRequest, now: u64) -> Result<()> {
        let st = self
            .devices
            .entry(request.device_id)
            .or_insert_with(DeviceState::new);
        st.prune(now);
        if let Some((prev, _)) = &st.outstanding {
            // A new request supersedes an unanswered one only by explicit
            // abort, never implicitly: an implicit supersede would let an
            // attacker cancel a legitimate in-flight request.
            if prev.request_id != request.request_id {
                return Err(ProtocolError::BadRequest(format!(
                    "device {} already has request {} outstanding",
                    request.device_id.short(),
                    prev.request_id.short()
                )));
            }
        }
        if st.was_consumed(&Key::Request(request.request_id.0)) {
            return Err(ProtocolError::Replay(format!(
                "request_id {} reused",
                request.request_id.short()
            )));
        }
        // Refuse a reused challenge up front as well, rather than discovering it
        // only when the response arrives.
        if st.was_consumed(&Key::Challenge(request.challenge.0)) {
            return Err(ProtocolError::Replay(format!(
                "challenge {} reused",
                request.challenge.short()
            )));
        }
        st.outstanding = Some((request.clone(), now));
        Ok(())
    }

    /// Consumes the outstanding request's `request_id` and `challenge`, then
    /// returns the request for verification.
    ///
    /// Consuming happens before the caller verifies the signature, so a replay
    /// cannot be replayed a second time even if it is byte-identical.
    pub fn consume_for_verification(
        &mut self,
        device_id: &Id,
        request_id: &Id,
        challenge: &Challenge,
        now: u64,
    ) -> Result<AuthRequest> {
        let st = self
            .devices
            .get_mut(device_id)
            .ok_or_else(|| ProtocolError::Replay("no outstanding request for device".into()))?;
        let (request, _) = st
            .outstanding
            .take()
            .ok_or_else(|| ProtocolError::Replay("no outstanding request for device".into()))?;
        if &request.request_id != request_id {
            // Put nothing back: the outstanding request is now dead, and
            // returning it would let a late response be accepted.
            st.consume(Key::Request(request.request_id.0), now);
            st.consume(Key::Challenge(request.challenge.0), now);
            return Err(ProtocolError::ContextMismatch(
                "response request_id does not match the outstanding request".into(),
            ));
        }
        if &request.challenge != challenge {
            st.consume(Key::Request(request.request_id.0), now);
            st.consume(Key::Challenge(request.challenge.0), now);
            return Err(ProtocolError::ContextMismatch(
                "response challenge does not match the outstanding request".into(),
            ));
        }
        let fresh_request = st.consume(Key::Request(request.request_id.0), now);
        let fresh_challenge = st.consume(Key::Challenge(request.challenge.0), now);
        if !fresh_request {
            return Err(ProtocolError::Replay(format!(
                "request_id {} reused",
                request.request_id.short()
            )));
        }
        if !fresh_challenge {
            return Err(ProtocolError::Replay(format!(
                "challenge {} reused",
                request.challenge.short()
            )));
        }
        Ok(request)
    }

    /// Discards an outstanding request, consuming its identifiers so a later
    /// response for it can never be accepted. Used on timeout, cancellation and
    /// malformed input.
    pub fn abort(&mut self, device_id: &Id, now: u64) {
        let Some(st) = self.devices.get_mut(device_id) else {
            return;
        };
        if let Some((request, _)) = st.outstanding.take() {
            st.consume(Key::Request(request.request_id.0), now);
            st.consume(Key::Challenge(request.challenge.0), now);
        }
    }

    /// True when the given challenge has already been consumed for this device.
    pub fn challenge_was_consumed(&self, device_id: &Id, challenge: &Challenge) -> bool {
        self.devices
            .get(device_id)
            .map(|st| st.was_consumed(&Key::Challenge(challenge.0)))
            .unwrap_or(false)
    }

    /// Expires outstanding requests that can no longer be inside any freshness
    /// window, consuming their identifiers.
    ///
    /// `skew` must be the same effective skew `verifier::check_freshness` uses
    /// for the transport in question, so a request is never discarded before it
    /// would have been rejected anyway.
    pub fn expire_stale(&mut self, now: u64, skew: u64) {
        let stale: Vec<Id> = self
            .devices
            .iter()
            .filter(|(_, st)| {
                st.outstanding
                    .as_ref()
                    .map(|(r, _)| now > r.expires_at.saturating_add(skew))
                    .unwrap_or(false)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.abort(&id, now);
        }
    }

    /// Drops consumed records older than `MAX_NONCE_AGE`.
    pub fn prune(&mut self, now: u64) {
        for st in self.devices.values_mut() {
            st.prune(now);
        }
    }

    pub fn outstanding_count(&self) -> usize {
        self.devices
            .values()
            .filter(|st| st.outstanding.is_some())
            .count()
    }
}

impl Challenge {
    fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id_byte: u8, chal_byte: u8) -> AuthRequest {
        AuthRequest::new(
            Id::from_slice(&[id_byte; 16]).unwrap(),
            Id::from_slice(&[0xAA; 16]).unwrap(),
            Id::from_slice(&[0xBB; 16]).unwrap(),
            "alice".into(),
            "sudo".into(),
            "sudo".into(),
            "authenticate".into(),
            Challenge::from_slice(&[chal_byte; 32]).unwrap(),
            1_000,
            1_030,
            Id::from_slice(&[0xCC; 16]).unwrap(),
        )
        .unwrap()
    }

    const DEVICE: Id = Id([0xBB; 16]);

    #[test]
    fn only_one_outstanding_request_per_device() {
        let mut g = ReplayGuard::new();
        let a = req(1, 1);
        let b = req(2, 2);
        g.begin(&a, 0).unwrap();
        assert!(g.begin(&b, 0).is_err());
        // Idempotent re-begin of the same request is allowed.
        assert!(g.begin(&a, 0).is_ok());
    }

    #[test]
    fn challenge_cannot_be_reused_after_consumption() {
        let mut g = ReplayGuard::new();
        let a = req(1, 7);
        g.begin(&a, 0).unwrap();
        g.consume_for_verification(&DEVICE, &a.request_id, &a.challenge, 1)
            .unwrap();

        // Same challenge, new request id: must be refused.
        let mut b = req(2, 7);
        b.challenge = a.challenge;
        assert!(matches!(g.begin(&b, 2), Err(ProtocolError::Replay(_))));

        let mut c = req(3, 3);
        c.challenge = a.challenge;
        assert!(matches!(g.begin(&c, 2), Err(ProtocolError::Replay(_))));
    }

    #[test]
    fn request_id_cannot_be_reused() {
        let mut g = ReplayGuard::new();
        let a = req(1, 1);
        g.begin(&a, 0).unwrap();
        g.consume_for_verification(&DEVICE, &a.request_id, &a.challenge, 1)
            .unwrap();
        let b = req(1, 9);
        assert!(matches!(g.begin(&b, 2), Err(ProtocolError::Replay(_))));
    }

    #[test]
    fn abort_consumes_identifiers_so_a_late_response_is_refused() {
        let mut g = ReplayGuard::new();
        let a = req(4, 4);
        g.begin(&a, 0).unwrap();
        g.abort(&DEVICE, 1);
        assert!(g
            .consume_for_verification(&DEVICE, &a.request_id, &a.challenge, 2)
            .is_err());
    }

    #[test]
    fn mismatched_response_is_context_mismatch_not_acceptance() {
        let mut g = ReplayGuard::new();
        let a = req(5, 5);
        let other = req(6, 6);
        g.begin(&a, 0).unwrap();
        assert!(matches!(
            g.consume_for_verification(&DEVICE, &other.request_id, &a.challenge, 1),
            Err(ProtocolError::ContextMismatch(_))
        ));
        // And the real response can no longer be accepted afterwards.
        assert!(g
            .consume_for_verification(&DEVICE, &a.request_id, &a.challenge, 2)
            .is_err());
    }

    #[test]
    fn stale_requests_expire() {
        let mut g = ReplayGuard::new();
        let a = req(7, 7);
        g.begin(&a, 0).unwrap();
        assert_eq!(g.outstanding_count(), 1);
        // expires_at = 1030; with skew 10 the deadline is now + 10.
        g.expire_stale(1_030, 0);
        assert_eq!(g.outstanding_count(), 1, "not yet past the deadline");
        g.expire_stale(1_050, 0);
        assert_eq!(g.outstanding_count(), 0);
        // The abandoned request's identifiers are burned.
        assert!(g
            .consume_for_verification(&DEVICE, &a.request_id, &a.challenge, 1_051)
            .is_err());
    }

    #[test]
    fn consumed_records_prune_out_after_max_nonce_age() {
        let mut g = ReplayGuard::new();
        let a = req(8, 8);
        g.begin(&a, 0).unwrap();
        g.consume_for_verification(&DEVICE, &a.request_id, &a.challenge, 1)
            .unwrap();
        assert!(g.challenge_was_consumed(&DEVICE, &a.challenge));
        g.prune(1 + MAX_NONCE_AGE + 10);
        assert!(
            !g.challenge_was_consumed(&DEVICE, &a.challenge),
            "record should be pruned once past MAX_NONCE_AGE"
        );
        // Pruning means a *very* old id becomes reusable, which is acceptable:
        // by then the request could not be inside any freshness window.
    }

    #[test]
    fn unknown_device_has_no_outstanding_request() {
        let mut g = ReplayGuard::new();
        assert!(g
            .consume_for_verification(&DEVICE, &Id([1u8; 16]), &Challenge([2u8; 32]), 0)
            .is_err());
    }
}
