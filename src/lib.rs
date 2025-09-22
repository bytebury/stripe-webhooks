use anyhow::{Result, anyhow};
use hmac::{
    Hmac, Mac,
    digest::{KeyInit, Update},
};
use http::HeaderMap;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub enum StripeEvent {
    CheckoutSessionCompleted(Value),
    CustomerSubscriptionDeleted(Value),
    Unknown(Value),
}

#[derive(Debug, Deserialize)]
pub struct StripeEventRequest {
    pub id: String,
    pub r#type: String,
    pub data: StripeEventData,
}

#[derive(Debug, Deserialize)]
pub struct StripeEventData {
    pub object: Value,
}

pub struct StripeListener {
    secret: String,
}
impl StripeListener {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }

    /// Process a Stripe webhook payload, verifying its signature and parsing the event.
    /// Returns a `StripeEvent` enum variant on success, or an error if verification or parsing fails.
    pub fn process(&self, headers: &HeaderMap, payload: &str) -> Result<StripeEvent> {
        if !self.verify(headers, payload).is_none_or(|x| x) {
            return Err(anyhow!("signature verification failed"));
        }

        let event: StripeEventRequest = serde_json::from_str(payload)
            .map_err(|e| anyhow!("failed to parse Stripe event: {e}"))?;

        match event.r#type.as_str() {
            "checkout.session.completed" => {
                Ok(StripeEvent::CheckoutSessionCompleted(event.data.object))
            }
            "customer.subscription.deleted" => {
                Ok(StripeEvent::CustomerSubscriptionDeleted(event.data.object))
            }
            _ => Ok(StripeEvent::Unknown(event.data.object)),
        }
    }

    fn verify(&self, headers: &HeaderMap, payload: &str) -> Option<bool> {
        let signature_header = headers.get("Stripe-Signature")?.to_str().ok()?;
        let valid = self.verify_signature(signature_header, payload);

        Some(valid)
    }

    fn verify_signature(&self, signature_header: &str, payload: &str) -> bool {
        let (timestamp, signature_hex) = match self.parse_signature(signature_header) {
            Some(x) => x,
            None => return false,
        };
        let signed_payload = format!("{timestamp}.{payload}");

        // HMAC
        let mut mac = match <HmacSha256 as KeyInit>::new_from_slice(self.secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };

        Update::update(&mut mac, signed_payload.as_bytes());
        let expected = mac.finalize().into_bytes();

        // decode header-provided hex signature to bytes
        let sig_bytes = match hex::decode(signature_hex) {
            Ok(v) => v,
            Err(_) => return false,
        };

        if expected.len() != sig_bytes.len() {
            return false;
        }

        // constant-time compare
        expected.as_slice().ct_eq(&sig_bytes).unwrap_u8() == 1
    }

    fn parse_signature(&self, header: &str) -> Option<(String, String)> {
        let mut ts = None;
        let mut sig = None;

        for part in header.split(',') {
            let mut kv = part.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("t"), Some(v)) => ts = Some(v.to_string()),
                // pick the first v1 we see
                (Some("v1"), Some(v)) if sig.is_none() => sig = Some(v.to_string()),
                _ => {}
            }
        }
        match (ts, sig) {
            (Some(t), Some(s)) => Some((t, s)),
            _ => None,
        }
    }
}
