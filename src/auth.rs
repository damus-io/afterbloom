use anyhow::{anyhow, bail, Result};
use base64::Engine;
use secp256k1::{schnorr::Signature, XOnlyPublicKey, SECP256K1};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const KIND_BLOSSOM_AUTH: u32 = 24242;

#[derive(Debug, Deserialize)]
pub struct AuthEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Upload,
    List,
    Delete,
}

impl Action {
    fn as_str(&self) -> &'static str {
        match self {
            Action::Upload => "upload",
            Action::List => "list",
            Action::Delete => "delete",
        }
    }
}

pub struct VerifiedAuth {
    pub pubkey: String,
    pub hashes: Vec<String>,
}

/// Parse the `Authorization: Nostr <base64>` header.
pub fn parse_header(header: &str) -> Result<AuthEvent> {
    let rest = header
        .strip_prefix("Nostr ")
        .ok_or_else(|| anyhow!("authorization scheme must be 'Nostr'"))?;
    let json = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .map_err(|e| anyhow!("invalid base64: {e}"))?;
    let event: AuthEvent =
        serde_json::from_slice(&json).map_err(|e| anyhow!("invalid auth event json: {e}"))?;
    Ok(event)
}

/// Verify the auth event signature, ID, kind, expiration, and required action tag.
/// `max_lifetime_seconds` caps how far in the future the `expiration` tag may be.
pub fn verify(
    event: &AuthEvent,
    expected_action: Action,
    max_lifetime_seconds: u64,
) -> Result<VerifiedAuth> {
    if event.kind != KIND_BLOSSOM_AUTH {
        bail!("wrong kind: expected {KIND_BLOSSOM_AUTH}, got {}", event.kind);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    if event.created_at > now + 60 {
        bail!("created_at is in the future");
    }

    let expiration = find_single_tag(&event.tags, "expiration")
        .ok_or_else(|| anyhow!("missing 'expiration' tag"))?
        .parse::<i64>()
        .map_err(|_| anyhow!("invalid 'expiration' tag"))?;

    if expiration <= now {
        bail!("auth event expired");
    }
    if expiration > now + max_lifetime_seconds as i64 {
        bail!(
            "auth event expiration is too far in the future (max {max_lifetime_seconds}s)"
        );
    }

    let action = find_single_tag(&event.tags, "t")
        .ok_or_else(|| anyhow!("missing action ('t') tag"))?;
    if action != expected_action.as_str() {
        bail!(
            "action mismatch: auth is for '{action}', request needs '{}'",
            expected_action.as_str()
        );
    }

    let computed_id = compute_event_id(event)?;
    if computed_id != event.id {
        bail!("event id mismatch");
    }

    let pubkey_bytes = hex::decode(&event.pubkey).map_err(|_| anyhow!("invalid pubkey hex"))?;
    let pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|_| anyhow!("invalid pubkey"))?;
    let sig_bytes = hex::decode(&event.sig).map_err(|_| anyhow!("invalid sig hex"))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|_| anyhow!("invalid sig"))?;
    let id_bytes = hex::decode(&event.id).map_err(|_| anyhow!("invalid id hex"))?;
    if id_bytes.len() != 32 {
        bail!("invalid id length");
    }

    SECP256K1
        .verify_schnorr(&sig, &id_bytes, &pubkey)
        .map_err(|_| anyhow!("signature verification failed"))?;

    let hashes = event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "x")
        .map(|t| t[1].to_lowercase())
        .collect();

    Ok(VerifiedAuth {
        pubkey: event.pubkey.to_lowercase(),
        hashes,
    })
}

fn find_single_tag<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// Compute NIP-01 event ID: sha256 of `[0, pubkey, created_at, kind, tags, content]`
/// serialized as compact JSON.
fn compute_event_id(event: &AuthEvent) -> Result<String> {
    let canonical = serde_json::json!([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content,
    ]);
    let serialized = serde_json::to_string(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}
