//! Smoke-test helper: emit a base64-encoded Nostr Blossom auth event.
//!
//! Usage:
//!   mkauth <hex-secret-key> <action> [<hash>...]
//!
//! Prints the auth event JSON to stderr and the base64 header value to stdout.

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use secp256k1::{rand::rngs::OsRng, Keypair, SECP256K1};
use sha2::{Digest, Sha256};

fn main() {
    let mut args = env::args().skip(1);
    let sk_hex = args.next().expect("usage: mkauth <hex-sk|new> <action> [hash...]");
    let action = args.next().expect("missing action");
    let hashes: Vec<String> = args.collect();

    let sk_bytes = if sk_hex == "new" {
        let kp = Keypair::new(SECP256K1, &mut OsRng);
        kp.secret_bytes().to_vec()
    } else {
        hex::decode(&sk_hex).expect("bad sk hex")
    };
    let kp = Keypair::from_seckey_slice(SECP256K1, &sk_bytes).expect("bad sk");
    let (xonly, _) = kp.x_only_public_key();
    let pub_hex = hex::encode(xonly.serialize());

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let exp = now + 300;

    let mut tags: Vec<Vec<String>> = vec![
        vec!["t".into(), action.clone()],
        vec!["expiration".into(), exp.to_string()],
    ];
    for h in &hashes {
        tags.push(vec!["x".into(), h.clone()]);
    }

    let event_obj = serde_json::json!({
        "pubkey": pub_hex,
        "created_at": now,
        "kind": 24242,
        "tags": tags,
        "content": "afterbloom smoke",
    });

    let canonical = serde_json::json!([
        0,
        pub_hex,
        now,
        24242,
        tags,
        "afterbloom smoke",
    ]);
    let serialized = serde_json::to_string(&canonical).unwrap();
    let mut h = Sha256::new();
    h.update(serialized.as_bytes());
    let id_bytes: [u8; 32] = h.finalize().into();
    let id_hex = hex::encode(id_bytes);

    let sig = SECP256K1.sign_schnorr(&id_bytes, &kp);
    let sig_hex = hex::encode(sig.as_ref());

    let mut full = event_obj.as_object().unwrap().clone();
    full.insert("id".into(), serde_json::Value::String(id_hex));
    full.insert("sig".into(), serde_json::Value::String(sig_hex));
    let event_json = serde_json::to_string(&serde_json::Value::Object(full)).unwrap();

    eprintln!("sk: {}", hex::encode(&sk_bytes));
    eprintln!("pub: {pub_hex}");
    eprintln!("event: {event_json}");

    let b64 = base64::engine::general_purpose::STANDARD.encode(event_json.as_bytes());
    println!("Nostr {b64}");
}
