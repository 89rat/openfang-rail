// openfang-engine — the Rust compute plane for the x402 rail.
//
// Front door (TypeScript worker) handles payments, manifests, pages, failover.
// THIS worker hosts the CPU-bound core: secp256k1 receipt-signature recovery
// (the heaviest operation in the stack), batch verification, and benchmarks.
//
// Endpoints:
//   POST /verify-batch   { receipts: [{ canonical, signature, signer }] }
//                        -> { results: [{ valid, signer_recovered?, error? }], verified, invalid, elapsed_ms }
//   POST /recover        { canonical, signature } -> { address }
//   GET  /benchmark?n=N  -> measured secp256k1 recoveries: { recoveries, elapsed_ms, ops_per_sec }
//   GET  /health
//
// Receipt canonical form (must match the TypeScript worker exactly):
//   v|tool|tool_version|input_hash|output_hash|payer|recipient|amount|nonce|ts|tier
// Signature form: r || s || v(27/28) hex, 65 bytes.

use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::*;

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use tiny_keccak::{Hasher, Keccak};

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// Recover the Ethereum-style address from an (r||s||v27/28) signature over a 32-byte digest.
fn recover_address(digest32: &[u8; 32], sig_hex: &str) -> std::result::Result<String, String> {
    let clean = sig_hex.trim_start_matches("0x");
    if clean.len() != 130 {
        return Err(format!("signature must be 65 bytes hex (130 chars), got {} chars", clean.len()));
    }
    let bytes = hex::decode(clean).map_err(|e| format!("bad signature hex: {e}"))?;
    if !(27..=28).contains(&bytes[64]) {
        return Err(format!("recovery byte must be 27/28, got {}", bytes[64]));
    }
    let rec = RecoveryId::from_byte(bytes[64] - 27).ok_or_else(|| "bad recovery id".to_string())?;
    let sig = Signature::from_slice(&bytes[0..64]).map_err(|e| format!("bad signature: {e}"))?;
    let vk = VerifyingKey::recover_from_prehash(digest32, &sig, rec)
        .map_err(|e| format!("recovery failed: {e}"))?;
    let point = vk.to_encoded_point(false);
    let addr = &keccak256(&point.as_bytes()[1..65])[12..32];
    Ok(format!("0x{}", hex::encode(addr)))
}

/// Verify one receipt: recover signer from canonical, compare to claimed signer.
fn verify_one(rc: &ReceiptInput) -> (bool, Option<String>, Option<String>) {
    let digest = keccak256(rc.canonical.as_bytes());
    match recover_address(&digest, &rc.signature) {
        Ok(recovered) => {
            let ok = recovered.eq_ignore_ascii_case(rc.signer.trim());
            (ok, Some(recovered), None)
        }
        Err(e) => (false, None, Some(e)),
    }
}

fn cors(res: &mut Response) {
    let _ = res.headers_mut().set("Access-Control-Allow-Origin", "*");
}

fn json_ok(v: serde_json::Value) -> Result<Response> {
    let mut res = Response::from_json(&v)?;
    cors(&mut res);
    Ok(res)
}

fn json_error(status: u16, msg: &str) -> Result<Response> {
    let mut res = Response::from_json(&json!({ "error": msg }))?;
    res = res.with_status(status);
    cors(&mut res);
    Ok(res)
}

#[derive(Deserialize, Clone)]
struct ReceiptInput {
    canonical: String,
    signature: String,
    signer: String,
}

#[event(fetch)]
async fn main(mut req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let path = url.path().to_string();
    let method = req.method().clone();

    if method == Method::Options {
        let mut res = Response::empty()?;
        let _ = res.headers_mut().set("Access-Control-Allow-Origin", "*");
        let _ = res.headers_mut().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        let _ = res.headers_mut().set("Access-Control-Allow-Headers", "content-type");
        return Ok(res);
    }

    // query string, parsed manually (worker::Url has no search_params in 0.4)
    let full = url.to_string();
    let qs = full.split('?').nth(1).unwrap_or("").to_string();
    let qp = |key: &str| -> Option<String> {
        qs.split('&').find_map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next()?;
            if k == key { it.next().map(|v| v.to_string()) } else { None }
        })
    };

    if method == Method::Post && path == "/verify-batch" {
        let body = req.text().await?;
        #[derive(Deserialize)]
        struct BatchReq { receipts: Vec<ReceiptInput> }
        let parsed: BatchReq = match serde_json::from_str(&body) {
            Ok(x) => x,
            Err(e) => return json_error(400, &format!("bad body: {e}")),
        };
        if parsed.receipts.is_empty() || parsed.receipts.len() > 500 {
            return json_error(400, "receipts must contain 1-500 items");
        }
        let started = js_sys::Date::now();
        #[derive(Serialize)]
        struct Row { valid: bool, signer_recovered: Option<String>, error: Option<String> }
        let mut results = Vec::with_capacity(parsed.receipts.len());
        let mut valid_count = 0usize;
        for rc in &parsed.receipts {
            let (valid, recovered, err) = verify_one(rc);
            if valid { valid_count += 1; }
            results.push(Row { valid, signer_recovered: recovered, error: err });
        }
        let elapsed = js_sys::Date::now() - started;
        return json_ok(json!({
            "results": results,
            "verified": valid_count,
            "invalid": parsed.receipts.len() - valid_count,
            "elapsed_ms": (elapsed * 1000.0).round() / 1000.0,
            "engine": "rust/wasm32 k256",
        }));
    }

    if method == Method::Post && path == "/recover" {
        let body = req.text().await?;
        #[derive(Deserialize)]
        struct RecReq { canonical: String, signature: String }
        let parsed: RecReq = match serde_json::from_str(&body) {
            Ok(x) => x,
            Err(e) => return json_error(400, &format!("bad body: {e}")),
        };
        let digest = keccak256(parsed.canonical.as_bytes());
        return match recover_address(&digest, &parsed.signature) {
            Ok(addr) => json_ok(json!({ "address": addr })),
            Err(e) => json_error(400, &e),
        };
    }

    if method == Method::Get && path == "/benchmark" {
        let n: u32 = qp("n").and_then(|v| v.parse().ok()).unwrap_or(100).clamp(1, 20_000);
        let sk = SigningKey::from_slice(&[1u8; 32]).map_err(|e| e.to_string())?;
        let digest = [2u8; 32];
        let (sig, recid) = sk.sign_prehash_recoverable(&digest).map_err(|e| e.to_string())?;
        let started = js_sys::Date::now();
        let mut recovered = 0u32;
        for _ in 0..n {
            if VerifyingKey::recover_from_prehash(&digest, &sig, recid).is_ok() {
                recovered += 1;
            }
        }
        let elapsed = js_sys::Date::now() - started;
        let ops = if elapsed > 0.0 { (n as f64) / elapsed * 1000.0 } else { 0.0 };
        return json_ok(json!({
            "recoveries": n,
            "recovered": recovered,
            "elapsed_ms": (elapsed * 1000.0).round() / 1000.0,
            "ops_per_sec": (ops * 1000.0).round() / 1000.0,
            "note": "measured on this edge isolate at request time — real numbers, not claims",
        }));
    }

    if method == Method::Get && path == "/health" {
        return json_ok(json!({
            "ok": true,
            "engine": "openfang-engine",
            "lang": "rust/wasm32",
            "endpoints": ["/verify-batch", "/recover", "/benchmark", "/health"],
        }));
    }

    json_error(404, "no such route (engine: /verify-batch, /recover, /benchmark, /health)")
}
