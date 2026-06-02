use crate::models::*;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;

/// 解码 base64url（不含padding）
fn b64url_decode(input: &str) -> Result<Vec<u8>> {
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    let s = padded.replace('-', "+").replace('_', "/");
    Ok(general_purpose::STANDARD.decode(&s)?)
}

/// 将 JWT 字符串解析为 ParsedJwt
pub fn parse_jwt(token: &str) -> Result<ParsedJwt> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("无效的JWT格式：需要三段（header.payload.signature）"));
    }

    let header_bytes = b64url_decode(parts[0])?;
    let payload_bytes = b64url_decode(parts[1])?;

    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| anyhow!("Header解析失败: {}", e))?;
    let payload: JwtPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow!("Payload解析失败: {}", e))?;

    let sig_bytes = b64url_decode(parts[2]).unwrap_or_default();

    Ok(ParsedJwt {
        raw: RawJwt {
            header_b64: parts[0].to_string(),
            payload_b64: parts[1].to_string(),
            signature_b64: parts[2].to_string(),
        },
        header,
        payload,
        signature_hex: hex::encode(&sig_bytes),
    })
}

/// 对已解析的JWT进行全面分析，生成报告
pub fn analyze_jwt(parsed: &ParsedJwt) -> AnalysisReport {
    let now = Utc::now().timestamp();

    // 时间相关分析
    let (is_expired, expiry_info) = match parsed.payload.exp {
        Some(exp) => {
            if exp < now {
                let ago = now - exp;
                (true, format!("已过期 {} 秒前 (exp={})", ago, exp))
            } else {
                let remaining = exp - now;
                (false, format!("有效，剩余 {} 秒 (exp={})", remaining, exp))
            }
        }
        None => (false, "未设置过期时间（exp字段缺失）".to_string()),
    };

    let token_summary = TokenSummary {
        algorithm: parsed.header.alg.clone(),
        is_expired,
        expiry_info,
        issuer: parsed.payload.iss.clone(),
        subject: parsed.payload.sub.clone(),
        has_kid: parsed.header.kid.is_some(),
        has_jku: parsed.header.jku.is_some(),
    };

    let vulnerabilities = detect_vulnerabilities(parsed, now);

    let risk_level = compute_risk(&vulnerabilities);
    let recommendations = generate_recommendations(&vulnerabilities, &token_summary);

    AnalysisReport {
        token_summary,
        vulnerabilities,
        recommendations,
        risk_level,
    }
}

fn detect_vulnerabilities(parsed: &ParsedJwt, now: i64) -> Vec<VulnFinding> {
    let mut findings = Vec::new();
    let alg = parsed.header.alg.to_uppercase();

    // CVE类：alg=none
    if alg == "NONE" {
        findings.push(VulnFinding {
            id: "JWT-001".to_string(),
            name: "Algorithm None 攻击".to_string(),
            severity: Severity::Critical,
            description: "JWT使用alg=none，服务端若不验证算法类型将完全跳过签名校验".to_string(),
            evidence: Some(format!("alg: {}", parsed.header.alg)),
            exploit_hint: Some("将header中alg改为none/None/NONE，去掉签名段，服务端可能接受任意payload".to_string()),
        });
    }

    // 弱算法：HS256/HS384/HS512 使用弱密钥风险（配合爆破模块）
    if alg.starts_with("HS") {
        findings.push(VulnFinding {
            id: "JWT-002".to_string(),
            name: "对称算法弱密钥风险".to_string(),
            severity: Severity::Medium,
            description: "使用HMAC对称算法，若密钥强度不足可被离线爆破".to_string(),
            evidence: Some(format!("alg: {}", parsed.header.alg)),
            exploit_hint: Some("使用bruteforce模块对该token进行字典爆破".to_string()),
        });
    }

    // RS256 -> HS256 混淆攻击
    if alg.starts_with("RS") || alg.starts_with("ES") {
        findings.push(VulnFinding {
            id: "JWT-003".to_string(),
            name: "算法混淆攻击 (RS/ES → HS)".to_string(),
            severity: Severity::High,
            description: "若服务端未强制校验算法类型，可将alg从RS256改为HS256，用公钥作为HMAC密钥伪造签名".to_string(),
            evidence: Some(format!("当前alg: {}", parsed.header.alg)),
            exploit_hint: Some("获取服务端公钥，将alg改为HS256，用公钥内容作为HMAC secret重新签名".to_string()),
        });
    }

    // kid 注入
    if let Some(kid) = &parsed.header.kid {
        if kid.contains("..") || kid.contains('/') || kid.contains('\\') {
            findings.push(VulnFinding {
                id: "JWT-004".to_string(),
                name: "kid路径遍历注入".to_string(),
                severity: Severity::High,
                description: "kid字段包含路径遍历字符，服务端若直接用kid读取密钥文件则存在路径遍历".to_string(),
                evidence: Some(format!("kid: {}", kid)),
                exploit_hint: Some("尝试kid=../../dev/null使密钥为空，或指向可控文件".to_string()),
            });
        }
        if kid.to_lowercase().contains("select") || kid.contains('\'') || kid.contains('"') {
            findings.push(VulnFinding {
                id: "JWT-005".to_string(),
                name: "kid SQL注入风险".to_string(),
                severity: Severity::Critical,
                description: "kid字段包含SQL关键字或引号，服务端若将kid拼入SQL查询则存在注入".to_string(),
                evidence: Some(format!("kid: {}", kid)),
                exploit_hint: Some("尝试kid=' UNION SELECT 'secret'-- 使服务端使用可控密钥".to_string()),
            });
        }
    }

    // jku / x5u SSRF
    if let Some(jku) = &parsed.header.jku {
        findings.push(VulnFinding {
            id: "JWT-006".to_string(),
            name: "jku SSRF / 外部密钥注入".to_string(),
            severity: Severity::High,
            description: "jku字段指定外部JWKS URL，若服务端未限制域名则可控制密钥".to_string(),
            evidence: Some(format!("jku: {}", jku)),
            exploit_hint: Some("将jku改为攻击者控制的JWKS URL，用对应私钥签名".to_string()),
        });
    }
    if let Some(x5u) = &parsed.header.x5u {
        findings.push(VulnFinding {
            id: "JWT-007".to_string(),
            name: "x5u SSRF / 外部证书注入".to_string(),
            severity: Severity::High,
            description: "x5u字段指向外部X.509证书URL，可能造成SSRF或密钥替换".to_string(),
            evidence: Some(format!("x5u: {}", x5u)),
            exploit_hint: None,
        });
    }

    // 过期时间未设置
    if parsed.payload.exp.is_none() {
        findings.push(VulnFinding {
            id: "JWT-008".to_string(),
            name: "缺少过期时间(exp)".to_string(),
            severity: Severity::Medium,
            description: "Token未设置exp字段，一旦签发永久有效，泄露后无法失效".to_string(),
            evidence: None,
            exploit_hint: None,
        });
    }

    // nbf未来时间检测
    if let Some(nbf) = parsed.payload.nbf {
        if nbf > now {
            findings.push(VulnFinding {
                id: "JWT-009".to_string(),
                name: "nbf未来时间（Token尚未生效）".to_string(),
                severity: Severity::Low,
                description: format!("Token的nbf（{}）在当前时间之后，理论上不应被接受", nbf),
                evidence: Some(format!("nbf={}, now={}", nbf, now)),
                exploit_hint: Some("测试服务端是否校验nbf字段".to_string()),
            });
        }
    }

    // iat时钟偏移检测（iat距现在超过24h且token仍有效）
    if let Some(iat) = parsed.payload.iat {
        let age = now - iat;
        if age > 86400 {
            findings.push(VulnFinding {
                id: "JWT-010".to_string(),
                name: "Token长期未刷新".to_string(),
                severity: Severity::Low,
                description: format!("Token签发时间距今已 {} 小时，建议定期刷新", age / 3600),
                evidence: Some(format!("iat={}", iat)),
                exploit_hint: None,
            });
        }
    }

    findings
}

fn compute_risk(findings: &[VulnFinding]) -> RiskLevel {
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        RiskLevel::Critical
    } else if findings.iter().any(|f| f.severity == Severity::High) {
        RiskLevel::High
    } else if findings.iter().any(|f| f.severity == Severity::Medium) {
        RiskLevel::Medium
    } else if findings.iter().any(|f| f.severity == Severity::Low) {
        RiskLevel::Low
    } else {
        RiskLevel::Safe
    }
}

fn generate_recommendations(findings: &[VulnFinding], summary: &TokenSummary) -> Vec<String> {
    let mut recs = Vec::new();
    for f in findings {
        match f.id.as_str() {
            "JWT-001" => recs.push("服务端必须强制校验alg字段，拒绝alg=none的Token".to_string()),
            "JWT-002" => recs.push("使用长度≥32字节的随机密钥，避免使用单词、项目名等弱密钥".to_string()),
            "JWT-003" => recs.push("服务端应硬编码期望的算法类型，不信任Header中的alg字段".to_string()),
            "JWT-004" | "JWT-005" => recs.push("对kid字段进行严格验证，不直接拼接到文件路径或SQL中".to_string()),
            "JWT-006" | "JWT-007" => recs.push("限制jku/x5u只允许白名单域名，或完全禁用这些字段".to_string()),
            "JWT-008" => recs.push("始终设置exp字段，建议有效期不超过1小时".to_string()),
            _ => {}
        }
    }
    if !summary.has_kid && !summary.has_jku {
        recs.push("密钥轮换时建议使用kid标识密钥版本".to_string());
    }
    recs.dedup();
    recs
}
