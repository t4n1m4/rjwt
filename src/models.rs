use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWT三段式原始结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawJwt {
    pub header_b64: String,
    pub payload_b64: String,
    pub signature_b64: String,
}

/// 已解析的JWT完整信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedJwt {
    pub raw: RawJwt,
    pub header: JwtHeader,
    pub payload: JwtPayload,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    #[serde(rename = "typ")]
    pub typ: Option<String>,
    pub kid: Option<String>,
    pub jku: Option<String>,
    pub x5u: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtPayload {
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<serde_json::Value>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: Option<String>,
    #[serde(flatten)]
    pub claims: HashMap<String, serde_json::Value>,
}

/// 分析报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub token_summary: TokenSummary,
    pub vulnerabilities: Vec<VulnFinding>,
    pub recommendations: Vec<String>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSummary {
    pub algorithm: String,
    pub is_expired: bool,
    pub expiry_info: String,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub has_kid: bool,
    pub has_jku: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: Option<String>,
    pub exploit_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Safe,
}

/// 爆破结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteResult {
    pub success: bool,
    pub found_secret: Option<String>,
    pub attempts: u64,
    pub duration_ms: u64,
}

/// HTTP通信请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub jwt_placement: JwtPlacement,
    pub jwt_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JwtPlacement {
    AuthorizationBearer,
    Header(String),
    QueryParam(String),
    Cookie(String),
}

/// HTTP通信响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub jwt_in_response: Option<String>,
}

/// Agent API 统一请求/响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    pub action: AgentAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentAction {
    Parse {
        token: String,
    },
    Analyze {
        token: String,
    },
    Bruteforce {
        token: String,
        wordlist: Option<Vec<String>>,
        use_builtin: Option<bool>,
    },
    CheckVulns {
        token: String,
    },
    Forge {
        original_token: String,
        new_claims: HashMap<String, serde_json::Value>,
        secret: Option<String>,
        alg: Option<String>,
    },
    HttpProbe {
        request: HttpRequest,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub success: bool,
    pub action: String,
    pub data: serde_json::Value,
    pub error: Option<String>,
}
