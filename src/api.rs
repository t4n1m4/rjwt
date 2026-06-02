use crate::analyzer::{analyze_jwt, parse_jwt};
use crate::bruteforce::{bruteforce, forge_token};
use crate::http_client::send_request;
use crate::models::*;
use axum::{
    Router,
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use tower_http::cors::{Any, CorsLayer};

pub fn build_router() -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/", get(health))
        .route("/health", get(health))
        .route("/api/parse", post(api_parse))
        .route("/api/analyze", post(api_analyze))
        .route("/api/bruteforce", post(api_bruteforce))
        .route("/api/vulns", post(api_check_vulns))
        .route("/api/forge", post(api_forge))
        .route("/api/probe", post(api_probe))
        .route("/api/agent", post(api_agent))
        .layer(cors)
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "rjwt",
        "version": "0.1.0",
        "endpoints": [
            "POST /api/parse",
            "POST /api/analyze",
            "POST /api/bruteforce",
            "POST /api/vulns",
            "POST /api/forge",
            "POST /api/probe",
            "POST /api/agent"
        ]
    }))
}

/// 解析JWT结构
async fn api_parse(Json(body): Json<Value>) -> impl IntoResponse {
    let token = match body.get("token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return err_response("缺少 token 字段"),
    };
    match parse_jwt(&token) {
        Ok(parsed) => ok_response("parse", json!(parsed)),
        Err(e) => err_response(&e.to_string()),
    }
}

/// 分析JWT安全性
async fn api_analyze(Json(body): Json<Value>) -> impl IntoResponse {
    let token = match body.get("token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return err_response("缺少 token 字段"),
    };
    match parse_jwt(&token) {
        Ok(parsed) => {
            let report = analyze_jwt(&parsed);
            ok_response("analyze", json!(report))
        }
        Err(e) => err_response(&e.to_string()),
    }
}

/// 弱密钥爆破
async fn api_bruteforce(Json(body): Json<Value>) -> impl IntoResponse {
    let token = match body.get("token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return err_response("缺少 token 字段"),
    };
    let use_builtin = body
        .get("use_builtin")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let wordlist: Option<Vec<String>> = body.get("wordlist").and_then(|v| {
        v.as_array().map(|arr| {
            arr.iter()
                .filter_map(|i| i.as_str().map(String::from))
                .collect()
        })
    });

    match bruteforce(&token, wordlist, use_builtin) {
        Ok(result) => ok_response("bruteforce", json!(result)),
        Err(e) => err_response(&e.to_string()),
    }
}

/// 漏洞检测
async fn api_check_vulns(Json(body): Json<Value>) -> impl IntoResponse {
    let token = match body.get("token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return err_response("缺少 token 字段"),
    };
    match parse_jwt(&token) {
        Ok(parsed) => {
            let report = analyze_jwt(&parsed);
            ok_response(
                "vulns",
                json!({
                    "vulnerabilities": report.vulnerabilities,
                    "risk_level": report.risk_level,
                    "count": report.vulnerabilities.len()
                }),
            )
        }
        Err(e) => err_response(&e.to_string()),
    }
}

/// 伪造token
async fn api_forge(Json(body): Json<Value>) -> impl IntoResponse {
    let token = match body.get("token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return err_response("缺少 token 字段"),
    };
    let secret = body.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let alg = body.get("alg").and_then(|v| v.as_str());
    let claims = match body.get("claims") {
        Some(c) => c.clone(),
        None => return err_response("缺少 claims 字段"),
    };

    // alg=none 模式
    if alg == Some("none") || alg == Some("None") || alg == Some("NONE") {
        match crate::bruteforce::forge_token(&token, &claims, "", Some("HS256")) {
            Ok(_) => {
                // 生成none变体
                let _parsed = match parse_jwt(&token) {
                    Ok(p) => p,
                    Err(e) => return err_response(&e.to_string()),
                };
                let header = json!({"alg": "none", "typ": "JWT"});
                let h64 = b64url_encode_val(&header);
                let p64 = b64url_encode_val(&claims);
                let forged = format!("{}.{}.", h64, p64);
                return ok_response("forge", json!({ "token": forged, "alg": "none" }));
            }
            Err(e) => return err_response(&e.to_string()),
        }
    }

    match forge_token(&token, &claims, secret, alg) {
        Ok(forged) => ok_response("forge", json!({ "token": forged, "alg": alg })),
        Err(e) => err_response(&e.to_string()),
    }
}

/// HTTP探测：用指定token与目标站点通信
async fn api_probe(Json(body): Json<Value>) -> impl IntoResponse {
    let req: HttpRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(e) => return err_response(&format!("请求体格式错误: {}", e)),
    };

    match tokio::task::spawn_blocking(move || send_request(&req)).await {
        Ok(Ok(resp)) => ok_response("probe", json!(resp)),
        Ok(Err(e)) => err_response(&e.to_string()),
        Err(e) => err_response(&format!("任务执行失败: {}", e)),
    }
}

/// 统一Agent接口（供AI Agent调用）
async fn api_agent(Json(body): Json<AgentRequest>) -> impl IntoResponse {
    match &body.action {
        AgentAction::Parse { token } => match parse_jwt(token) {
            Ok(p) => ok_response("parse", json!(p)),
            Err(e) => err_response(&e.to_string()),
        },
        AgentAction::Analyze { token } => match parse_jwt(token) {
            Ok(p) => ok_response("analyze", json!(analyze_jwt(&p))),
            Err(e) => err_response(&e.to_string()),
        },
        AgentAction::Bruteforce {
            token,
            wordlist,
            use_builtin,
        } => {
            let wl = wordlist.clone();
            let ub = use_builtin.unwrap_or(true);
            let tok = token.clone();
            match tokio::task::spawn_blocking(move || bruteforce(&tok, wl, ub)).await {
                Ok(Ok(r)) => ok_response("bruteforce", json!(r)),
                Ok(Err(e)) => err_response(&e.to_string()),
                Err(e) => err_response(&e.to_string()),
            }
        }
        AgentAction::CheckVulns { token } => match parse_jwt(token) {
            Ok(p) => {
                let report = analyze_jwt(&p);
                ok_response("check_vulns", json!(report.vulnerabilities))
            }
            Err(e) => err_response(&e.to_string()),
        },
        AgentAction::Forge {
            original_token,
            new_claims,
            secret,
            alg,
        } => {
            let s = secret.as_deref().unwrap_or("");
            let a = alg.as_deref();
            let claims_val =
                serde_json::to_value(new_claims).unwrap_or(Value::Object(Default::default()));
            match forge_token(original_token, &claims_val, s, a) {
                Ok(t) => ok_response("forge", json!({ "token": t })),
                Err(e) => err_response(&e.to_string()),
            }
        }
        AgentAction::HttpProbe { request } => {
            let req = request.clone();
            match tokio::task::spawn_blocking(move || send_request(&req)).await {
                Ok(Ok(r)) => ok_response("http_probe", json!(r)),
                Ok(Err(e)) => err_response(&e.to_string()),
                Err(e) => err_response(&e.to_string()),
            }
        }
    }
}

// ---- 辅助函数 ----

fn ok_response(action: &str, data: Value) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "action": action,
            "data": data,
            "error": null
        })),
    )
}

fn err_response(msg: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "action": "error",
            "data": null,
            "error": msg
        })),
    )
}

fn b64url_encode_val(val: &Value) -> String {
    use base64::{Engine as _, engine::general_purpose};
    let s = serde_json::to_string(val).unwrap_or_default();
    general_purpose::STANDARD
        .encode(s.as_bytes())
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}
