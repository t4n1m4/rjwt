use crate::models::*;
use anyhow::Result;
use std::collections::HashMap;

/// 向目标站点发送携带JWT的HTTP请求（使用blocking reqwest）
pub fn send_request(req: &HttpRequest) -> Result<HttpResponse> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(false) // 生产环境不跳过TLS校验
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let method = match req.method.to_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "PATCH" => reqwest::Method::PATCH,
        "DELETE" => reqwest::Method::DELETE,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => return Err(anyhow::anyhow!("不支持的HTTP方法: {}", other)),
    };

    let mut builder = client.request(method, &req.url);

    // 注入JWT到指定位置
    builder = match &req.jwt_placement {
        JwtPlacement::AuthorizationBearer => {
            builder.header("Authorization", format!("Bearer {}", req.jwt_token))
        }
        JwtPlacement::Header(name) => {
            builder.header(name.as_str(), req.jwt_token.as_str())
        }
        JwtPlacement::QueryParam(param) => {
            builder.query(&[(param.as_str(), req.jwt_token.as_str())])
        }
        JwtPlacement::Cookie(name) => {
            builder.header("Cookie", format!("{}={}", name, req.jwt_token))
        }
    };

    // 添加自定义headers
    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    // 添加body
    if let Some(body) = &req.body {
        builder = builder
            .header("Content-Type", "application/json")
            .body(body.clone());
    }

    let response = builder.send()?;
    let status = response.status().as_u16();

    let mut resp_headers = HashMap::new();
    for (k, v) in response.headers() {
        resp_headers.insert(
            k.to_string(),
            v.to_str().unwrap_or("").to_string(),
        );
    }

    let body = response.text()?;

    // 尝试从响应中提取JWT
    let jwt_in_response = extract_jwt_from_body(&body)
        .or_else(|| resp_headers.get("authorization").and_then(|v| {
            if v.starts_with("Bearer ") {
                Some(v[7..].to_string())
            } else {
                None
            }
        }));

    Ok(HttpResponse {
        status,
        headers: resp_headers,
        body,
        jwt_in_response,
    })
}

/// 从响应body中尝试提取JWT
fn extract_jwt_from_body(body: &str) -> Option<String> {
    // 简单的JWT模式匹配: 三段base64url
    let jwt_pattern = regex_find_jwt(body);
    jwt_pattern
}

fn regex_find_jwt(text: &str) -> Option<String> {
    // JWT格式: [A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*
    let mut i = 0;
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();

    while i < len {
        // 找连续的base64url字符
        let start = i;
        while i < len && (chars[i].is_alphanumeric() || chars[i] == '-' || chars[i] == '_') {
            i += 1;
        }
        if i < len && chars[i] == '.' && i > start + 3 {
            let dot1 = i;
            i += 1;
            let mid_start = i;
            while i < len && (chars[i].is_alphanumeric() || chars[i] == '-' || chars[i] == '_') {
                i += 1;
            }
            if i < len && chars[i] == '.' && i > mid_start + 3 {
                let dot2 = i;
                i += 1;
                let sig_start = i;
                while i < len && (chars[i].is_alphanumeric() || chars[i] == '-' || chars[i] == '_') {
                    i += 1;
                }
                // 签名可以为空（none算法）或有内容
                let candidate: String = chars[start..i].iter().collect();
                if candidate.len() > 20 {
                    let _ = (dot1, dot2, sig_start); // suppress warnings
                    return Some(candidate);
                }
            }
        }
        i += 1;
    }
    None
}

/// 批量探测：用不同token测试同一端点，收集响应差异
pub fn probe_endpoint(
    url: &str,
    tokens: &[(String, String)], // (label, token)
    method: &str,
    extra_headers: &HashMap<String, String>,
) -> Vec<(String, Result<HttpResponse>)> {
    tokens.iter().map(|(label, token)| {
        let req = HttpRequest {
            url: url.to_string(),
            method: method.to_string(),
            headers: extra_headers.clone(),
            body: None,
            jwt_placement: JwtPlacement::AuthorizationBearer,
            jwt_token: token.clone(),
        };
        let resp = send_request(&req);
        (label.clone(), resp)
    }).collect()
}
