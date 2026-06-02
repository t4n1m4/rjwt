use crate::models::*;
use anyhow::Result;
use std::collections::HashMap;

pub fn send_request(req: &HttpRequest) -> Result<HttpResponse> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(false)
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

    // 处理 QueryParam 时手动拼接到 URL
    let final_url = match &req.jwt_placement {
        JwtPlacement::QueryParam(param) => {
            let sep = if req.url.contains('?') { '&' } else { '?' };
            format!("{}{}{}={}", req.url, sep, param, req.jwt_token)
        }
        _ => req.url.clone(),
    };

    let mut builder = client.request(method, &final_url);

    // 其余位置正常注入 JWT
    builder = match &req.jwt_placement {
        JwtPlacement::AuthorizationBearer => {
            builder.header("Authorization", format!("Bearer {}", req.jwt_token))
        }
        JwtPlacement::Header(name) => builder.header(name.as_str(), req.jwt_token.as_str()),
        JwtPlacement::Cookie(name) => {
            builder.header("Cookie", format!("{}={}", name, req.jwt_token))
        }
        JwtPlacement::QueryParam(_) => builder, // 已拼到 URL，无需再处理
    };

    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if let Some(body) = &req.body {
        builder = builder
            .header("Content-Type", "application/json")
            .body(body.clone());
    }

    let response = builder.send()?;
    let status = response.status().as_u16();

    let mut resp_headers = HashMap::new();
    for (k, v) in response.headers() {
        resp_headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
    }

    let body = response.text()?;

    let jwt_in_response = extract_jwt_from_body(&body).or_else(|| {
        resp_headers
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer ").map(|s| s.to_string()))
    });

    Ok(HttpResponse {
        status,
        headers: resp_headers,
        body,
        jwt_in_response,
    })
}

pub fn probe_endpoint(
    url: &str,
    tokens: &[(String, String)],
    method: &str,
    extra_headers: &HashMap<String, String>,
) -> Vec<(String, Result<HttpResponse>)> {
    tokens
        .iter()
        .map(|(label, token)| {
            let req = HttpRequest {
                url: url.to_string(),
                method: method.to_string(),
                headers: extra_headers.clone(),
                body: None,
                jwt_placement: JwtPlacement::AuthorizationBearer,
                jwt_token: token.clone(),
            };
            (label.clone(), send_request(&req))
        })
        .collect()
}

fn extract_jwt_from_body(body: &str) -> Option<String> {
    regex_find_jwt(body)
}

fn regex_find_jwt(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let start = i;
        while i < len && (chars[i].is_alphanumeric() || chars[i] == '-' || chars[i] == '_') {
            i += 1;
        }
        if i < len && chars[i] == '.' && i > start + 3 {
            i += 1;
            let mid_start = i;
            while i < len && (chars[i].is_alphanumeric() || chars[i] == '-' || chars[i] == '_') {
                i += 1;
            }
            if i < len && chars[i] == '.' && i > mid_start + 3 {
                i += 1;
                while i < len && (chars[i].is_alphanumeric() || chars[i] == '-' || chars[i] == '_')
                {
                    i += 1;
                }
                let candidate: String = chars[start..i].iter().collect();
                if candidate.len() > 20 {
                    return Some(candidate);
                }
            }
        }
        i += 1;
    }
    None
}
