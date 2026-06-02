use clap::{Parser, Subcommand};
use colored::*;
use rjwt::{
    analyzer::{analyze_jwt, parse_jwt},
    bruteforce::{bruteforce, forge_none_token, forge_token},
    http_client::send_request,
    models::*,
};
use std::collections::HashMap;

#[derive(Parser)]
#[command(
    name = "rjwt",
    about = "JWT安全分析工具 - 用于授权渗透测试和安全研究",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 解析并展示JWT结构信息
    Parse {
        token: String,
        #[arg(long)]
        json: bool,
    },
    /// 全面安全分析（漏洞检测 + 风险评级）
    Analyze {
        token: String,
        #[arg(long)]
        json: bool,
    },
    /// 弱密钥字典爆破
    Brute {
        token: String,
        #[arg(short, long)]
        wordlist: Option<String>,
        #[arg(long, default_value = "true")]
        builtin: bool,
    },
    /// 伪造JWT Token
    Forge {
        token: String,
        #[arg(short, long, default_value = "")]
        secret: String,
        #[arg(long)]
        alg: Option<String>,
        #[arg(long)]
        payload: Option<String>,
    },
    /// 向目标URL发送携带JWT的HTTP请求
    Probe {
        url: String,
        #[arg(short, long)]
        token: String,
        #[arg(short, long, default_value = "GET")]
        method: String,
        #[arg(long, default_value = "bearer")]
        placement: String,
    },
    /// 启动REST API服务（供Agent调用）
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(short, long, default_value = "7878")]
        port: u16,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    print_banner();
    match cli.command {
        Commands::Parse { token, json } => cmd_parse(&token, json),
        Commands::Analyze { token, json } => cmd_analyze(&token, json),
        Commands::Brute {
            token,
            wordlist,
            builtin,
        } => cmd_brute(&token, wordlist, builtin),
        Commands::Forge {
            token,
            secret,
            alg,
            payload,
        } => cmd_forge(&token, &secret, alg, payload),
        Commands::Probe {
            url,
            token,
            method,
            placement,
        } => cmd_probe(&url, &token, &method, &placement),
        Commands::Serve { host, port } => cmd_serve(&host, port).await,
    }
}

fn print_banner() {
    println!("{}", "  ██████╗      ██╗██╗    ██╗████████╗".bright_cyan());
    println!("{}", "  ██╔══██╗     ██║██║    ██║╚══██╔══╝".bright_cyan());
    println!("{}", "  ██████╔╝     ██║██║ █╗ ██║   ██║   ".bright_cyan());
    println!("{}", "  ██╔══██╗██   ██║██║███╗██║   ██║   ".bright_cyan());
    println!("{}", "  ██║  ██║╚█████╔╝╚███╔███╔╝   ██║   ".bright_cyan());
    println!("{}", "  ╚═╝  ╚═╝ ╚════╝  ╚══╝╚══╝    ╚═╝   ".bright_cyan());
    println!(
        "{}\n",
        "    JWT Security Analysis Tool v0.1.0 | 仅用于授权测试".bright_black()
    );
}

fn cmd_parse(token: &str, as_json: bool) {
    match parse_jwt(token) {
        Ok(parsed) => {
            if as_json {
                println!("{}", serde_json::to_string_pretty(&parsed).unwrap());
                return;
            }
            println!("{}", "=== JWT 结构解析 ===".bright_yellow().bold());
            println!("{}", "[ Header ]".bright_blue());
            println!("  算法 (alg): {}", parsed.header.alg.bright_white());
            if let Some(typ) = &parsed.header.typ {
                println!("  类型 (typ): {}", typ);
            }
            if let Some(kid) = &parsed.header.kid {
                println!("  密钥ID (kid): {}", kid.yellow());
            }
            if let Some(jku) = &parsed.header.jku {
                println!("  密钥URL (jku): {}", jku.red());
            }
            println!("{}", "[ Payload ]".bright_blue());
            if let Some(sub) = &parsed.payload.sub {
                println!("  主体 (sub): {}", sub.bright_white());
            }
            if let Some(iss) = &parsed.payload.iss {
                println!("  签发者 (iss): {}", iss);
            }
            if let Some(exp) = parsed.payload.exp {
                println!("  过期时间 (exp): {}", exp);
            } else {
                println!("  过期时间 (exp): {}", "未设置".red());
            }
            if let Some(iat) = parsed.payload.iat {
                println!("  签发时间 (iat): {}", iat);
            }
            println!("{}", "[ 自定义Claims ]".bright_blue());
            for (k, v) in &parsed.payload.claims {
                println!("  {}: {}", k, v);
            }
            println!("{}", "[ 签名 ]".bright_blue());
            let sig_preview = &parsed.raw.signature_b64[..parsed.raw.signature_b64.len().min(40)];
            println!("  base64url: {}...", sig_preview);
        }
        Err(e) => eprintln!("{}: {}", "解析失败".red().bold(), e),
    }
}

fn cmd_analyze(token: &str, as_json: bool) {
    match parse_jwt(token) {
        Ok(parsed) => {
            let report = analyze_jwt(&parsed);
            if as_json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                return;
            }
            println!("{}", "=== JWT 安全分析报告 ===".bright_yellow().bold());
            let risk_str = match &report.risk_level {
                RiskLevel::Critical => "🔴 严重 (CRITICAL)".red().bold().to_string(),
                RiskLevel::High => "🟠 高危 (HIGH)".bright_red().to_string(),
                RiskLevel::Medium => "🟡 中危 (MEDIUM)".yellow().to_string(),
                RiskLevel::Low => "🔵 低危 (LOW)".blue().to_string(),
                RiskLevel::Safe => "🟢 安全 (SAFE)".green().to_string(),
            };
            println!("\n  综合风险等级: {}", risk_str);
            println!("\n{}", "[ Token摘要 ]".bright_blue());
            println!("  算法: {}", report.token_summary.algorithm.bright_white());
            println!(
                "  过期状态: {}",
                if report.token_summary.is_expired {
                    report.token_summary.expiry_info.red().to_string()
                } else {
                    report.token_summary.expiry_info.green().to_string()
                }
            );
            println!("\n{}", "[ 发现的漏洞/风险 ]".bright_blue());
            if report.vulnerabilities.is_empty() {
                println!("  {}", "未发现明显漏洞".green());
            } else {
                for vuln in &report.vulnerabilities {
                    let sev = match vuln.severity {
                        Severity::Critical => "[严重]".red().bold().to_string(),
                        Severity::High => "[高危]".bright_red().to_string(),
                        Severity::Medium => "[中危]".yellow().to_string(),
                        Severity::Low => "[低危]".blue().to_string(),
                        Severity::Info => "[信息]".white().to_string(),
                    };
                    println!(
                        "\n  {} {} - {}",
                        sev,
                        vuln.id.bright_white(),
                        vuln.name.bold()
                    );
                    println!("     描述: {}", vuln.description);
                    if let Some(ev) = &vuln.evidence {
                        println!("     证据: {}", ev.yellow());
                    }
                    if let Some(hint) = &vuln.exploit_hint {
                        println!("     利用提示: {}", hint.cyan());
                    }
                }
            }
            println!("\n{}", "[ 修复建议 ]".bright_blue());
            for rec in &report.recommendations {
                println!("  ✓ {}", rec.green());
            }
        }
        Err(e) => eprintln!("{}: {}", "分析失败".red().bold(), e),
    }
}

fn cmd_brute(token: &str, wordlist_path: Option<String>, use_builtin: bool) {
    println!("{}", "=== JWT 弱密钥爆破 ===".bright_yellow().bold());
    let custom_words: Option<Vec<String>> = wordlist_path.map(|path| {
        std::fs::read_to_string(&path)
            .map(|c| c.lines().map(String::from).collect())
            .unwrap_or_else(|e| {
                eprintln!("读取字典失败: {}", e);
                vec![]
            })
    });
    if use_builtin {
        println!("  使用内置弱密钥字典 + 动态扩展");
    }
    println!("  {} 开始并行爆破...\n", "►".bright_cyan());
    match bruteforce(token, custom_words, use_builtin) {
        Ok(result) => {
            println!("  尝试次数: {}", result.attempts.to_string().bright_white());
            println!("  耗时: {} ms", result.duration_ms);
            if result.success {
                println!(
                    "\n  {} 找到密钥: {}",
                    "✓".bright_green().bold(),
                    result
                        .found_secret
                        .as_deref()
                        .unwrap_or("")
                        .bright_green()
                        .bold()
                );
            } else {
                println!("\n  {} 未找到弱密钥（可使用 -w 指定自定义字典）", "✗".red());
            }
        }
        Err(e) => eprintln!("{}: {}", "爆破失败".red(), e),
    }
}

fn cmd_forge(token: &str, secret: &str, alg: Option<String>, payload: Option<String>) {
    println!("{}", "=== JWT 伪造 ===".bright_yellow().bold());
    let claims: serde_json::Value = if let Some(p) = payload {
        match serde_json::from_str(&p) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Payload JSON解析失败: {}", e);
                return;
            }
        }
    } else {
        match parse_jwt(token) {
            Ok(p) => serde_json::to_value(&p.payload).unwrap_or_default(),
            Err(e) => {
                eprintln!("解析原始Token失败: {}", e);
                return;
            }
        }
    };
    let alg_str = alg.as_deref();
    if alg_str == Some("none") {
        match forge_none_token(token, &claims) {
            Ok(forged) => {
                println!("  {} alg=none Token 变体:", "✓".bright_green());
                for (i, t) in forged.split("\n--- 变体 ---\n").enumerate() {
                    println!("\n  [变体{}] {}", i + 1, t.bright_white());
                }
            }
            Err(e) => eprintln!("伪造失败: {}", e),
        }
    } else {
        match forge_token(token, &claims, secret, alg_str) {
            Ok(forged) => {
                println!(
                    "  {} 伪造Token:\n\n  {}",
                    "✓".bright_green(),
                    forged.bright_white()
                );
            }
            Err(e) => eprintln!("伪造失败: {}", e),
        }
    }
}

fn cmd_probe(url: &str, token: &str, method: &str, placement: &str) {
    println!("{}", "=== HTTP 探测 ===".bright_yellow().bold());
    println!("  目标: {}", url.bright_white());
    let jwt_placement = if placement == "bearer" {
        JwtPlacement::AuthorizationBearer
    } else if let Some(r) = placement.strip_prefix("header:") {
        JwtPlacement::Header(r.to_string())
    } else if let Some(r) = placement.strip_prefix("query:") {
        JwtPlacement::QueryParam(r.to_string())
    } else if let Some(r) = placement.strip_prefix("cookie:") {
        JwtPlacement::Cookie(r.to_string())
    } else {
        JwtPlacement::AuthorizationBearer
    };
    let req = HttpRequest {
        url: url.to_string(),
        method: method.to_string(),
        headers: HashMap::new(),
        body: None,
        jwt_placement,
        jwt_token: token.to_string(),
    };
    match send_request(&req) {
        Ok(resp) => {
            let sc = if resp.status < 300 {
                resp.status.to_string().green().to_string()
            } else if resp.status < 400 {
                resp.status.to_string().yellow().to_string()
            } else {
                resp.status.to_string().red().to_string()
            };
            println!("  响应状态: {}", sc);
            let preview = &resp.body[..resp.body.len().min(512)];
            println!("  响应体:\n{}", preview);
            if let Some(jwt) = resp.jwt_in_response {
                println!(
                    "\n  {} 响应中发现JWT: {}...",
                    "★".bright_yellow(),
                    &jwt[..jwt.len().min(60)]
                );
            }
        }
        Err(e) => eprintln!("请求失败: {}", e),
    }
}

async fn cmd_serve(host: &str, port: u16) {
    let addr = format!("{}:{}", host, port);
    println!("{}", "=== rjwt Agent API 服务 ===".bright_yellow().bold());
    println!("  监听: {}", addr.bright_white());
    println!("  统一Agent接口: POST http://{}/api/agent", addr);
    println!("  健康检查:      GET  http://{}/health\n", addr);
    let router = rjwt::api::build_router();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("端口绑定失败");
    axum::serve(listener, router).await.expect("服务运行失败");
}
