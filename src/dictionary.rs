/// 内置字典生成器 - 用于生成常见弱密钥候选
pub struct DictionaryGenerator;

impl DictionaryGenerator {
    /// 获取内置的常见弱密钥列表
    pub fn builtin_secrets() -> Vec<String> {
        let static_words: &[&str] = &[
            // 通用弱密钥
            "secret",
            "password",
            "123456",
            "qwerty",
            "admin",
            "test",
            "key",
            "jwt",
            "token",
            "auth",
            "secure",
            "private",
            "mysecret",
            "mypassword",
            "myjwt",
            "jwtkey",
            "jwttoken",
            "jwtpassword",
            "jwtsecret",
            "jwtauth",
            "jwtprivate",
            "secret123",
            "password123",
            "admin123",
            "test123",
            "12345678",
            "123456789",
            "1234567890",
            "00000000",
            "changeme",
            "changeit",
            "change_me",
            "change-me",
            "default",
            "defaults",
            "placeholder",
            // 常见框架/项目名
            "spring",
            "springboot",
            "laravel",
            "django",
            "express",
            "nodejs",
            "node",
            "flask",
            "rails",
            "symfony",
            "app",
            "application",
            "backend",
            "frontend",
            "server",
            "api",
            "apikey",
            "api_key",
            "api-key",
            "apitoken",
            // 空值/数字序列
            "",
            " ",
            "0",
            "1",
            "000",
            "111",
            "999",
            "000000",
            "111111",
            "666666",
            "888888",
            "999999",
        ];

        let mut words: Vec<String> = static_words.iter().map(|s| s.to_string()).collect();

        // 动态扩展：Leet变体 + 常用后缀
        let leet_bases = ["secret", "password", "admin", "secure"];
        for base in leet_bases {
            words.push(base.replace('a', "@"));
            words.push(base.replace('e', "3"));
            words.push(base.replace('o', "0"));
            words.push(format!("{}!", base));
            words.push(format!("{}123", base));
            words.push(format!("{}@123", base));
            words.push(format!("{}#", base));
            words.push(base.to_uppercase());
        }

        // 年份组合
        for year in 2018u32..=2025 {
            words.push(format!("secret{}", year));
            words.push(format!("password{}", year));
            words.push(format!("admin{}", year));
            words.push(format!("jwt{}", year));
        }

        words
    }

    /// 从用户提供的词列表生成扩展字典（加前后缀）
    pub fn expand_wordlist(base: &[String]) -> Vec<String> {
        let suffixes = ["", "!", "123", "@123", "#", "1", "2024", "2025"];
        let prefixes = ["", "my", "the", "super"];
        let mut expanded = Vec::new();
        for word in base {
            for prefix in prefixes {
                for suffix in suffixes {
                    expanded.push(format!("{}{}{}", prefix, word, suffix));
                }
            }
        }
        expanded
    }

    /// 生成基于charset的短密钥暴力枚举（仅限极短密钥，有上限保护）
    pub fn generate_short_keys(max_len: usize) -> Vec<String> {
        let charset: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
        let mut result = Vec::new();
        for len in 1..=max_len {
            Self::permute(&charset, len, String::new(), &mut result);
            if result.len() > 100_000 {
                break;
            }
        }
        result
    }

    fn permute(charset: &[char], remaining: usize, current: String, out: &mut Vec<String>) {
        if remaining == 0 {
            out.push(current);
            return;
        }
        for &ch in charset {
            Self::permute(charset, remaining - 1, format!("{}{}", current, ch), out);
        }
    }
}
