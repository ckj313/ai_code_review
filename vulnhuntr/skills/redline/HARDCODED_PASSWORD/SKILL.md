# HARDCODED_PASSWORD

<display_name>硬编码密码</display_name>

<summary>检测代码中是否直接写死密码/口令/密钥等敏感信息。</summary>

<prompt>
结合 <file_code> 和 <context_code>，分析 C 代码是否存在硬编码密码/口令/密钥等敏感信息。该问题属于合规风险。

关注点：
1. 直接在代码中以字符串字面量保存密码/口令/密钥。
2. 宏定义或常量里包含 PASSWORD/PASS/PWD/SECRET/TOKEN 等字段。
3. 变量赋值时写死敏感值。

请：
- 只判断该合规问题是否成立。
- 在分析结论中引用 <candidate_matches> 中的证据片段。
- PoC 字段如不适用请输出 "None"。
</prompt>

<positive_example>
const char *password = "admin123";
</positive_example>

<negative_example>
const char *password = getenv("DB_PASSWORD");
</negative_example>

<bypasses>
</bypasses>

<rules>
(?i)^\s*#define\s+\w*(PASS|PASSWORD|PWD|SECRET|TOKEN)\w*\s+"[^"]+"
(?i)\b(pass(word|wd)?|pwd|secret|token)\b\s*=\s*"[^"]+"
(?i)\b(pass(word|wd)?|pwd|secret|token)\b\s*=\s*'[^']+'
</rules>
