# HARDCODED_PUBLIC_ADDRESS

<display_name>硬编码公网地址</display_name>

<summary>检测代码中是否硬编码公网 URL/IP 地址。</summary>

<prompt>
结合 <file_code> 和 <context_code>，分析 C 代码是否存在硬编码公网地址（URL/IP）。该问题属于合规风险。

关注点：
1. 代码中直接出现 http/https 等 URL 字面量。
2. 代码中硬编码 IP 地址（需要判断是否为公网地址）。
3. 若仅为本地/私网地址（127.0.0.1、10.x、172.16-31、192.168.x），可视为不满足该问题。

请：
- 只判断该合规问题是否成立。
- 在分析结论中引用 <candidate_matches> 中的证据片段。
- 给出问题行号与调用栈。
</prompt>

<positive_example>
const char *api = "https://203.0.113.10/api";
</positive_example>

<negative_example>
const char *api = get_config("api_url");
</negative_example>

<bypasses>
</bypasses>

<rules>
\bhttps?://[^\s"']+
\b(?:\d{1,3}\.){3}\d{1,3}\b
</rules>
