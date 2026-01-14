# LOG_PASSWORD

<display_name>日志打印密码</display_name>

<summary>检测日志输出中是否包含密码/口令等敏感信息。</summary>

<prompt>
结合 <file_code> 和 <context_code>，分析 C 代码是否在日志中打印了密码/口令等敏感信息。该问题属于合规风险，不是漏洞利用。

关注点：
1. 常见日志/输出接口：printf/fprintf/syslog/printk，以及项目自定义的 log 函数。
2. 日志内容是否包含 password/passwd/pwd/secret/token 等敏感字段或变量。
3. 是否存在直接把用户输入或凭据写入日志的情况。

请：
- 只判断该合规问题是否成立。
- 在分析结论中引用 <candidate_matches> 中的证据片段。
- 给出问题行号与调用栈。
</prompt>

<positive_example>
printf("login password=%s", password);
</positive_example>

<negative_example>
printf("login failed for user=%s", username);
</negative_example>

<bypasses>
</bypasses>

<rules>
(?i)\b(printf|fprintf|syslog|printk)\s*\([^\n]*(password|passwd|pwd|secret|token)
(?i)\b(LOG\w*|log\w*)\s*\([^\n]*(password|passwd|pwd|secret|token)
</rules>
