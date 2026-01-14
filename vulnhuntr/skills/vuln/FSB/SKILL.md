# FSB

<display_name>Format String Bug (FSB)</display_name>

<summary>检测格式化字符串使用不当的问题。</summary>

<prompt>
结合 <file_code> 和 <context_code>，以白盒代码检查视角排查格式化字符串问题。

关注点：
1. 高风险函数与接口：
   - printf(), fprintf(), sprintf(), snprintf()
   - vprintf(), vsprintf(), vsnprintf(), dprintf(), vdprintf()
   - syslog()
2. 格式化字符串控制：
   - 不可信输入作为格式化字符串
   - 缺失格式化占位符
3. 风险影响：
   - %x/%p 信息泄露，%n 写入等

输出要求：
- 只报告代码问题，不做漏洞利用分析。
- 结合 <candidate_matches> 提供的证据。
- 给出问题行号与调用栈。
</prompt>

<positive_example>
printf(user_input);
</positive_example>

<negative_example>
printf("%s", user_input);
</negative_example>

<bypasses>
- %x %x %x %x
- %p %p %p
- %n
- %08x.%08x.%08x
</bypasses>

<rules>
\bprintf\s*\(
\bfprintf\s*\(
\bsprintf\s*\(
\bsnprintf\s*\(
\bvprintf\s*\(
\bvsprintf\s*\(
\bvsnprintf\s*\(
\bdprintf\s*\(
\bvdprintf\s*\(
\bsyslog\s*\(
</rules>
