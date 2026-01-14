# MEMORY_LEAK

<display_name>内存泄露</display_name>

<summary>检测申请后未释放或错误路径遗漏释放的内存泄露问题。</summary>

<prompt>
结合 <file_code> 和 <context_code>，以白盒代码检查视角排查内存泄露问题。

关注点：
1. 申请后是否在所有路径释放（包括错误分支与早退）。
2. 资源所有权是否明确，是否遗漏释放或重复转移。
3. 循环或多次调用中是否反复分配而未释放。

输出要求：
- 只报告代码问题，不做漏洞利用分析。
- 结合 <candidate_matches> 提供的证据。
- 给出问题行号与调用栈。
</prompt>

<positive_example>
char *buf = malloc(64);
if (error) {
    return -1;
}
</positive_example>

<negative_example>
char *buf = malloc(64);
if (error) {
    free(buf);
    return -1;
}
free(buf);
</negative_example>

<bypasses>
</bypasses>

<rules>
\bmalloc\s*\(
\bcalloc\s*\(
\brealloc\s*\(
\bstrdup\s*\(
\basprintf\s*\(
\bvasprintf\s*\(
</rules>
