# NULL_DEREF

<display_name>空指针解引用</display_name>

<summary>检测指针可能为 NULL 时的解引用或访问。</summary>

<prompt>
结合 <file_code> 和 <context_code>，以白盒代码检查视角排查空指针解引用问题。

关注点：
1. 可能返回 NULL 的调用是否有判空：malloc/calloc/realloc/strdup/fopen/getenv 等。
2. 判空逻辑是否覆盖所有路径（尤其是错误路径或早退）。
3. 指针在赋值后是否被直接解引用或传入需要非空指针的接口。

输出要求：
- 只报告代码问题，不做漏洞利用分析。
- 结合 <candidate_matches> 提供的证据。
- 给出问题行号与调用栈。
</prompt>

<positive_example>
char *buf = malloc(128);
*buf = 'A';
</positive_example>

<negative_example>
char *buf = malloc(128);
if (!buf) {
    return -1;
}
*buf = 'A';
</negative_example>

<bypasses>
</bypasses>

<rules>
\bmalloc\s*\(
\bcalloc\s*\(
\brealloc\s*\(
\bstrdup\s*\(
\bfopen\s*\(
\bgetenv\s*\(
</rules>
