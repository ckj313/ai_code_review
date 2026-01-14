# INT_OVERFLOW

<display_name>Integer Overflow (INT_OVERFLOW)</display_name>

<summary>检测长度与尺寸计算中的整数溢出问题。</summary>

<prompt>
结合 <file_code> 和 <context_code>，以白盒代码检查视角排查整数溢出问题。

关注点：
1. 高风险模式：
   - 分配或拷贝长度计算
   - 不可信长度参与加/乘
   - 有符号/无符号转换
2. 常见接口：
   - malloc(), calloc(), realloc()
   - memcpy(), memmove(), memset()
   - 基于长度的解析循环

输出要求：
- 只报告代码问题，不做漏洞利用分析。
- 结合 <candidate_matches> 提供的证据。
- 给出问题行号与调用栈。
</prompt>

<positive_example>
size_t len = count * sizeof(struct item);
char *buf = malloc(len);
</positive_example>

<negative_example>
if (count > SIZE_MAX / sizeof(struct item)) {
    return -1;
}
size_t len = count * sizeof(struct item);
char *buf = malloc(len);
</negative_example>

<bypasses>
- 2147483647
- 4294967295
- 0xffffffff
- -1
- 0x100000000
</bypasses>

<rules>
\bmalloc\s*\(
\bcalloc\s*\(
\brealloc\s*\(
\bmemcpy\s*\(
\bmemmove\s*\(
\bmemset\s*\(
\bstrtol\s*\(
\bstrtoul\s*\(
\batoi\s*\(
\batol\s*\(
\batoll\s*\(
</rules>
