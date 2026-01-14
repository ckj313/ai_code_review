# BOF

<display_name>Buffer Overflow (BOF)</display_name>

<summary>检测可能导致缓冲区越界的写入问题。</summary>

<prompt>
结合 <file_code> 和 <context_code>，以白盒代码检查视角排查 C 代码中的缓冲区越界问题。

关注点：
1. 高风险函数与接口：
   - strcpy(), strcat(), gets(), sprintf(), vsprintf()
   - memcpy(), memmove(), strncpy(), strncat(), snprintf()
   - read(), recv() 写入固定大小缓冲区
2. 缓冲区边界：
   - 栈/堆缓冲区
   - 固定大小数组或结构体字段
3. 长度校验：
   - 缺失或错误的边界检查
   - off-by-one
4. 间接越界：
   - 长度计算溢出/下溢
   - 信任外部长度字段

输出要求：
- 只报告代码问题，不做漏洞利用分析。
- 结合 <candidate_matches> 提供的证据。
- 给出问题行号与调用栈。
</prompt>

<positive_example>
char buf[64];
recv(sock, buf, 512, 0);
</positive_example>

<negative_example>
char buf[64];
int n = recv(sock, buf, sizeof(buf) - 1, 0);
if (n >= 0) {
    buf[n] = '\0';
}
</negative_example>

<bypasses>
- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
- %1024s
- \x41\x41\x41\x41\x41\x41\x41\x41
</bypasses>

<rules>
\bstrcpy\s*\(
\bstrcat\s*\(
\bgets\s*\(
\bsprintf\s*\(
\bvsprintf\s*\(
\bmemcpy\s*\(
\bmemmove\s*\(
\bstrncpy\s*\(
\bstrncat\s*\(
\bsnprintf\s*\(
\bscanf\s*\(
\bsscanf\s*\(
\bread\s*\(
\brecv\s*\(
</rules>
