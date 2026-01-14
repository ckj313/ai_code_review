# UAF

<display_name>Use-After-Free (UAF)</display_name>

<summary>检测释放后使用或重复释放的问题。</summary>

<prompt>
结合 <file_code> 和 <context_code>，以白盒代码检查视角排查释放后使用问题。

关注点：
1. 释放行为：
   - free(), kfree(), vPortFree()
   - 自定义分配器或内存池释放
2. 释放后使用：
   - free 后仍访问/解引用
   - double free
3. 生命周期管理：
   - 归属不清导致重复释放
   - 错误路径释放后仍继续使用

输出要求：
- 只报告代码问题，不做漏洞利用分析。
- 结合 <candidate_matches> 提供的证据。
- 给出问题行号与调用栈。
</prompt>

<positive_example>
free(obj);
obj->state = 1;
</positive_example>

<negative_example>
free(obj);
obj = NULL;
</negative_example>

<bypasses>
</bypasses>

<rules>
\bfree\s*\(
\bkfree\s*\(
\bvPortFree\s*\(
\bheap_free\s*\(
\bpool_free\s*\(
</rules>
