# UAF

<display_name>Use-After-Free (UAF)</display_name>

<summary>Detect dereferences of freed pointers along a remote input path.</summary>

<prompt>
Combine the code in <file_code> and <context_code> tags then analyze the C code for remotely exploitable Use-After-Free (UAF) vulnerabilities by following the remote user-input call chain of code.

UAF-Specific Focus Areas:
1. Freeing Memory:
   - free(), kfree(), vPortFree()
   - custom allocators and pool free routines

2. Use After Free:
   - Accessing or dereferencing pointers after free
   - Double free patterns

3. Lifetime Management:
   - Ownership confusion across modules
   - Error paths that free but continue to use pointers

When analyzing, consider:
- Whether freed pointers are reused or accessed
- Whether there is clear ownership and nulling after free
- Whether user input can influence allocation/free timing
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
