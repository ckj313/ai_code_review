# INT_OVERFLOW

<display_name>Integer Overflow (INT_OVERFLOW)</display_name>

<prompt>
Combine the code in <file_code> and <context_code> tags then analyze the C code for remotely exploitable Integer Overflow vulnerabilities by following the remote user-input call chain of code.

INT_OVERFLOW-Specific Focus Areas:
1. High-Risk Patterns:
   - Size calculations for allocations or copies
   - Multiplication/addition on untrusted lengths
   - Signed/unsigned conversions

2. Common APIs:
   - malloc(), calloc(), realloc()
   - memcpy(), memmove(), memset()
   - length-based parsing loops

3. Example INT_OVERFLOW payloads are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- Whether integer math is bounded before use
- Whether the result is used for allocation or copy sizes
- Whether truncation or wraparound can be exploited
</prompt>

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
