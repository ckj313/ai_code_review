# BOF

<display_name>Buffer Overflow (BOF)</display_name>

<summary>Detect remotely reachable writes that can exceed fixed-size buffers.</summary>

<prompt>
Combine the code in <file_code> and <context_code> tags then analyze the C code for remotely exploitable Buffer Overflow (BOF) vulnerabilities by following the remote user-input call chain of code.

BOF-Specific Focus Areas:
1. High-Risk Functions and APIs:
   - strcpy(), strcat(), gets(), sprintf(), vsprintf()
   - memcpy(), memmove(), strncpy(), strncat(), snprintf()
   - read(), recv() into fixed-size buffers

2. Buffer Boundaries:
   - Stack vs heap buffers
   - Fixed-size arrays and struct fields

3. Length Tracking:
   - Missing or incorrect bounds checks
   - Off-by-one errors and truncation

4. Indirect Overflows:
   - Length calculations that underflow or overflow
   - Trusting size fields from input

5. Example BOF payloads are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How input size is validated before copy/write
- Whether the destination buffer size is known and enforced
- Whether the call chain includes remote input parsing
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
