# FSB

<display_name>Format String Bug (FSB)</display_name>

<summary>Detect attacker-controlled format strings in printf-style logging and output.</summary>

<prompt>
Combine the code in <file_code> and <context_code> tags then analyze the C code for remotely exploitable Format String vulnerabilities by following the remote user-input call chain of code.

FSB-Specific Focus Areas:
1. High-Risk Functions and APIs:
   - printf(), fprintf(), sprintf(), snprintf()
   - vprintf(), vsprintf(), vsnprintf(), dprintf(), vdprintf()
   - syslog()

2. Format String Control:
   - User input used as the format string
   - Missing format specifiers with untrusted data

3. Memory Safety Impact:
   - %x/%p leaks, %n writes, stack disclosure

4. Example FSB payloads are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- Whether the format string is attacker-controlled
- Whether the call is reachable from remote input
- Potential for info leak or memory writes via %n
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
