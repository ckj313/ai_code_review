# XSS

<display_name>Cross-Site Scripting (XSS)</display_name>

<prompt>
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Cross-Site Scripting (XSS) vulnerabilities by following the remote user-input call chain of code.

XSS-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - HTML rendering functions
   - JavaScript generation or manipulation
   - DOM manipulation methods

2. Output Contexts:
   - Unescaped output in HTML content
   - Attribute value insertion
   - JavaScript code or JSON data embedding

3. Input Handling:
   - User input reflection in responses
   - Sanitization and encoding functions
   - Custom input filters or cleaners

4. Indirect XSS Vectors:
   - Stored user input (e.g., in databases, files)
   - URL parameter reflection
   - HTTP header injection points

5. Example XSS-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input flows into HTML, JavaScript, or JSON contexts
- Effectiveness of input validation, sanitization, and output encoding
- Potential for filter evasion using encoding or obfuscation
- Impact of Content Security Policy (CSP) if implemented
</prompt>

<bypasses>
- {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
- ${7*7}
- {% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("id").read()}}{%endif%}{% endfor %}
- <script>alert(document.domain)</script>
- javascript:alert(1)
</bypasses>
