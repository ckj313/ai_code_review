# SSRF

<display_name>Server-Side Request Forgery (SSRF)</display_name>

<prompt>
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Server-Side Request Forgery (SSRF) vulnerabilities by following the remote user-input call chain of code.

SSRF-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - requests.get(), urllib.request.urlopen()
   - Custom HTTP clients
   - API calls to external services

2. URL Parsing and Validation:
   - URL parsing libraries usage
   - Custom URL validation routines

3. Indirect SSRF Vectors:
   - File inclusion functions (e.g., reading from URLs)
   - XML parsers with external entity processing
   - PDF generators, image processors using remote resources

4. Cloud Metadata Access:
   - Requests to cloud provider metadata URLs

5. Example SSRF-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input influences outgoing network requests
- Effectiveness of URL validation and whitelisting approaches
- Potential for DNS rebinding or time-of-check to time-of-use attacks
</prompt>

<bypasses>
- http://0.0.0.0:22
- file:///etc/passwd
- dict://127.0.0.1:11211/
- ftp://anonymous:anonymous@127.0.0.1:21
- gopher://127.0.0.1:9000/_GET /
</bypasses>
