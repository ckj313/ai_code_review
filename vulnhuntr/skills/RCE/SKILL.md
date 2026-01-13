# RCE

<display_name>Remote Code Execution (RCE)</display_name>

<prompt>
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Remote Code Execution (RCE) vulnerabilities by following the remote user-input call chain of code.

RCE-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - eval(), exec(), subprocess modules
   - os.system(), os.popen()
   - pickle.loads(), yaml.load(), json.loads() with custom decoders

2. Indirect Code Execution:
   - Dynamic imports (e.g., __import__())
   - Reflection/introspection misuse
   - Server-side template injection

3. Command Injection Vectors:
   - Shell command composition
   - Unsanitized use of user input in system calls

4. Deserialization Vulnerabilities:
   - Unsafe deserialization of user-controlled data

5. Example RCE-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input flows into these high-risk areas
- Potential for filter evasion or sanitization bypasses
- Environment-specific factors (e.g., Python version, OS) affecting exploitability
</prompt>

<bypasses>
- __import__('os').system('id')
- eval('__import__(\'os\').popen(\'id\').read()')
- exec('import subprocess;print(subprocess.check_output([\'id\']))')
- globals()['__builtins__'].__import__('os').system('id')
- getattr(__import__('os'), 'system')('id')
- $(touch${IFS}/tmp/mcinerney)
- import pickle; pickle.loads(b\'cos\\nsystem\\n(S"id"\\ntR.\')
</bypasses>
