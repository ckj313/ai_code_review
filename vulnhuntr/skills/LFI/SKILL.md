# LFI

<display_name>Local File Inclusion (LFI)</display_name>

<prompt>
Combine the code in <file_code> and <context_code> then analyze the code for remotely-exploitable Local File Inclusion (LFI) vulnerabilities by following the remote user-input call chain of code.

LFI-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - open(), file(), io.open()
   - os.path.join() for file paths
   - Custom file reading functions

2. Path Traversal Opportunities:
   - User-controlled file paths or names
   - Dynamic inclusion of files or modules

3. File Operation Wrappers:
   - Template engines with file inclusion features
   - Custom file management classes

4. Indirect File Inclusion:
   - Configuration file parsing
   - Plugin or extension loading systems
   - Log file viewers

5. Example LFI-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags

When analyzing, consider:
- How user input influences file paths or names
- Effectiveness of path sanitization and validation
- Potential for null byte injection or encoding tricks
- Interaction with file system access controls
</prompt>

<bypasses>
- ../../../../etc/passwd
- /proc/self/environ
- data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
- file:///etc/passwd
- C:\win.ini/?../../../../../../../etc/passwd
</bypasses>
