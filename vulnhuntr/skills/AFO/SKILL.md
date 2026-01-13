# AFO

<display_name>Arbitrary File Overwrite (AFO)</display_name>

<prompt>
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Arbitrary File Overwrite (AFO) vulnerabilities by following the remote user-input call chain of code.

AFO-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - open() with write modes
   - os.rename(), shutil.move()
   - Custom file writing functions

2. Path Traversal Opportunities:
   - User-controlled file paths
   - Directory creation or manipulation

3. File Operation Wrappers:
   - Custom file management classes
   - Frameworks' file handling methods

4. Indirect File Writes:
   - Log file manipulation
   - Configuration file updates
   - Cache file creation

5. Example AFO-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input influences file paths or names
- Effectiveness of path sanitization and validation
- Potential for race conditions in file operations
</prompt>

<bypasses>
- ../../../etc/passwd%00.jpg
- shell.py;.jpg
- .htaccess
- /proc/self/cmdline
- ../../config.py/.
</bypasses>
