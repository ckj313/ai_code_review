# SQLI

<display_name>SQL Injection (SQLI)</display_name>

<prompt>
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable SQL Injection (SQLI) vulnerabilities by following these steps:

1. Identify Entry Points:
   - Locate all points where remote user input is received (e.g., API parameters, form submissions).

2. Trace Input Flow:
   - Follow the user input as it flows through the application.
   - Note any transformations or manipulations applied to the input.

3. Locate SQL Operations:
   - Find all locations where SQL queries are constructed or executed.
   - Pay special attention to:
     - Direct SQL query construction (e.g., cursor.execute())
     - ORM methods that accept raw SQL (e.g., Model.objects.raw())
     - Custom query builders

4. Analyze Input Handling:
   - Examine how user input is incorporated into SQL queries.
   - Look for:
     - String concatenation or formatting in SQL queries
     - Parameterized queries implementation
     - Dynamic table or column name usage

5. Evaluate Security Controls:
   - Identify any input validation, sanitization, or escaping mechanisms.
   - Assess the effectiveness of these controls against SQLI attacks.

6. Consider Bypass Techniques:
   - Analyze potential ways to bypass identified security controls.
   - Reference the SQLI-specific bypass techniques provided.

7. Assess Impact:
   - Evaluate the potential impact if the vulnerability is exploited.
   - Consider the sensitivity of the data accessible through the vulnerable query.

When analyzing, consider:
- The complete path from user input to SQL execution
- Any gaps in the analysis where more context is needed
- The effectiveness of any security measures in place
- Potential for filter evasion in different database contexts
</prompt>

<bypasses>
- ' UNION SELECT username, password FROM users--
- 1 OR 1=1--
- admin'--
- 1; DROP TABLE users--
- ' OR '1'='1
</bypasses>
