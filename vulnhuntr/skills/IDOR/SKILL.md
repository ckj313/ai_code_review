# IDOR

<display_name>Insecure Direct Object Reference (IDOR)</display_name>

<prompt>
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Insecure Direct Object Reference (IDOR) vulnerabilities.

IDOR-Specific Focus Areas:
1. Look for code segments involving IDs, keys, filenames, session tokens, or any other unique identifiers that might be used to access resources (e.g., user_id, file_id, order_id).

2. Common Locations:
   - URLs/Routes: Check if IDs are passed directly in the URL parameters (e.g., /user/{user_id}/profile).
   - Form Parameters: Look for IDs submitted through forms.
   - API Endpoints: Examine API requests where IDs are sent in request bodies or headers.

3. Ensure Authorization is Enforced:
   - Verify that the code checks the user's authorization before allowing access to the resource identified by the ID.
   - Look for authorization checks immediately after the object reference is received.

4. Common Functions:
   - Functions like `has_permission()`, `is_authorized()`, or similar should be present near the object access code.
   - Absence of such checks could indicate a potential IDOR vulnerability.

5. Example IDOR-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input is used when processing a request.
- Presence of any logic responsible for determining the authentication/authorization of a user.
</prompt>

<bypasses>
</bypasses>
