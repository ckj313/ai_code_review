from typing import Sequence


def _format_bullet_list(items: Sequence[str]) -> str:
    return "\n".join(f"   - {item}" for item in items)


def _format_numbered_list(items: Sequence[str]) -> str:
    return "\n".join(f"{i}. {item}" for i, item in enumerate(items, start=1))


def build_initial_analysis_prompt(vuln_display_names: Sequence[str]) -> str:
    vuln_list = _format_bullet_list(vuln_display_names)
    return INITIAL_ANALYSIS_PROMPT_TEMPLATE.format(vuln_list=vuln_list)


def build_system_prompt(vuln_display_names: Sequence[str]) -> str:
    vuln_list = _format_numbered_list(vuln_display_names)
    return SYS_PROMPT_TEMPLATE.format(vuln_list=vuln_list)


INITIAL_ANALYSIS_PROMPT_TEMPLATE = """
Analyze the code in <file_code> tags for potential remotely exploitable vulnerabilities:
1. Identify all remote user input entry points (e.g., API endpoints, form submissions) and if you can't find that, request the necessary classes or functions in the <context_code> tags.
2. Locate potential vulnerability sinks for:
{vuln_list}
3. Note any security controls or sanitization measures encountered along the way so you can craft bypass techniques for the proof of concept (PoC).
4. Highlight areas where more context is needed to complete the analysis.

Be generous and thorough in identifying potential vulnerabilities as you'll analyze more code in subsequent steps so if there's just a possibility of a vulnerability, include it the <vulnerability_types> tags.
"""

README_SUMMARY_PROMPT_TEMPLATE = """
Provide a very concise summary of the README.md content in <readme_content></readme_content> tags from a security researcher's perspective, focusing specifically on:
1. The project's main purpose
2. Any networking capabilities, such as web interfaces or remote API calls that constitute remote attack surfaces
3. Key features that involve network communications

Please keep the summary brief and to the point, highlighting only the most relevant networking-related functionality as it relates to attack surface.

Output in <summary></summary> XML tags.
"""

GUIDELINES_TEMPLATE = """Reporting Guidelines:
1. JSON Format:
   - Provide a single, well-formed JSON report combining all findings.
   - Use 'None' for any aspect of the report that you lack the necessary information for.
   - Place your step-by-step analysis in the scratchpad field, before doing a final analysis in the analysis field.

2. Context Requests:
   - Classes: Use ClassName1,ClassName2
   - Functions: Use func_name,ClassName.method_name
   - If you request ClassName, do not also request ClassName.method_name as that code will already be fetched with the ClassName request.
   - Important: Do not request code from standard libraries or third-party packages. Simply use what you know about them in your analysis.

3. Vulnerability Reporting:
   - Report only remotely exploitable vulnerabilities (no local access/CLI args).
   - Always include at least one vulnerability_type field when requesting context.
   - Provide a confidence score (0-10) and detailed justification for each vulnerability.
     - If your proof of concept (PoC) exploit does not start with remote user input via remote networking calls such as remote HTTP, API, or RPC calls, set the confidence score to 6 or below.
   
4. Proof of Concept:
   - Include a PoC exploit or detailed exploitation steps for each vulnerability.
   - Ensure PoCs are specific to the analyzed code, not generic examples.
   - Review the code path ofthe potential vulnerability and be sure that the PoC bypasses any security controls in the code path.
"""

ANALYSIS_APPROACH_TEMPLATE = """Analysis Instructions:
1. Comprehensive Review:
   - Thoroughly examine the content in <file_code>, <context_code> tags (if provided) with a focus on remotely exploitable vulnerabilities.

2. Vulnerability Scanning:
   - You only care about remotely exploitable network related components and remote user input handlers.
   - Identify potential entry points for vulnerabilities.
   - Consider non-obvious attack vectors and edge cases.

3. Code Path Analysis:
   - Very important: trace the flow of user input from remote request source to function sink.
   - Examine input validation, sanitization, and encoding practices.
   - Analyze how data is processed, stored, and output.

4. Security Control Analysis:
   - Evaluate each security measure's implementation and effectiveness.
   - Formulate potential bypass techniques, considering latest exploit methods.

6. Context-Aware Analysis:
   - If this is a follow-up analysis, build upon previous findings in <previous_analysis> using the new information provided in the <context_code>.
   - Request additional context code as needed to complete the analysis and you will be provided with the necessary code.
   - Confirm that the requested context class or function is not already in the <context_code> tags from the user's message.

7. Final Review:
   - Confirm your proof of concept (PoC) exploits bypass any security controls.
   - Double-check that your JSON response is well-formed and complete."""

SYS_PROMPT_TEMPLATE = """
You are the world's foremost expert in Python security analysis, renowned for uncovering novel and complex vulnerabilities in web applications. Your task is to perform an exhaustive static code analysis, focusing on remotely exploitable vulnerabilities including but not limited to:

{vuln_list}

Your analysis must:
- Meticulously track user input from remote sources to high-risk function sinks.
- Uncover complex, multi-step vulnerabilities that may bypass multiple security controls.
- Consider non-obvious attack vectors and chained vulnerabilities.
- Identify vulnerabilities that could arise from the interaction of multiple code components.

If you don't have the complete code chain from user input to high-risk function, strategically request the necessary context to fill in the gaps in the <context_code> tags of your response.

The project's README summary is provided in <readme_summary> tags. Use this to understand the application's purpose and potential attack surfaces.

Remember, you have many opportunities to respond and request additional context. Use them wisely to build a comprehensive understanding of the application's security posture.

Output your findings in JSON format, conforming to the schema in <response_format> tags.
"""
