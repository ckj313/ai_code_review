import json
import re
import argparse
import structlog
from vulnhuntr.c_symbol_finder import CSymbolExtractor
from vulnhuntr.LLMs import Claude, ChatGPT, Ollama
from vulnhuntr.prompts import (
    ANALYSIS_APPROACH_TEMPLATE,
    GUIDELINES_TEMPLATE,
    README_SUMMARY_PROMPT_TEMPLATE,
    build_system_prompt,
)
from vulnhuntr.rule_engine import RuleMatch, build_rule_engine
from vulnhuntr.skill_loader import load_skill_details, load_vuln_skills
from rich.console import Console
from typing import Dict, List, Generator
from pathlib import Path
from pydantic_xml import BaseXmlModel, element
from pydantic import BaseModel, Field
import dotenv
import os

dotenv.load_dotenv()

structlog.configure(
    processors=[
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.WriteLoggerFactory(
        file=Path('vulnhuntr').with_suffix(".log").open("wt")
    )
)

import faulthandler
faulthandler.enable()

log = structlog.get_logger("vulnhuntr")
console = Console(markup=False)

class ContextCode(BaseModel):
    name: str = Field(description="Function or Class name")
    reason: str = Field(description="Brief reason why this function's code is needed for analysis")
    code_line: str = Field(description="The single line of code where where this context object is referenced.")

def build_response_model() -> type[BaseModel]:
    class Response(BaseModel):
        scratchpad: str = Field(description="Your step-by-step analysis process. Output in plaintext with no line breaks.")
        analysis: str = Field(description="Your final analysis. Output in plaintext with no line breaks.")
        poc: str = Field(description="Proof-of-concept exploit, if applicable.")
        confidence_score: int = Field(description="0-10, where 0 is no confidence and 10 is absolute certainty because you have the entire user input to server output code path.")
        context_code: List[ContextCode] = Field(description="List of context code items requested for analysis, one function or class name per item. No standard library or third-party package code.")

    return Response

class ReadmeContent(BaseXmlModel, tag="readme_content"):
    content: str

class ReadmeSummary(BaseXmlModel, tag="readme_summary"):
    readme_summary: str

class Instructions(BaseXmlModel, tag="instructions"):
    instructions: str

class ResponseFormat(BaseXmlModel, tag="response_format"):
    response_format: str

class AnalysisApproach(BaseXmlModel, tag="analysis_approach"):
    analysis_approach: str

class Guidelines(BaseXmlModel, tag="guidelines"):
    guidelines: str

class FileCode(BaseXmlModel, tag="file_code"):
    file_path: str = element()
    file_source: str = element()

class PreviousAnalysis(BaseXmlModel, tag="previous_analysis"):
    previous_analysis: str

class ExampleBypasses(BaseXmlModel, tag="example_bypasses"):
    example_bypasses: str

class SkillId(BaseXmlModel, tag="skill_id"):
    skill_id: str

class PositiveExample(BaseXmlModel, tag="positive_example"):
    positive_example: str

class NegativeExample(BaseXmlModel, tag="negative_example"):
    negative_example: str

class CandidateMatch(BaseXmlModel, tag="candidate_match"):
    rule_id: str = element()
    file_path: str = element()
    start: int = element()
    end: int = element()
    snippet: str = element()

class CandidateMatches(BaseXmlModel, tag="candidate_matches"):
    matches: List[CandidateMatch] = []

class CodeDefinition(BaseXmlModel, tag="code"):
    name: str = element()
    context_name_requested: str = element()
    file_path: str = element()
    source: str = element()

class CodeDefinitions(BaseXmlModel, tag="context_code"):
    definitions: List[CodeDefinition] = []

class RepoOps:
    def __init__(self, repo_path: Path | str ) -> None:
        self.repo_path = Path(repo_path)
        self.to_exclude = {'/setup.py', '/test', '/example', '/docs', '/site-packages', '.venv', 'virtualenv', '/dist'}
        self.file_names_to_exclude = ['test_', 'conftest', '_test.py']

    def get_readme_content(self) -> str:
        # Use glob to find README.md or README.rst in a case-insensitive manner in the root directory
        prioritized_patterns = ["[Rr][Ee][Aa][Dd][Mm][Ee].[Mm][Dd]", "[Rr][Ee][Aa][Dd][Mm][Ee].[Rr][Ss][Tt]"]
        
        # First, look for README.md or README.rst in the root directory with case insensitivity
        for pattern in prioritized_patterns:
            for readme in self.repo_path.glob(pattern):
                with readme.open(encoding='utf-8') as f:
                    return f.read()
                
        # If no README.md or README.rst is found, look for any README file with supported extensions
        for readme in self.repo_path.glob("[Rr][Ee][Aa][Dd][Mm][Ee]*.[Mm][DdRrSsTt]"):
            with readme.open(encoding='utf-8') as f:
                return f.read()
        
        return

    def get_relevant_files(self, extensions: List[str]) -> Generator[Path, None, None]:
        """Gets all source files matching extensions minus the ones in the exclude list."""
        files = []
        for ext in extensions:
            for f in self.repo_path.rglob(f"*{ext}"):
                # Convert the path to a string with forward slashes
                f_str = str(f).replace('\\', '/')
                
                # Lowercase the string for case-insensitive matching
                f_str = f_str.lower()

                # Check if any exclusion pattern matches a substring of the full path
                if any(exclude in f_str for exclude in self.to_exclude):
                    continue

                # Check if the file name should be excluded
                if any(fn in f.name for fn in self.file_names_to_exclude):
                    continue
                
                files.append(f)

        return files

    def get_files_to_analyze(self, analyze_path: Path | None = None, extensions: List[str] | None = None) -> List[Path]:
        path_to_analyze = analyze_path or self.repo_path
        extensions = extensions or [".c", ".h"]
        if path_to_analyze.is_file():
            return [path_to_analyze]
        elif path_to_analyze.is_dir():
            files = []
            for ext in extensions:
                files.extend(list(path_to_analyze.rglob(f"*{ext}")))
            return files
        else:
            raise FileNotFoundError(f"Specified analyze path does not exist: {path_to_analyze}")

def extract_between_tags(tag: str, string: str, strip: bool = False) -> list[str]:
    """
    https://github.com/anthropics/anthropic-cookbook/blob/main/misc/how_to_enable_json_mode.ipynb
    """
    ext_list = re.findall(f"<{tag}>(.+?)</{tag}>", string, re.DOTALL)
    if strip:
        ext_list = [e.strip() for e in ext_list]
    return ext_list


def group_matches_by_skill(matches: List[RuleMatch]) -> Dict[str, List[RuleMatch]]:
    grouped: Dict[str, List[RuleMatch]] = {}
    for match in matches:
        grouped.setdefault(match.skill_id, []).append(match)
    return grouped

def initialize_llm(llm_arg: str, system_prompt: str = "") -> Claude | ChatGPT | Ollama:
    llm_arg = llm_arg.lower()
    if llm_arg == 'claude':
        anth_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        anth_base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        llm = Claude(anth_model, anth_base_url, system_prompt)
    elif llm_arg == 'gpt':
        openai_model = os.getenv("OPENAI_MODEL", "chatgpt-4o-latest")
        openai_base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        llm = ChatGPT(openai_model, openai_base_url, system_prompt)
    elif llm_arg == 'ollama':
        ollama_model = os.getenv("OLLAMA_MODEL", "llama3")
        ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/api/generate")
        llm = Ollama(ollama_model, ollama_base_url, system_prompt)
    else:
        raise ValueError(f"Invalid LLM argument: {llm_arg}\nValid options are: claude, gpt, ollama")
    return llm

def print_readable(report: BaseModel) -> None:
    label_map = {
        "scratchpad": "推理过程",
        "analysis": "分析结论",
        "poc": "PoC",
        "confidence_score": "置信度",
        "context_code": "上下文请求",
    }
    for attr, value in vars(report).items():
        label = label_map.get(attr, attr)
        console.print(f"{label}:")
        if isinstance(value, str):
            # For multiline strings, add indentation
            lines = value.split('\n')
            for line in lines:
                console.print(f"  {line}")
        elif isinstance(value, list):
            # For lists, print each item on a new line
            for item in value:
                console.print(f"  - {item}")
        else:
            # For other types, just print the value
            console.print(f"  {value}")
        console.print('-' * 40)
        console.print("")  # Add an empty line between attributes

def run():
    parser = argparse.ArgumentParser(description='Analyze a GitHub project for vulnerabilities. Export your ANTHROPIC_API_KEY/OPENAI_API_KEY before running.')
    parser.add_argument('-r', '--root', type=str, required=True, help='Path to the root directory of the project')
    parser.add_argument('-a', '--analyze', type=str, help='Specific path or file within the project to analyze')
    parser.add_argument('-l', '--llm', type=str, choices=['claude', 'gpt', 'ollama'], default='claude', help='LLM client to use (default: claude)')
    parser.add_argument('-v', '--verbosity', action='count', default=0, help='Increase output verbosity (-v for INFO, -vv for DEBUG)')
    args = parser.parse_args()

    repo = RepoOps(args.root)
    code_extractor = CSymbolExtractor(args.root)
    skills = load_vuln_skills(load_full=False)
    skill_names = sorted(skills)
    vuln_display_names = [skills[name].display_name for name in skill_names]
    skills_without_rules = [name for name in skill_names if not skills[name].rules]
    if skills_without_rules:
        log.warning("Skills missing rules", skills=skills_without_rules)
    if len(skills_without_rules) == len(skill_names):
        raise ValueError("No rules found in skills; add <rules> blocks to SKILL.md files")
    rule_engine = build_rule_engine(skills)
    ResponseModel = build_response_model()
    log.info("Loaded vuln skills", skills=skill_names)
    if args.verbosity > 0:
        console.print(f"已加载技能: {', '.join(skill_names)}")
    # Get repo files that don't include stuff like tests and documentation
    extensions = [".c", ".h"]
    files = repo.get_relevant_files(extensions)

    # User specified --analyze flag
    if args.analyze:
        # Determine the path to analyze
        analyze_path = Path(args.analyze)

        # If the path is absolute, use it as is, otherwise join it with the root path so user can specify relative paths
        if analyze_path.is_absolute():
            files_to_analyze = repo.get_files_to_analyze(analyze_path, extensions)
        else:
            files_to_analyze = repo.get_files_to_analyze(Path(args.root) / analyze_path, extensions)

    # Analyze the entire project for network-related files
    else:
        files_to_analyze = files
    
    llm = initialize_llm(args.llm)

    readme_content = repo.get_readme_content()
    if readme_content:
        log.info("Summarizing project README")
        summary = llm.chat(
            (ReadmeContent(content=readme_content).to_xml() + b'\n' +
            Instructions(instructions=README_SUMMARY_PROMPT_TEMPLATE).to_xml()
            ).decode()
        )
        summary = extract_between_tags("summary", summary)[0]
        log.info("README summary complete", summary=summary)
    else:
        log.warning("No README summary found")
        summary = ''
    
    # Initialize the system prompt with the README summary
    system_prompt = (Instructions(instructions=build_system_prompt(vuln_display_names)).to_xml() + b'\n' +
                ReadmeSummary(readme_summary=summary).to_xml()
                ).decode()
    
    llm = initialize_llm(args.llm, system_prompt)

    scanned_files = 0
    matched_files = 0
    total_matches = 0

    # files_to_analyze is either a list of all network-related files or a list containing a single file/dir to analyze
    for py_f in files_to_analyze:
        log.info("Scanning file for rule matches", file=str(py_f))

        with py_f.open(encoding='utf-8') as f:
            content = f.read()
            if not len(content):
                continue

            scanned_files += 1
            matches = rule_engine.scan(content, str(py_f))
            if args.verbosity > 1:
                console.print(f"扫描 {py_f} - 命中: {len(matches)}")
            if not matches:
                continue

            matched_files += 1
            total_matches += len(matches)
            matches_by_skill = group_matches_by_skill(matches)
            log.info("Rule matches found", file=str(py_f), skills=sorted(matches_by_skill))

            console.print(f"\n分析 {py_f}")
            console.print('-' * 40 +'\n')
            if args.verbosity > 0:
                console.print(f"规则命中: {', '.join(sorted(matches_by_skill))}")

            for skill_name, skill_matches in matches_by_skill.items():
                skill = skills.get(skill_name)
                if not skill:
                    log.warning("Unknown skill for rule match", skill=skill_name, file=py_f)
                    continue
                if not skill.prompt:
                    skill = load_skill_details(skill)
                    skills[skill_name] = skill
                max_candidate_matches = 25
                if len(skill_matches) > max_candidate_matches:
                    log.info(
                        "Truncating candidate matches",
                        skill=skill_name,
                        total=len(skill_matches),
                        limit=max_candidate_matches,
                    )
                    skill_matches = skill_matches[:max_candidate_matches]

                log.info("Using vuln skill", vuln_type=skill_name, skill=skill.name, matches=len(skill_matches))

                candidate_matches = CandidateMatches(
                    matches=[
                        CandidateMatch(
                            rule_id=match.rule_id,
                            file_path=match.file_path,
                            start=match.start,
                            end=match.end,
                            snippet=match.snippet,
                        )
                        for match in skill_matches
                    ]
                )

                # Do not fetch the context code on the first pass of the secondary analysis because the context will be from the general analysis
                stored_code_definitions = {}
                definitions = CodeDefinitions(definitions=[])
                same_context = False

                # Don't include the first iteration of the secondary analysis in the user_prompt
                previous_analysis = ''
                previous_context_amount = 0

                for i in range(7):
                    log.info("Performing vuln-specific analysis", iteration=i, vuln_type=skill_name, file=py_f)

                    # Only lookup context code and previous analysis on second pass and onwards
                    if i > 0:
                        previous_context_amount = len(stored_code_definitions)
                        previous_analysis = secondary_analysis_report.analysis

                        for context_item in secondary_analysis_report.context_code:
                            # Make sure bot isn't requesting the same code multiple times
                            if context_item.name not in stored_code_definitions:
                                name = context_item.name
                                code_line = context_item.code_line
                                match = code_extractor.extract(name, code_line, files)
                                if match:
                                    stored_code_definitions[name] = match

                        code_definitions = list(stored_code_definitions.values())
                        definitions = CodeDefinitions(definitions=code_definitions)

                        if args.verbosity > 1:
                            for definition in definitions.definitions:
                                if '\n' in definition.source:
                                    lines = definition.source.split('\n')
                                    snippet = lines[0] + '\n' + lines[1]
                                else:
                                    snippet = definition.source[:75]

                                console.print(f"名称: {definition.name}")
                                console.print(f"上下文搜索: {definition.context_name_requested}")
                                console.print(f"文件路径: {definition.file_path}")
                                console.print(f"源码前两行: {snippet}\n")

                    vuln_specific_user_prompt = (
                        FileCode(file_path=str(py_f), file_source=content).to_xml() + b'\n' +
                        SkillId(skill_id=skill.name).to_xml() + b'\n' +
                        candidate_matches.to_xml() + b'\n' +
                        definitions.to_xml() + b'\n' +  # These are all the requested context functions and classes
                        ExampleBypasses(
                            example_bypasses='\n'.join(skill.bypasses)
                        ).to_xml() + b'\n' +
                        PositiveExample(
                            positive_example=skill.positive_example
                        ).to_xml() + b'\n' +
                        NegativeExample(
                            negative_example=skill.negative_example
                        ).to_xml() + b'\n' +
                        Instructions(instructions=skill.prompt).to_xml() + b'\n' +
                        AnalysisApproach(analysis_approach=ANALYSIS_APPROACH_TEMPLATE).to_xml() + b'\n' +
                        PreviousAnalysis(previous_analysis=previous_analysis).to_xml() + b'\n' +
                        Guidelines(guidelines=GUIDELINES_TEMPLATE).to_xml() + b'\n' +
                        ResponseFormat(
                            response_format=json.dumps(
                                ResponseModel.model_json_schema(), indent=4
                            )
                        ).to_xml()
                    ).decode()

                    secondary_analysis_report = llm.chat(vuln_specific_user_prompt, response_model=ResponseModel)
                    log.info("Secondary analysis complete", secondary_analysis_report=secondary_analysis_report.model_dump())

                    if args.verbosity > 0:
                        print_readable(secondary_analysis_report)

                    if not len(secondary_analysis_report.context_code):
                        log.debug("No new context functions or classes found")
                        if args.verbosity == 0:
                            print_readable(secondary_analysis_report)
                        break

                    # Check if any new context code is requested
                    if previous_context_amount >= len(stored_code_definitions) and i > 0:
                        # Let it request the same context once, then on the second time it requests the same context, break
                        if same_context:
                            log.debug("No new context functions or classes requested")
                            if args.verbosity == 0:
                                print_readable(secondary_analysis_report)
                            break
                        same_context = True
                        log.debug("No new context functions or classes requested")
                pass

    if args.verbosity > 0:
        console.print(
            f"扫描汇总 - 扫描文件: {scanned_files}, 命中文件: {matched_files}, 命中总数: {total_matches}"
        )

if __name__ == '__main__':
    run()
