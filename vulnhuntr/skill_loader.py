import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

SKILLS_DIR = Path(__file__).with_name("skills")


@dataclass(frozen=True)
class SkillRule:
    rule_id: str
    skill_id: str
    pattern: str
    kind: str


@dataclass(frozen=True)
class VulnSkill:
    name: str
    display_name: str
    summary: str
    prompt: str
    bypasses: List[str]
    rules: List[SkillRule]
    positive_example: str
    negative_example: str
    path: Path


def _extract_tag(content: str, tag: str) -> str:
    match = re.findall(rf"<{tag}>(.+?)</{tag}>", content, re.DOTALL)
    if not match:
        return ""
    return match[0].strip()


def _parse_bypasses(block: str) -> List[str]:
    if not block:
        return []
    items = []
    for line in block.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("-"):
            line = line[1:].strip()
        items.append(line)
    return items


def _parse_rules(block: str, skill_name: str) -> List[SkillRule]:
    if not block:
        return []
    rules: List[SkillRule] = []
    rule_index = 1
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        kind = "regex"
        pattern = line
        if line.startswith("regex:"):
            pattern = line[len("regex:"):].strip()
        elif line.startswith("literal:"):
            pattern = line[len("literal:"):].strip()
            kind = "literal"
        if not pattern:
            continue
        rule_id = f"{skill_name}_{rule_index:03d}"
        rules.append(
            SkillRule(
                rule_id=rule_id,
                skill_id=skill_name,
                pattern=pattern,
                kind=kind,
            )
        )
        rule_index += 1
    return rules


def _load_skill_file(skill_file: Path, load_full: bool) -> VulnSkill:
    content = skill_file.read_text(encoding="utf-8")
    name = skill_file.parent.name.upper()
    display_name = _extract_tag(content, "display_name") or name
    summary = _extract_tag(content, "summary") or display_name
    rules_block = _extract_tag(content, "rules")
    rules = _parse_rules(rules_block, name)

    prompt = ""
    bypasses: List[str] = []
    positive_example = ""
    negative_example = ""
    if load_full:
        prompt = _extract_tag(content, "prompt")
        if not prompt:
            raise ValueError(f"Missing <prompt> tag in {skill_file}")
        bypasses_block = _extract_tag(content, "bypasses")
        bypasses = _parse_bypasses(bypasses_block)
        positive_example = _extract_tag(content, "positive_example")
        negative_example = _extract_tag(content, "negative_example")

    return VulnSkill(
        name=name,
        display_name=display_name,
        summary=summary,
        prompt=prompt,
        bypasses=bypasses,
        rules=rules,
        positive_example=positive_example,
        negative_example=negative_example,
        path=skill_file,
    )


def load_skill_details(skill: VulnSkill) -> VulnSkill:
    if skill.prompt:
        return skill
    return _load_skill_file(skill.path, load_full=True)


@lru_cache(maxsize=4)
def load_vuln_skills(
    skills_dir: Path | None = None,
    load_full: bool = True,
) -> Dict[str, VulnSkill]:
    root = Path(skills_dir) if skills_dir else SKILLS_DIR
    if not root.exists():
        raise FileNotFoundError(f"Skills directory not found: {root}")

    skills: Dict[str, VulnSkill] = {}
    for skill_file in sorted(root.glob("**/SKILL.md")):
        skill = _load_skill_file(skill_file, load_full)
        if skill.name in skills:
            raise ValueError(f"Duplicate skill name: {skill.name}")
        skills[skill.name] = skill

    if not skills:
        raise ValueError(f"No skills found under {root}")

    return skills
