import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

SKILLS_DIR = Path(__file__).with_name("skills")


@dataclass(frozen=True)
class VulnSkill:
    name: str
    display_name: str
    prompt: str
    bypasses: List[str]


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


def load_vuln_skills(skills_dir: Path | None = None) -> Dict[str, VulnSkill]:
    root = skills_dir or SKILLS_DIR
    if not root.exists():
        raise FileNotFoundError(f"Skills directory not found: {root}")

    skills: Dict[str, VulnSkill] = {}
    for skill_file in sorted(root.glob("*/SKILL.md")):
        content = skill_file.read_text(encoding="utf-8")
        name = skill_file.parent.name.upper()
        display_name = _extract_tag(content, "display_name") or name
        prompt = _extract_tag(content, "prompt")
        if not prompt:
            raise ValueError(f"Missing <prompt> tag in {skill_file}")
        bypasses_block = _extract_tag(content, "bypasses")
        bypasses = _parse_bypasses(bypasses_block)
        if name in skills:
            raise ValueError(f"Duplicate skill name: {name}")
        skills[name] = VulnSkill(
            name=name,
            display_name=display_name,
            prompt=prompt,
            bypasses=bypasses,
        )

    if not skills:
        raise ValueError(f"No skills found under {root}")

    return skills
