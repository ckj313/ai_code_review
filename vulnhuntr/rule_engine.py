import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence

from vulnhuntr.skill_loader import SkillRule, VulnSkill


@dataclass(frozen=True)
class RuleMatch:
    file_path: str
    start: int
    end: int
    snippet: str
    rule_id: str
    skill_id: str


def _extract_snippet(text: str, start: int, end: int, radius: int = 120) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    snippet = text[left:right]
    return snippet.replace("\n", " ").replace("\r", " ").strip()


def _validate_rule_patterns(rules: Sequence[SkillRule]) -> None:
    for rule in rules:
        pattern = rule.pattern
        if rule.kind == "literal":
            pattern = re.escape(pattern)
        try:
            re.compile(pattern, re.MULTILINE)
        except re.error as exc:
            raise ValueError(
                f"Invalid rule pattern for {rule.skill_id}:{rule.rule_id}: {exc}"
            ) from exc


class CombinedRegexEngine:
    def __init__(self, rules: Sequence[SkillRule]) -> None:
        if not rules:
            raise ValueError("No rules provided for scanning")
        _validate_rule_patterns(rules)
        self.rules = list(rules)
        self._regex, self._group_to_rule = self._compile_rules(self.rules)

    def scan(self, text: str, file_path: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for match in self._regex.finditer(text):
            group = match.lastgroup
            if not group:
                continue
            rule = self._group_to_rule[group]
            snippet = _extract_snippet(text, match.start(), match.end())
            matches.append(
                RuleMatch(
                    file_path=file_path,
                    start=match.start(),
                    end=match.end(),
                    snippet=snippet,
                    rule_id=rule.rule_id,
                    skill_id=rule.skill_id,
                )
            )
        return matches

    def _compile_rules(self, rules: Sequence[SkillRule]) -> tuple[re.Pattern, Dict[str, SkillRule]]:
        parts: List[str] = []
        group_to_rule: Dict[str, SkillRule] = {}
        for idx, rule in enumerate(rules):
            group_name = f"r{idx}"
            group_to_rule[group_name] = rule
            pattern = rule.pattern
            if rule.kind == "literal":
                pattern = re.escape(pattern)
            parts.append(f"(?P<{group_name}>{pattern})")
        combined = "|".join(parts)
        return re.compile(combined, re.MULTILINE), group_to_rule


def build_rule_engine(skills: Dict[str, VulnSkill]) -> CombinedRegexEngine:
    rules: List[SkillRule] = []
    for skill in skills.values():
        rules.extend(skill.rules)
    return CombinedRegexEngine(rules)
