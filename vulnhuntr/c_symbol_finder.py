import re
from pathlib import Path
from typing import Dict, List, Optional


class CSymbolExtractor:
    def __init__(self, repo_path: str | Path) -> None:
        self.repo_path = Path(repo_path)

    def extract(self, symbol_name: str, code_line: str, filtered_files: List[Path]) -> Optional[Dict]:
        symbol = symbol_name.split(".")[-1].strip()
        if not symbol or not re.match(r"^[A-Za-z_]\w*$", symbol):
            return None

        matching_files = [
            file for file in filtered_files if self._search_string_in_file(file, code_line)
        ]
        if not matching_files:
            matching_files = filtered_files

        for file in matching_files:
            source = file.read_text(encoding="utf-8", errors="ignore")
            match = self._find_definition(source, symbol)
            if match:
                return {
                    "name": symbol,
                    "context_name_requested": symbol_name,
                    "file_path": str(file),
                    "source": match,
                }
        return None

    def _find_definition(self, source: str, symbol: str) -> Optional[str]:
        func_pattern = re.compile(
            rf"^[ \t\w\*\(\),]+\b{re.escape(symbol)}\s*\([^;{{]*\)\s*\{{",
            re.MULTILINE,
        )
        match = func_pattern.search(source)
        if match:
            return self._extract_block(source, match.start())

        struct_pattern = re.compile(rf"^\s*struct\s+{re.escape(symbol)}\b", re.MULTILINE)
        match = struct_pattern.search(source)
        if match:
            return self._extract_block(source, match.start())

        typedef_pattern = re.compile(
            rf"^\s*typedef\s+struct\b[\s\S]*?\}}\s*{re.escape(symbol)}\b",
            re.MULTILINE,
        )
        match = typedef_pattern.search(source)
        if match:
            return self._extract_block(source, match.start())

        macro_pattern = re.compile(rf"^\s*#define\s+{re.escape(symbol)}\b.*$", re.MULTILINE)
        match = macro_pattern.search(source)
        if match:
            return match.group(0).strip()

        return None

    def _extract_block(self, source: str, start_index: int) -> str:
        brace_start = source.find("{", start_index)
        if brace_start == -1:
            return self._extract_snippet(source, start_index)
        depth = 0
        for idx in range(brace_start, len(source)):
            char = source[idx]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[start_index : idx + 1].strip()
        return source[start_index:].strip()

    def _extract_snippet(self, source: str, start_index: int, radius: int = 600) -> str:
        left = max(0, start_index - radius)
        right = min(len(source), start_index + radius)
        return source[left:right].strip()

    def _search_string_in_file(self, file: Path, code_line: str) -> bool:
        if not code_line:
            return True
        normalized = self._normalize(code_line)
        with file.open(encoding="utf-8", errors="ignore") as f:
            return normalized in self._normalize(f.read())

    @staticmethod
    def _normalize(text: str) -> str:
        return (
            text.replace(" ", "")
            .replace("\n", "")
            .replace('"', "'")
            .replace("\r", "")
            .replace("\t", "")
        )
