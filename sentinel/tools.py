"""
sentinel/tools.py
-----------------
The "tool layer": the small, safe functions the AI agent calls to investigate a
codebase. Think of these as the agent's hands — the ONLY ways it can touch the
target. Every tool here is:

  * SCOPED to the target directory. The agent can never read outside it. This
    blocks path-traversal (a confused/manipulated agent trying to read /etc/passwd
    or your SSH keys).
  * READ-ONLY. Investigation never modifies the target.
  * SMALL and PREDICTABLE. One clear job each, returning text/data the model can
    use. Good tool design is the #1 driver of agent reliability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class GrepMatch:
    path: str          # path relative to the target root
    line_number: int
    line: str          # the matching line, stripped of surrounding whitespace


class Tools:
    """Read-only investigation tools, locked to a single target directory."""

    def __init__(self, root: str | Path) -> None:
        # Resolve to one absolute path. Every tool is confined to here.
        self.root = Path(root).resolve()

    def _safe_path(self, relative_path: str) -> Path:
        """Resolve a path and REFUSE anything that escapes the target root.

        This is the security boundary for the whole tool layer. A path like
        '../../etc/passwd' resolves outside self.root, so we reject it.
        """
        candidate = (self.root / relative_path).resolve()
        if not candidate.is_relative_to(self.root):
            raise ValueError(
                f"Refused: path escapes the target directory: {relative_path}"
            )
        return candidate

    def list_files(self) -> list[str]:
        """List all Python files in the target, as paths relative to the root."""
        files = []
        for p in sorted(self.root.rglob("*.py")):
            if "__pycache__" in p.parts or ".venv" in p.parts:
                continue
            files.append(str(p.relative_to(self.root)))
        return files

    def read_file(
        self,
        relative_path: str,
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> str:
        """Read a file (or a slice) from inside the target directory.

        Line numbers are 1-based and inclusive — matching how humans and error
        messages talk about code.
        """
        path = self._safe_path(relative_path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

        start = (start_line - 1) if start_line else 0
        end = end_line if end_line else len(lines)
        selected = lines[start:end]

        # Prefix each line with its real line number — the agent needs these to
        # report exactly WHERE a vulnerability is.
        numbered = [f"{n}: {text}" for n, text in enumerate(selected, start=start + 1)]
        return "\n".join(numbered)

    def grep(self, pattern: str) -> list[GrepMatch]:
        """Search every Python file in the target for a regex pattern."""
        regex = re.compile(pattern)
        matches: list[GrepMatch] = []
        for rel in self.list_files():
            path = self.root / rel
            text = path.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    matches.append(GrepMatch(path=rel, line_number=i, line=line.strip()))
        return matches