"""
sentinel/patcher.py
-------------------
The Patcher: for a CONFIRMED finding, propose a minimal, secure fix.

It asks the model to rewrite the file with the vulnerability fixed, then computes a
real unified diff (with Python's difflib) between the original and the fix -- so we
show exactly what changed, accurately, without trusting the model to format a diff.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass

from sentinel.llm import LLMClient
from sentinel.hunter import Finding


SYSTEM_PROMPT = (
    "You are a senior secure-coding engineer. You fix security vulnerabilities with "
    "the smallest change that removes the risk while preserving behavior. You output "
    "ONLY the complete corrected file contents -- no prose, no markdown."
)

PATCH_PROMPT = """This file contains a confirmed {vuln_class} vulnerability around
line {line} ({description}).

Rewrite the ENTIRE file with that vulnerability fixed using a secure, idiomatic
approach (for example: parameterized SQL queries, argument lists instead of shell
strings, secrets read from environment variables). Change as little else as possible.

--- BEGIN FILE ---
{code}
--- END FILE ---

Output ONLY the full corrected file contents.
"""


@dataclass
class Patch:
    finding: Finding
    diff: str
    fixed_code: str


class Patcher:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def propose(self, finding: Finding, original_code: str) -> Patch:
        fixed = self._clean(
            self.llm.complete(
                prompt=PATCH_PROMPT.format(
                    vuln_class=finding.vuln_class,
                    line=finding.line,
                    description=finding.description,
                    code=original_code,
                ),
                system=SYSTEM_PROMPT,
            ).text
        )
        diff = self._make_diff(original_code, fixed, finding.file)
        return Patch(finding=finding, diff=diff, fixed_code=fixed)

    def _make_diff(self, original: str, fixed: str, filename: str) -> str:
        diff_lines = difflib.unified_diff(
            original.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
        return "".join(diff_lines)

    def _clean(self, text: str) -> str:
        """Strip markdown code fences if the model added them despite instructions."""
        text = text.strip()
        fence = "`" * 3
        if text.startswith(fence):
            lines = text.splitlines()
            lines = lines[1:]
            if lines and lines[-1].strip().startswith(fence):
                lines = lines[:-1]
            text = "\n".join(lines)
        return text