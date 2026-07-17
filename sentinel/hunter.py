"""
sentinel/hunter.py
------------------
The Hunter agent: the "brain" that uses the tool layer (its hands) and the model
layer (its reasoning) to find vulnerabilities in a codebase.

For each file in the target it:
  1. reads the source (with line numbers) via Tools,
  2. asks the LLM to analyze it and return structured findings as JSON,
  3. parses that JSON into typed Finding objects.

This is the first version. In Module 8 we'll wrap it in a LangGraph orchestrator
that lets the model call tools freely across multiple steps.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from sentinel.llm import LLMClient
from sentinel.tools import Tools


@dataclass
class Finding:
    """One vulnerability the Hunter believes it found."""
    vuln_class: str
    file: str
    line: int
    severity: str
    description: str
    confidence: float


SYSTEM_PROMPT = (
    "You are a meticulous application security analyst. You find real, exploitable "
    "vulnerabilities in source code, and you never invent issues that aren't there. "
    "You respond with JSON only - no prose, no markdown."
)

# {path} and {source} are filled in per file before sending to the model.
USER_PROMPT = """Analyze this Python file for security vulnerabilities.

Look especially for: SQL injection, command injection, hardcoded secrets,
path traversal, SSRF, and insecure deserialization.

For each vulnerability, report:
  - vuln_class: a short name, e.g. "SQL Injection"
  - line: the exact line number where it occurs
  - severity: one of "low", "medium", "high", "critical"
  - description: one sentence tracing the untrusted data from source to sink
  - confidence: a number from 0.0 to 1.0

File: {path}
--- BEGIN CODE ---
{source}
--- END CODE ---

Respond with ONLY this JSON shape and nothing else:
{{"findings": [{{"vuln_class": "", "line": 0, "severity": "", "description": "", "confidence": 0.0}}]}}
If you find nothing, respond with {{"findings": []}}.
"""


class Hunter:
    def __init__(self, llm: LLMClient, tools: Tools) -> None:
        self.llm = llm
        self.tools = tools

    def hunt(self) -> list[Finding]:
        """Analyze every file in the target and return all findings."""
        all_findings: list[Finding] = []
        for rel_path in self.tools.list_files():
            source = self.tools.read_file(rel_path)
            all_findings.extend(self._hunt_file(rel_path, source))
        return all_findings

    def _hunt_file(self, path: str, source: str) -> list[Finding]:
        prompt = USER_PROMPT.format(path=path, source=source)
        response = self.llm.complete(prompt=prompt, system=SYSTEM_PROMPT)
        return self._parse(response.text, path)

    def _parse(self, raw: str, path: str) -> list[Finding]:
        """Turn the model's JSON reply into Finding objects, tolerantly.

        Small models sometimes wrap JSON in fences or add stray text, so we grab
        the first {...} block instead of trusting the whole string.
        """
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return []
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for item in data.get("findings", []):
            try:
                findings.append(
                    Finding(
                        vuln_class=str(item["vuln_class"]),
                        file=path,
                        line=int(item["line"]),
                        severity=str(item.get("severity", "unknown")),
                        description=str(item.get("description", "")),
                        confidence=float(item.get("confidence", 0.0)),
                    )
                )
            except (KeyError, ValueError, TypeError):
                # Skip a malformed entry rather than crashing the whole run.
                continue
        return findings