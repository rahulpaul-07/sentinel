"""
sentinel/scanner.py
-------------------
The Orchestrator: coordinates the whole pipeline (hunt -> validate -> patch) and
returns a structured ScanReport.

Design choices worth defending:
  * scan() is PURE: it analyzes and returns data. It never prints, asks for input,
    or writes files -- so it's easy to test and reuse (CLI, web UI, or CI can all
    call it). Human-in-the-loop and file-writing live in the CLI layer instead.
  * We patch each FILE once, not each finding. Several findings often share a file,
    so we group confirmed findings by file and generate a single fix per file.
  * A budget (max_findings) caps how much work we do, so a huge repo can't run away
    with time and tokens.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.llm import LLMClient
from sentinel.tools import Tools
from sentinel.hunter import Hunter, Finding
from sentinel.sandbox import Sandbox
from sentinel.validator import Validator
from sentinel.patcher import Patcher, Patch


@dataclass
class ScannedFinding:
    finding: Finding
    confirmed: bool


@dataclass
class ScanReport:
    target: str
    scanned: list[ScannedFinding] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)

    @property
    def confirmed(self) -> list[ScannedFinding]:
        return [s for s in self.scanned if s.confirmed]

    def summary(self) -> str:
        return (
            f"Target: {self.target}\n"
            f"  Candidate findings:   {len(self.scanned)}\n"
            f"  Confirmed by exploit: {len(self.confirmed)}\n"
            f"  Files with fixes:     {len(self.patches)}"
        )


class Scanner:
    def __init__(self, llm: LLMClient, target: str, max_findings: int = 20) -> None:
        self.llm = llm
        self.target = target
        self.max_findings = max_findings
        self.tools = Tools(target)
        self.hunter = Hunter(llm, self.tools)
        self.validator = Validator(llm, Sandbox())
        self.patcher = Patcher(llm)

    def scan(self, validate: bool = True, patch: bool = True) -> ScanReport:
        report = ScanReport(target=self.target)

        findings = self.hunter.hunt()[: self.max_findings]

        for finding in findings:
            confirmed = False
            if validate:
                numbered = self.tools.read_file(finding.file)
                confirmed = self.validator.validate(finding, numbered).confirmed
            report.scanned.append(ScannedFinding(finding=finding, confirmed=confirmed))

        if patch:
            report.patches = self._patch_confirmed(report)

        return report

    def _patch_confirmed(self, report: ScanReport) -> list[Patch]:
        # Group confirmed findings by file so we patch each file only once.
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for s in report.confirmed:
            by_file[s.finding.file].append(s.finding)

        patches: list[Patch] = []
        for file, findings in by_file.items():
            raw = (Path(self.target) / file).read_text(encoding="utf-8", errors="replace")
            # The patcher rewrites the whole file, fixing every issue in it; we pass
            # the first finding as the headline reason.
            patches.append(self.patcher.propose(findings[0], raw))
        return patches