"""
sentinel/evaluation.py
----------------------
The evaluation harness: measures how good Sentinel actually is, against labeled
ground truth. This turns "it finds bugs" into "it detects at X% recall with a Y%
false-positive rate across N targets" -- numbers you can defend in an interview.

Definitions:
  True Positive  (TP): a CONFIRMED finding that matches a known real vulnerability.
  False Positive (FP): a CONFIRMED finding that matches no known vulnerability.
  False Negative (FN): a known vulnerability Sentinel did NOT confirm.

  Precision = TP / (TP + FP)   -> of what we reported, how much was real?
  Recall    = TP / (TP + FN)   -> of what was real, how much did we catch?
  F1        = harmonic mean of precision and recall.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sentinel.llm import LLMClient
from sentinel.hunter import Finding
from sentinel.scanner import Scanner


LINE_TOLERANCE = 5  # a finding within +/- 5 lines of the labeled line still counts


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def __add__(self, other: "Metrics") -> "Metrics":
        return Metrics(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)


def _normalize(name: str) -> str:
    return name.strip().lower()


def _matches(finding: Finding, truth: dict) -> bool:
    return (
        finding.file == truth["file"]
        and _normalize(finding.vuln_class) == _normalize(truth["vuln_class"])
        and abs(finding.line - truth["line"]) <= LINE_TOLERANCE
    )


def evaluate_target(llm: LLMClient, target: str) -> Metrics:
    truths = json.loads(
        (Path(target) / "ground_truth.json").read_text(encoding="utf-8")
    )["vulnerabilities"]

    scanner = Scanner(llm, target)
    report = scanner.scan(patch=False)          # metrics only need confirmed findings
    confirmed = [s.finding for s in report.confirmed]

    matched: set[int] = set()
    tp = 0
    for finding in confirmed:
        idx = next(
            (i for i, t in enumerate(truths) if i not in matched and _matches(finding, t)),
            None,
        )
        if idx is not None:
            tp += 1
            matched.add(idx)

    fp = len(confirmed) - tp
    fn = len(truths) - len(matched)
    return Metrics(tp=tp, fp=fp, fn=fn)