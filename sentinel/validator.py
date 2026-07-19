"""
sentinel/validator.py
---------------------
The Validator: turns a Finding from a CLAIM into PROOF -- or rejects it.

For each finding it:
  1. asks the LLM to write a self-contained proof-of-concept (PoC) that prints a
     unique marker (SENTINEL_PWNED) only if the vulnerability is real,
  2. runs that PoC in the locked-down sandbox,
  3. if it fails, feeds the failure BACK to the model and lets it try again
     (self-correction) -- up to max_attempts times,
  4. confirms the finding only if some attempt prints the marker.

The self-correction loop is a core agentic pattern: the agent observes the result
of its action and, if it failed, uses that feedback to improve the next attempt.
This recovers true positives a single shot would miss, while still rejecting any
claim that can never be demonstrated (keeping false positives near zero).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from sentinel.llm import LLMClient
from sentinel.sandbox import Sandbox
from sentinel.hunter import Finding

MARKER = "SENTINEL_PWNED"

SYSTEM_PROMPT = (
    "You are an exploit developer writing a minimal proof-of-concept to demonstrate "
    "a specific vulnerability. You output ONLY a runnable Python script -- no prose, "
    "no markdown."
)

POC_PROMPT = """A security scan reported this potential vulnerability:

  Class:       {vuln_class}
  File/line:   {file}:{line}
  Description: {description}

Here is the relevant source code (for CONTEXT ONLY -- do not import from it):
--- BEGIN CODE ---
{code}
--- END CODE ---

Write a SHORT, COMPLETELY SELF-CONTAINED Python 3 script that proves this
vulnerability class is exploitable.

STRICT RULES:
  - Do NOT import Flask/Django or reference the app above. Recreate the vulnerable
    pattern yourself in plain Python.
  - Set up everything the script needs first (create any files, data, or tables).
  - Feed the vulnerable code a malicious, attacker-controlled input.
  - Print this EXACT marker, and ONLY if the exploit genuinely succeeds: {marker}
  - Use ONLY the Python standard library. No network, no pip installs.

Output ONLY the Python code, nothing else.
"""

FIX_PROMPT = """Your previous proof-of-concept did NOT print the marker {marker}.
Here is the script and what happened when it ran.

Previous PoC:
--- BEGIN POC ---
{poc}
--- END POC ---

Output when it ran:
--- BEGIN OUTPUT ---
{output}
--- END OUTPUT ---

Fix the script so it correctly demonstrates the {vuln_class} vulnerability and
prints {marker} on success. Keep it self-contained, standard-library only, and set
up anything it needs. Output ONLY the corrected Python code.
"""


@dataclass
class ValidationResult:
    finding: Finding
    confirmed: bool
    poc_code: str
    output: str
    attempts: int


class Validator:
    def __init__(self, llm: LLMClient, sandbox: Sandbox, max_attempts: int = 3) -> None:
        self.llm = llm
        self.sandbox = sandbox
        self.max_attempts = max_attempts

    def validate(self, finding: Finding, code: str) -> ValidationResult:
        poc = self._initial_poc(finding, code)
        output = ""

        for attempt in range(1, self.max_attempts + 1):
            result = self.sandbox.run(self._as_command(poc))
            output = (result.stdout + result.stderr).strip()

            if MARKER in result.stdout:
                return ValidationResult(finding, True, poc, output, attempt)

            # Failed: if attempts remain, let the model self-correct from the output.
            if attempt < self.max_attempts:
                poc = self._fix_poc(finding, code, poc, output)

        return ValidationResult(finding, False, poc, output, self.max_attempts)

    def _initial_poc(self, finding: Finding, code: str) -> str:
        prompt = POC_PROMPT.format(
            vuln_class=finding.vuln_class,
            file=finding.file,
            line=finding.line,
            description=finding.description,
            code=code,
            marker=MARKER,
        )
        return self._clean(self.llm.complete(prompt=prompt, system=SYSTEM_PROMPT).text)

    def _fix_poc(self, finding: Finding, code: str, poc: str, output: str) -> str:
        prompt = FIX_PROMPT.format(
            marker=MARKER, poc=poc, output=output, vuln_class=finding.vuln_class
        )
        return self._clean(self.llm.complete(prompt=prompt, system=SYSTEM_PROMPT).text)

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

    def _as_command(self, poc_code: str) -> str:
        """Turn PoC source into a shell command that runs it inside the container."""
        encoded = base64.b64encode(poc_code.encode("utf-8")).decode("ascii")
        return f"echo {encoded} | base64 -d | python3"