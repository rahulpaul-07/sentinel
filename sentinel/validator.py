"""
sentinel/validator.py
---------------------
The Validator: turns a Finding from a CLAIM into PROOF -- or rejects it.

For each finding it:
  1. asks the LLM to write a small, self-contained proof-of-concept (PoC) script
     that prints a unique marker (SENTINEL_PWNED) IF the vulnerability is real,
  2. runs that PoC inside the locked-down sandbox,
  3. confirms the finding only if the marker actually appears in the output.

This is what cuts false positives: an LLM can *claim* anything, but a claim it
cannot demonstrate by running code gets downgraded to 'unconfirmed'.

(v1 proves the vulnerability CLASS is exploitable by reproducing it in isolation.
A future v2 would run the actual target app and exploit it over HTTP.)
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
  - Set up everything the script needs first. For a SQL bug, create AND populate an
    in-memory sqlite table before querying it.
  - Feed the vulnerable code a malicious, attacker-controlled input.
  - Print this EXACT marker, and ONLY if the exploit genuinely succeeds: {marker}
  - Use ONLY the Python standard library. No network, no pip installs.

Output ONLY the Python code, nothing else.
"""


@dataclass
class ValidationResult:
    finding: Finding
    confirmed: bool
    poc_code: str
    output: str


class Validator:
    def __init__(self, llm: LLMClient, sandbox: Sandbox) -> None:
        self.llm = llm
        self.sandbox = sandbox

    def validate(self, finding: Finding, code: str) -> ValidationResult:
        poc = self._generate_poc(finding, code)
        result = self.sandbox.run(self._as_command(poc))
        confirmed = MARKER in result.stdout
        return ValidationResult(
            finding=finding,
            confirmed=confirmed,
            poc_code=poc,
            output=(result.stdout + result.stderr).strip(),
        )

    def _generate_poc(self, finding: Finding, code: str) -> str:
        prompt = POC_PROMPT.format(
            vuln_class=finding.vuln_class,
            file=finding.file,
            line=finding.line,
            description=finding.description,
            code=code,
            marker=MARKER,
        )
        response = self.llm.complete(prompt=prompt, system=SYSTEM_PROMPT)
        return self._clean(response.text)

    def _clean(self, text: str) -> str:
        """Strip markdown code fences if the model added them despite instructions."""
        text = text.strip()
        fence = "`" * 3  # three backticks, built without writing them literally
        if text.startswith(fence):
            lines = text.splitlines()
            lines = lines[1:]                      # drop the opening fence line
            if lines and lines[-1].strip().startswith(fence):
                lines = lines[:-1]                 # drop the closing fence line
            text = "\n".join(lines)
        return text

    def _as_command(self, poc_code: str) -> str:
        """Turn PoC source into a shell command that runs it inside the container.

        We base64-encode the script so quotes and newlines can't break the shell
        line, then decode and run it with python3 inside the sandbox.
        """
        encoded = base64.b64encode(poc_code.encode("utf-8")).decode("ascii")
        return f"echo {encoded} | base64 -d | python3"