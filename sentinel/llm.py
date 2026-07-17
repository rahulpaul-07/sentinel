"""
sentinel/llm.py
----------------
The "model layer": the ONLY part of Sentinel that talks directly to an AI model.

Why isolate this in one file?
  - Every other part of Sentinel asks THIS module for AI help. Nothing else ever
    imports a vendor SDK directly.
  - So switching from Claude to GPT to a free local model is a ONE-LINE config
    change here, and the rest of the codebase never notices.
  - This is the "Adapter" pattern (a form of dependency inversion). It's exactly
    the kind of design choice interviewers ask you to justify.

Under the hood we use `litellm`, a library that speaks to 100+ providers through a
single function. We wrap it in our own small class so the rest of our code depends
on OUR clean interface, not on litellm's details.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import litellm
from dotenv import load_dotenv

# Read key=value lines from a local `.env` file into the environment (if the file
# exists). This is how the API key and model name reach the program without being
# hard-coded into the source. Runs once, when this file is first imported.
load_dotenv()


@dataclass
class LLMResponse:
    """A structured result from the model.

    We return a small object instead of a bare string so callers can also see how
    many tokens were used and what the call cost — numbers we'll need later for the
    'cost per finding' metric in the evaluation harness.
    """
    text: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float


class LLMClient:
    """A thin, provider-agnostic wrapper around an AI model.

    The rest of Sentinel only ever uses this class. Swap providers by changing the
    SENTINEL_MODEL value in your .env — no code changes required.
    """

    def __init__(self, model: str | None = None, temperature: float = 0.0) -> None:
        # If no model is passed in, read it from the environment (set in .env).
        # Examples: "claude-sonnet-5", "gpt-4o-mini", "ollama/llama3.2".
        self.model = model or os.getenv("SENTINEL_MODEL")
        if not self.model:
            raise ValueError(
                "No model configured. Set SENTINEL_MODEL in your .env file "
                "(e.g. SENTINEL_MODEL=ollama/llama3.2)."
            )

        # temperature controls randomness: 0.0 = focused and repeatable, which is
        # what we want for security analysis (we want consistency, not creativity).
        self.temperature = temperature

    def complete(self, prompt: str, system: str | None = None) -> LLMResponse:
        """Send one prompt to the model and get a structured response back.

        `system` is an optional 'system prompt': high-level instructions that set
        the model's role, e.g. "You are a meticulous security analyst."
        """
        # Build the message list in the standard chat format all providers accept.
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # The single call litellm routes to whichever provider `self.model` names:
        #   "ollama/..."  -> your local model
        #   "claude-..."  -> Anthropic
        #   "gpt-..."     -> OpenAI
        # Same code path for all of them.
        response = litellm.completion(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
        )

        # Extract the reply text from the (OpenAI-shaped) response object.
        text = response.choices[0].message.content or ""

        # Token counts show how much context we used. getattr guards against a
        # provider that doesn't report usage.
        usage = getattr(response, "usage", None)
        prompt_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
        completion_tokens = getattr(usage, "completion_tokens", 0) if usage else 0

        # litellm can estimate the dollar cost for known hosted models. Local models
        # cost $0. We catch errors so an unknown model name can't crash the program.
        try:
            cost = litellm.completion_cost(completion_response=response)
        except Exception:
            cost = 0.0

        return LLMResponse(
            text=text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost,
        )