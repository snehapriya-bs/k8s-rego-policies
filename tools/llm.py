"""
tools/llm.py

The only file in this project that talks to Vertex AI. Kept separate from
regoforge_agent.py so the agent's parsing/validation/retry logic (Step 5c
onward) can be tested with a stub, without needing GCP credentials.
"""

from __future__ import annotations

import os

from google import genai
from google.genai import types

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT")
LOCATION = os.environ.get("VERTEX_LOCATION", "us-central1")
MODEL = os.environ.get("REGOFORGE_MODEL", "gemini-2.5-flash")

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
    return _client


def gemini_call(system: str, user: str, max_output_tokens: int = 4096) -> str:
    """Single request/response call. system is the system instruction,
    user is the prompt. Returns the model's text output, stripped."""
    response = _get_client().models.generate_content(
        model=MODEL,
        contents=user,
        config=types.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=max_output_tokens,
            temperature=0.1,  # deterministic-leaning, this is code generation not creative writing
        ),
    )
    return response.text.strip()
