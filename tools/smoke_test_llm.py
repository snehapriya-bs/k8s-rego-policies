"""
tools/smoke_test_llm.py

Confirms the CI runner can actually reach Vertex AI and get a response
from Gemini — nothing more. Not part of the RegoForge pipeline itself;
this exists purely to catch auth/config problems early and cheaply,
before Step 5c-5e wire up the real generation logic on top of tools/llm.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from llm import gemini_call

try:
    response = gemini_call("You are terse.", "Say OK if you can hear me.")
    print(f"Gemini responded: {response!r}")
    print("Vertex AI connection: OK")
    sys.exit(0)
except Exception as e:
    print(f"Vertex AI connection FAILED: {type(e).__name__}: {e}")
    sys.exit(1)
