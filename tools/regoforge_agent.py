"""
tools/regoforge_agent.py

Step 5c: the deterministic half of the RegoForge agent. No AI here —
just loading policies.json, loading the test manifests, and running the
real `opa` binary to validate a given Rego policy against them. This is
the grounding logic that Step 5d's generate_rego() will be checked
against; building and testing it in isolation first means the retry
loop (5d) has a trustworthy foundation to call.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import yaml

PACKAGE_NAME = "k8s.podsecurity"


def load_policies(json_path: str) -> dict:
    """Reads and does a light structural check on policies.json."""
    with open(json_path) as f:
        spec = json.load(f)
    if "policies" not in spec or not isinstance(spec["policies"], list):
        raise ValueError(f"{json_path} does not match the expected schema (missing 'policies' list)")
    for p in spec["policies"]:
        missing = {"id", "title", "rule", "applies_to", "condition", "action", "rationale"} - set(p.keys())
        if missing:
            raise ValueError(f"Policy {p.get('id', '?')} is missing fields: {missing}")
    return spec


def load_manifests(manifests_dir: str) -> list[dict]:
    """Reads manifests/*.yaml, tagging each pass/fail by filename prefix
    ('pass-*.yaml' expects zero violations, 'fail-*.yaml' expects at
    least one)."""
    manifests = []
    for path in sorted(Path(manifests_dir).glob("*.yaml")):
        name = path.name
        if name.startswith("pass-"):
            expect = "pass"
        elif name.startswith("fail-"):
            expect = "fail"
        else:
            raise ValueError(f"Manifest {name} must start with 'pass-' or 'fail-' to tag its expected outcome")
        with open(path) as f:
            content = yaml.safe_load(f)
        manifests.append({"name": name, "content": content, "expect": expect})
    if not manifests:
        raise ValueError(f"No manifests found in {manifests_dir}")
    return manifests


def validate(rego_code: str, manifests: list[dict], package_name: str = PACKAGE_NAME) -> dict:
    """The grounding step. Never calls an LLM. Writes rego_code + each
    manifest to a temp dir, runs the real opa binary, and compares the
    resulting deny-set against each manifest's expected pass/fail tag."""
    with tempfile.TemporaryDirectory() as tmp:
        policy_path = Path(tmp) / "policy.rego"
        policy_path.write_text(rego_code)

        check = subprocess.run(
            ["opa", "check", str(policy_path)], capture_output=True, text=True, timeout=15
        )
        if check.returncode != 0:
            return {
                "compiled": False,
                "compile_error": check.stderr.strip(),
                "manifests_run": 0,
                "manifests_passed": 0,
                "failures": [],
            }

        failures = []
        passed = 0
        query = f"data.{package_name}.deny"

        for m in manifests:
            input_path = Path(tmp) / f"{m['name']}.json"
            input_path.write_text(json.dumps(m["content"]))

            eval_run = subprocess.run(
                ["opa", "eval", "--data", str(policy_path), "--input", str(input_path), "--format", "json", query],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if eval_run.returncode != 0:
                failures.append({"manifest": m["name"], "error": eval_run.stderr.strip()})
                continue

            try:
                result = json.loads(eval_run.stdout)
                violations = result["result"][0]["expressions"][0]["value"]
            except (KeyError, IndexError, json.JSONDecodeError):
                violations = []

            actual = "pass" if len(violations) == 0 else "fail"
            if actual == m["expect"]:
                passed += 1
            else:
                failures.append({
                    "manifest": m["name"],
                    "expected": m["expect"],
                    "actual": actual,
                    "violations": list(violations),
                })

        return {
            "compiled": True,
            "compile_error": None,
            "manifests_run": len(manifests),
            "manifests_passed": passed,
            "failures": failures,
        }
