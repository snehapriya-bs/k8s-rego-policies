"""
tools/validate_policy.py

CI entrypoint for Step 5c's deterministic functions. Loads
policy/podsecurity.rego (today: a hand-verified baseline; from Step 5d
onward: whatever RegoForge generated and passed its own retry loop) and
checks it against every manifest in manifests/. Exits non-zero if
anything doesn't match its expected pass/fail tag, so this is a real CI
gate, not just a report.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from regoforge_agent import load_manifests, validate

POLICY_PATH = "policy/podsecurity.rego"
MANIFESTS_DIR = "manifests"


def main() -> int:
    if not Path(POLICY_PATH).exists():
        print(f"FAIL: {POLICY_PATH} does not exist")
        return 1

    rego_code = Path(POLICY_PATH).read_text()
    manifests = load_manifests(MANIFESTS_DIR)
    result = validate(rego_code, manifests)

    if not result["compiled"]:
        print(f"FAIL: {POLICY_PATH} does not compile")
        print(result["compile_error"])
        return 1

    print(f"{result['manifests_passed']}/{result['manifests_run']} manifests matched their expected outcome")

    if result["failures"]:
        print("FAILURES:")
        print(json.dumps(result["failures"], indent=2))
        return 1

    print("All manifests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
