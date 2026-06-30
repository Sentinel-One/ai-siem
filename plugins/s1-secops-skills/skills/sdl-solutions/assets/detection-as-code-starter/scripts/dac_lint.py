#!/usr/bin/env python3
"""Local lint for Detection-as-Code rule files.

A thin wrapper over dac_sync.py's validation + conversion. It never touches the
network, so it is safe as a pre-commit hook or a fast local check before opening
a pull request.

    python3 scripts/dac_lint.py                 # lint everything under detections/
    python3 scripts/dac_lint.py detections/cloud  # lint one folder
    python3 scripts/dac_lint.py path/to/rule.toml # lint one file

Exit code is 0 when every rule converts cleanly, 1 otherwise. CI calls
dac_sync.py --lint directly; this wrapper is for humans.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dac_sync import build_envelope, discover_rule_files, load_rule_file, RuleError  # noqa: E402


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    paths = argv or ["detections"]
    files = discover_rule_files(paths)
    if not files:
        print("No rule files found under:", ", ".join(paths))
        return 0
    ok, bad = 0, 0
    for f in files:
        try:
            build_envelope(load_rule_file(f), f, None)
            print(f"  OK    {f}")
            ok += 1
        except RuleError as e:
            print(f"  FAIL  {e}", file=sys.stderr)
            bad += 1
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL  {f}: {e}", file=sys.stderr)
            bad += 1
    print(f"\n{ok} OK, {bad} failed, {len(files)} total.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
