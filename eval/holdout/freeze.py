"""Freeze the holdout protocol manifest -> lock.json (sha256).

Run deliberately after an intentional protocol change; every protocol run
aborts on lock mismatch so a holdout can never be silently tuned.

Usage:
    python eval/holdout/freeze.py           # regenerate lock.json for manifest.yaml
    python eval/holdout/freeze.py --check   # verify current lock matches (exit 0/1)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from eval.holdout.runner import DEFAULT_LOCK, DEFAULT_MANIFEST, load_protocol


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify lock, do not write")
    args = parser.parse_args()

    if args.check:
        try:
            load_protocol()
        except Exception as exc:  # noqa: BLE001 - freeze.py is a human tool
            print(f"FAIL: {exc}")
            sys.exit(1)
        print("OK: manifest matches frozen lock")
        return

    raw = DEFAULT_MANIFEST.read_text(encoding="utf-8")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    DEFAULT_LOCK.write_text(
        json.dumps({"sha256": digest, "manifest": DEFAULT_MANIFEST.name}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(f"frozen {DEFAULT_MANIFEST} -> {DEFAULT_LOCK} ({digest[:12]}…)")
    load_protocol()  # round-trip check


if __name__ == "__main__":
    main()
