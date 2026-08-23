#!/usr/bin/env python3
"""Fail when CI checks out a different Product revision than Runtime conformance."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    arguments = sys.argv[1:]
    if len(arguments) not in (0, 2):
        fail("usage: verify-product-source-pinning.py [PRODUCT_SOURCE_JSON CI_WORKFLOW_YAML]")
    source_path = Path(arguments[0]) if arguments else root / "conformance" / "product-source.json"
    workflow_path = Path(arguments[1]) if arguments else root / ".github" / "workflows" / "ci.yml"

    source = json.loads(source_path.read_text(encoding="utf-8"))
    revision = source.get("revision")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        fail("conformance/product-source.json has an invalid Product revision")

    workflow = workflow_path.read_text(encoding="utf-8")
    matches = re.findall(
        r"repository:\s*juju-w/safa\s*\n\s*ref:\s*([0-9a-f]{40})\s*$",
        workflow,
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        fail("CI must contain exactly one exact juju-w/safa checkout revision")
    if matches[0] != revision:
        fail(
            "CI Product checkout does not match conformance/product-source.json: "
            f"{matches[0]} != {revision}"
        )

    print(f"validated CI Product checkout at {revision}")


if __name__ == "__main__":
    main()
