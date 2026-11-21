"""Stage the reviewed publisher schema set from exact public revisions."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


PUBLISHERS = {
    "source-controller", "task-manager", "team-registry", "flow-registry",
    "model-registry", "env-registry", "executor-registry", "admin-panel",
}
PATH = re.compile(r"svc/([a-z-]+)/schemas/([a-z0-9_.-]+\.schema\.json)")


def main(root):
    if not root.is_absolute() or not root.is_dir() or any(root.iterdir()):
        raise SystemExit("Pass an absolute, empty fixture directory.")

    here = Path(__file__).resolve().parent
    declarations = json.loads((here / "gitea-declarations.json").read_bytes())["schemas"]
    digests = {}
    for line in (here / "schema.sha256").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        if relative in digests:
            raise SystemExit(f"Duplicate fixture manifest entry: {relative}")
        digests[relative] = digest
    if not declarations or declarations.keys() != digests.keys():
        raise SystemExit("The audited fixture manifest and schema declarations differ.")

    pins = {publisher: os.environ.get(publisher.upper().replace("-", "_") + "_SHA", "")
            for publisher in PUBLISHERS}
    if any(not re.fullmatch(r"[0-9a-f]{40}", pin) for pin in pins.values()):
        raise SystemExit("Each publisher needs a full lowercase hexadecimal commit SHA.")

    for relative, digest in sorted(digests.items()):
        match = PATH.fullmatch(relative)
        if not match or match[1] not in pins or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SystemExit(f"Invalid fixture manifest entry: {relative}")
        publisher, filename = match.groups()
        owners = declarations[relative]
        if not owners or owners[0] != publisher or "audit" not in owners[1:]:
            raise SystemExit(f"Missing direct Audit declaration: {relative}")

        url = f"https://raw.githubusercontent.com/pandops/flowai-{publisher}/{pins[publisher]}/schemas/{filename}"
        response = subprocess.run(
            ["curl", "-qfsS", "--proto", "=https", "--max-time", "30",
             "--write-out", "%{http_code}", url],
            stdout=subprocess.PIPE, check=True,
        ).stdout
        body, status = response[:-3], response[-3:]
        if status != b"200" or hashlib.sha256(body).hexdigest() != digest:
            raise SystemExit(f"Unexpected status or schema bytes at {url}")
        if not isinstance(json.loads(body), dict):
            raise SystemExit(f"Expected a JSON Schema object at {url}")

        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
        print(f"{url} {digest} {relative}", flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
