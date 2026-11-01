"""Write an evidence package: raw artifact results, the merged timeline, and a SHA-256 manifest.

    <out>/<incident_id>/
        raw/<artifact>.jsonl       what the endpoint returned, unmodified
        timeline.csv, timeline.jsonl
        manifest.json              files with sha256 and size, sources, highlights, who approved
        manifest.json.sha256       hash of the manifest itself

Files are written to a temporary directory and renamed into place, so a reader never sees half a package.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_package(out_dir: Path, incident_id: str, files: dict[str, str], manifest: dict[str, Any],
                  now: datetime | None = None) -> Path:
    """``files`` maps relative names (``raw/x.jsonl``) to text content. Returns the package directory."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    final = out_dir / incident_id
    tmp = Path(tempfile.mkdtemp(prefix=f".{incident_id}.", dir=out_dir))
    try:
        entries = []
        for rel, text in sorted(files.items()):
            parts = [SAFE_NAME.sub("_", p) for p in rel.split("/") if p not in ("", ".", "..")]
            dest = tmp.joinpath(*parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
            entries.append({"name": "/".join(parts), "sha256": sha256_file(dest), "bytes": dest.stat().st_size})
        doc = {**manifest, "incident_id": incident_id, "files": entries,
               "created": (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace(
                   "+00:00", "Z")}
        mpath = tmp / "manifest.json"
        mpath.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (tmp / "manifest.json.sha256").write_text(f"{sha256_file(mpath)}  manifest.json\n", encoding="utf-8")
        if final.exists():
            # A re-collection keeps the earlier package next to the new one instead of overwriting evidence.
            os.replace(final, out_dir / f"{incident_id}.prev-{int(final.stat().st_mtime)}")
        os.replace(tmp, final)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return final


def verify_package(path: Path) -> list[str]:
    """Recompute every hash. Returns a list of problems (empty means intact)."""
    path = Path(path)
    problems = []
    mpath = path / "manifest.json"
    side = (path / "manifest.json.sha256").read_text(encoding="utf-8").split()[0]
    if sha256_file(mpath) != side:
        problems.append("manifest.json does not match manifest.json.sha256")
    doc = json.loads(mpath.read_text(encoding="utf-8"))
    for f in doc.get("files", []):
        p = path / f["name"]
        if not p.is_file():
            problems.append(f"{f['name']}: missing")
        elif sha256_file(p) != f["sha256"]:
            problems.append(f"{f['name']}: hash mismatch")
    return problems
