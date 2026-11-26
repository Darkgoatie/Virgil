#!/usr/bin/env python3
"""Read-only, non-blocking GitHub update check for the virgil skill."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

REPO = "Darkgoatie/Virgil"
BRANCH = "main"
COMMIT_API_URL = f"https://api.github.com/repos/{REPO}/commits/{BRANCH}"
VERSION_RAW_URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/skills/virgil/VERSION"
TIMEOUT_SEC = 4
USER_AGENT = "virgil-skill-update-check"


def read_local_version(skill_dir: Path) -> str:
    ver_file = skill_dir / "VERSION"
    try:
        text = ver_file.read_text(encoding="utf-8").strip()
        return text or "unknown"
    except OSError:
        return "unknown"


def read_local_commit(skill_dir: Path) -> str:
    marker = skill_dir / ".installed-commit"
    try:
        sha = marker.read_text(encoding="utf-8").strip()
        if sha:
            return sha
    except OSError:
        pass
    try:
        res = subprocess.run(
            ["git", "-C", str(skill_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def fetch_text(url: str, accept: str = "text/plain") -> str:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": accept,
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:
        return resp.read().decode("utf-8", errors="replace")


def is_local_ahead(skill_dir: Path, remote_sha: str) -> bool:
    try:
        res = subprocess.run(
            ["git", "-C", str(skill_dir), "merge-base", "--is-ancestor", remote_sha, "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def check_remote() -> tuple[str, str, str]:
    raw_commit = fetch_text(COMMIT_API_URL, accept="application/vnd.github+json")
    data = json.loads(raw_commit)
    remote_sha = str(data.get("sha", "")).strip()
    if not remote_sha:
        raise ValueError("Missing commit sha in GitHub response")

    remote_ver = "unknown"
    try:
        ver_text = fetch_text(VERSION_RAW_URL).strip()
        if ver_text:
            remote_ver = ver_text
    except (OSError, urllib.error.URLError, ValueError):
        pass

    return remote_sha, remote_ver, ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Darkgoatie/Virgil for virgil skill updates.")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    skill_dir = Path(__file__).resolve().parent.parent
    local_ver = read_local_version(skill_dir)
    local_sha = read_local_commit(skill_dir)

    remote_sha = ""
    remote_ver = "unknown"
    status = "skipped"
    message = ""

    try:
        remote_sha, remote_ver, _ = check_remote()
        short_remote = remote_sha[:7]
        if local_sha:
            short_local = local_sha[:7]
            if local_sha == remote_sha:
                status = "up_to_date"
                message = f"[UP TO DATE] virgil v{local_ver} ({short_local}) matches {REPO}@{BRANCH}."
            elif is_local_ahead(skill_dir, remote_sha):
                status = "ahead"
                message = f"[AHEAD] virgil local=v{local_ver} ({short_local}) is ahead of {REPO}@{BRANCH} ({short_remote})."
            else:
                status = "update_available"
                message = (
                    f"[UPDATE AVAILABLE] virgil local=v{local_ver} ({short_local}) "
                    f"vs remote=v{remote_ver} ({short_remote}). "
                    "Update from the Virgil clone with: git pull && ./install.sh (or .\\install.ps1)"
                )
        elif remote_ver != "unknown" and local_ver != remote_ver:
            status = "update_available"
            message = (
                f"[UPDATE AVAILABLE] virgil local=v{local_ver} vs remote=v{remote_ver} ({short_remote}). "
                "Update from the Virgil clone with: git pull && ./install.sh (or .\\install.ps1)"
            )
        elif remote_ver != "unknown":
            status = "up_to_date"
            message = f"[UP TO DATE] virgil v{local_ver} matches {REPO}@{BRANCH} ({short_remote})."
        else:
            status = "skipped"
            message = "[UPDATE CHECK SKIPPED] Local commit unknown and remote VERSION unavailable."
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError) as exc:
        status = "skipped"
        message = f"[UPDATE CHECK SKIPPED] Could not reach GitHub ({type(exc).__name__}). Continuing offline."

    if args.format == "json":
        payload = {
            "status": status,
            "repo": REPO,
            "branch": BRANCH,
            "local_version": local_ver,
            "remote_version": remote_ver,
            "local_commit": local_sha or None,
            "remote_commit": remote_sha or None,
            "message": message,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(message)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
