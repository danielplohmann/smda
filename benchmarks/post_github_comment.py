#!/usr/bin/env python3
"""Create or update the SMDA performance-gate PR comment."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_MARKER = "<!-- smda-performance-gate -->"


def request_json(method: str, url: str, token: str, data: dict[str, Any] | None = None) -> Any:
    body = None if data is None else json.dumps(data).encode("utf-8")
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read()
    return json.loads(payload.decode("utf-8")) if payload else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--issue-number", required=True)
    parser.add_argument("--body-file", type=Path, required=True)
    parser.add_argument("--marker", default=DEFAULT_MARKER)
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN is unavailable; skipping PR comment")
        return 0

    body = args.body_file.read_text(encoding="utf-8")
    comments_url = f"https://api.github.com/repos/{args.repo}/issues/{args.issue_number}/comments"
    try:
        comments = request_json("GET", comments_url, token)
        existing = next((item for item in comments if args.marker in str(item.get("body", ""))), None)
        if existing:
            request_json("PATCH", existing["url"], token, {"body": body})
            print(f"Updated performance comment {existing['id']}")
        else:
            created = request_json("POST", comments_url, token, {"body": body})
            print(f"Created performance comment {created['id']}")
    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read().decode("utf-8")
        except Exception:
            err_body = "<could not read response body>"
        print(f"HTTPError: {exc.code} {exc.reason}\nResponse: {err_body}", file=sys.stderr)
        if exc.code in {403, 404}:
            print(f"Skipping PR comment because GitHub returned HTTP {exc.code}", file=sys.stderr)
            return 0
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
