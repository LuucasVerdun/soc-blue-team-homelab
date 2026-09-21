#!/usr/bin/env python3
"""
Case 16 - Git update helper
Safely stages, commits, and optionally pushes the current repository changes.

Usage examples:
  python3 update_case16_git.py
  python3 update_case16_git.py --repo /path/to/soc-blue-team-homelab
  python3 update_case16_git.py --repo . --push
  python3 update_case16_git.py --repo . --message "Add Case 16 identity escalation investigation" --push

Notes:
- Does NOT store or request GitHub passwords/tokens.
- Does NOT use force-push.
- Shows the files that will be staged before committing.
- By default stages all current changes in the repository after confirmation.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_COMMIT = (
    "Add Case 16 Windows identity abuse and local administrator escalation investigation"
)


def run(cmd: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    print(f"\n$ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=str(cwd), text=True, check=check)


def capture(cmd: list[str], cwd: Path) -> str:
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout.strip()


def confirm(prompt: str) -> bool:
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in {"y", "yes", "s", "sim"}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stage, commit, and optionally push Case 16 repository updates."
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Path to the Git repository. Default: current directory.",
    )
    parser.add_argument(
        "--message",
        default=DEFAULT_COMMIT,
        help="Git commit message.",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Push after a successful commit.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive confirmations.",
    )
    args = parser.parse_args()

    repo = Path(args.repo).expanduser().resolve()

    if shutil.which("git") is None:
        print("ERROR: git was not found in PATH.", file=sys.stderr)
        return 1

    if not repo.exists():
        print(f"ERROR: repository path does not exist: {repo}", file=sys.stderr)
        return 1

    try:
        git_root = Path(capture(["git", "rev-parse", "--show-toplevel"], repo))
    except subprocess.CalledProcessError:
        print(f"ERROR: {repo} is not inside a Git repository.", file=sys.stderr)
        return 1

    print(f"Repository: {git_root}")

    branch = capture(["git", "branch", "--show-current"], git_root)
    print(f"Branch: {branch or '(detached HEAD)'}")

    if not branch:
        print("ERROR: detached HEAD. Aborting to avoid an accidental commit.")
        return 1

    remote = ""
    try:
        remote = capture(["git", "remote", "get-url", "origin"], git_root)
    except subprocess.CalledProcessError:
        pass

    if remote:
        print(f"Origin: {remote}")
    else:
        print("WARNING: no 'origin' remote is configured.")

    print("\nCurrent repository status:")
    run(["git", "status", "--short"], git_root)

    changes = capture(["git", "status", "--porcelain"], git_root)
    if not changes:
        print("\nNothing to commit. Working tree is clean.")
        return 0

    print("\nFiles/changes detected:")
    print(changes)

    if not args.yes and not confirm("\nStage ALL changes shown above?"):
        print("Cancelled before staging.")
        return 0

    run(["git", "add", "-A"], git_root)

    print("\nStaged changes:")
    run(["git", "diff", "--cached", "--stat"], git_root)

    staged = capture(["git", "diff", "--cached", "--name-status"], git_root)
    print("\nStaged file list:")
    print(staged if staged else "(none)")

    if not staged:
        print("\nNothing is staged. Exiting.")
        return 0

    if not args.yes and not confirm(f'\nCreate commit with message:\n"{args.message}"?'):
        print("Cancelled before commit. Changes remain staged.")
        return 0

    run(["git", "commit", "-m", args.message], git_root)

    print("\nLatest commit:")
    run(["git", "--no-pager", "log", "-1", "--oneline"], git_root)

    do_push = args.push
    if not args.push and not args.yes:
        do_push = confirm("\nPush this commit to origin?")

    if do_push:
        if not remote:
            print("ERROR: cannot push because 'origin' is not configured.")
            return 1

        run(["git", "push", "origin", branch], git_root)

        print("\nRemote update completed.")
        run(["git", "status", "--short"], git_root)
    else:
        print("\nCommit created locally. Push was not requested.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

