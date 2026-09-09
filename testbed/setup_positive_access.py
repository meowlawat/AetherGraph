"""Opt-in setup for the positive ACCESS validation experiment.

Creates an isolated repository containing a REAL Gitea personal access token and
a REAL remote pointing at the running Gitea service, so that the corrected
derivation rule has genuine evidence to work from. Nothing here writes a graph
edge: the rule must still resolve the remote against an independently observed
service and check credential compatibility.

The default testbed is untouched. This script only runs when invoked explicitly.

The token is read from the GITEA_PAC_TOKEN environment variable and is never
printed, logged, or written anywhere except the experiment repository working
tree, which lives under out/ and is not part of the committed source.

Usage:
    set GITEA_PAC_TOKEN=<token issued by the running Gitea>
    python testbed/setup_positive_access.py --gitea-host 10.41.159.81 \
        --repo-dir out/positive_access_live/repo --push
"""
import argparse
import os
import subprocess
import sys


def run(cmd, cwd=None, check=True, redact=None):
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if check and result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        if redact:
            message = message.replace(redact, "***REDACTED***")
        raise RuntimeError(f"command failed: {' '.join(cmd[:3])}...: {message}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitea-host", required=True,
                        help="Address at which Gitea is reachable AND is scanned")
    parser.add_argument("--gitea-port", default="3000")
    parser.add_argument("--user", default="pactest")
    parser.add_argument("--repo-name", default="pac-positive")
    parser.add_argument("--repo-dir", required=True)
    parser.add_argument("--push", action="store_true",
                        help="Push through the remote, proving it is real and usable")
    args = parser.parse_args()

    token = os.environ.get("GITEA_PAC_TOKEN", "").strip()
    if not token:
        print("[-] GITEA_PAC_TOKEN is not set. Refusing to fabricate a token.")
        return 2

    repo_dir = os.path.abspath(args.repo_dir)
    os.makedirs(repo_dir, exist_ok=True)
    remote = (f"http://{args.gitea_host}:{args.gitea_port}/"
              f"{args.user}/{args.repo_name}.git")

    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        run(["git", "init", "-b", "main"], cwd=repo_dir)
    run(["git", "config", "user.email", f"{args.user}@corp-testbed.local"], cwd=repo_dir)
    run(["git", "config", "user.name", "Positive Access Test"], cwd=repo_dir)

    # The credential is committed in the form a developer would leave it: a named
    # assignment. The scanner finds it by its own pattern; nothing tells the
    # scanner which service it belongs to.
    with open(os.path.join(repo_dir, "config.py"), "w", encoding="utf-8") as out:
        out.write("# Deployment configuration for the internal tooling service.\n")
        out.write(f'GITEA_API_TOKEN = "{token}"\n')
    with open(os.path.join(repo_dir, "README.md"), "w", encoding="utf-8") as out:
        out.write("Positive ACCESS validation fixture.\n")

    run(["git", "add", "config.py", "README.md"], cwd=repo_dir)
    status = run(["git", "status", "--porcelain"], cwd=repo_dir, check=False)
    if status.stdout.strip():
        run(["git", "commit", "-m", "add deployment configuration"],
            cwd=repo_dir, redact=token)

    run(["git", "remote", "remove", "origin"], cwd=repo_dir, check=False)
    run(["git", "remote", "add", "origin", remote], cwd=repo_dir)

    pushed = False
    if args.push:
        # Credentials are supplied only in the push URL, never stored in config.
        push_url = (f"http://{args.user}:{token}@{args.gitea_host}:"
                    f"{args.gitea_port}/{args.user}/{args.repo_name}.git")
        result = run(["git", "push", push_url, "HEAD:refs/heads/main"],
                     cwd=repo_dir, check=False, redact=token)
        pushed = result.returncode == 0
        if not pushed:
            print("[-] push failed:",
                  (result.stderr or "").replace(token, "***REDACTED***").strip()[:300])

    print(f"[+] repository   : {repo_dir}")
    print(f"[+] remote       : {remote}")
    print(f"[+] token length : {len(token)} (value withheld)")
    print(f"[+] pushed       : {pushed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
