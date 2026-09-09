"""Seed a local synthetic Git repository and optionally publish it to Gitea.

The canary is deliberately nonfunctional and must never be replaced with a real credential.
"""
import argparse
import json
import os
import subprocess
import urllib.error
import urllib.request

CANARY = "AKIAEXAMPLE000000000"


def run(command, cwd):
    subprocess.run(command, cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def create_seed_repo(repo_dir):
    os.makedirs(repo_dir, exist_ok=True)
    if os.path.exists(os.path.join(repo_dir, ".git")):
        return repo_dir
    run(["git", "init"], repo_dir)
    run(["git", "config", "user.email", "c.brown@corp-testbed.local"], repo_dir)
    run(["git", "config", "user.name", "Charlie Brown"], repo_dir)
    with open(os.path.join(repo_dir, "README.md"), "w", encoding="utf-8") as output:
        output.write("CorpTest internal tools.\n")
    run(["git", "add", "README.md"], repo_dir)
    run(["git", "commit", "-m", "initial repository"], repo_dir)
    with open(os.path.join(repo_dir, "config.py"), "w", encoding="utf-8") as output:
        output.write(f"AWS_ACCESS_KEY_ID = '{CANARY}'\n")
        output.write("# Synthetic canary only; this credential is invalid.\n")
    run(["git", "add", "config.py"], repo_dir)
    run(["git", "commit", "-m", "add development configuration"], repo_dir)
    return repo_dir


def publish_to_gitea(base_url, token, repo_dir):
    if not token:
        return False
    payload = json.dumps({"name": "internal-tools", "private": True}).encode()
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/v1/user/repos", data=payload,
        headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10):
            pass
    except urllib.error.HTTPError as error:
        if error.code != 409:
            raise
    remote = f"{base_url.rstrip('/')}/c.brown/internal-tools.git"
    subprocess.run(["git", "remote", "remove", "origin"], cwd=repo_dir,
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(["git", "remote", "add", "origin", remote], repo_dir)
    subprocess.run(["git", "push", "--all", "origin"], cwd=repo_dir, check=False)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", default=os.path.join(os.path.dirname(__file__), "gitea-seed", "internal-tools"))
    parser.add_argument("--gitea-url", default="http://127.0.0.1:3000")
    args = parser.parse_args()
    repo_dir = create_seed_repo(os.path.abspath(args.repo_dir))
    published = publish_to_gitea(args.gitea_url, os.environ.get("GITEA_TOKEN"), repo_dir)
    print(json.dumps({"repo_dir": repo_dir, "gitea_published": published, "canary": CANARY}))


if __name__ == "__main__":
    main()
