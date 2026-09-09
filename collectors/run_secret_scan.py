"""Scan a Git repository's history for secret canaries.

The finding itself (a secret of some kind exists in commit X, file Y) is
observed. Whether that secret reaches any service is a separate question,
answered by core.derive.derive_repo_service_access against the repository's
remotes and the services the active layer actually saw open. When the evidence
does not support a link, this collector emits the credential node with no
outgoing edge rather than guessing a target.
"""
import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.derive import derive_repo_service_access

#: Recognised canary shapes and the secret kind each implies. Kinds drive the
#: reachability rule, so a new pattern must also appear in SECRET_KIND_TARGETS.
SECRET_PATTERNS = [
    ("synthetic-aws-key", re.compile(r"AKIAEXAMPLE[0-9A-Z]{9}")),
    # Gitea's own prefixed format, used by some versions.
    ("gitea-pat", re.compile(r"gitea_pat_[0-9a-zA-Z]{32,}")),
    # Gitea 1.22 issues unprefixed 40-character hexadecimal tokens, which are
    # indistinguishable from a commit hash in isolation. Matching bare hex would
    # make this a false-positive generator, so the pattern requires a Gitea
    # keyword adjacent to the value -- the keyword-proximity approach used by
    # production secret scanners. The assignment name supplies the context; the
    # value itself is never recorded.
    ("gitea-token", re.compile(
        r"(?i)\bgitea[_a-z0-9]*(?:token|pat|key|secret)\b\s*[=:]\s*[\"']?[0-9a-f]{40}[\"']?")),
]

SCANNED_FILES = ("config.py", "settings.py", ".env")


def repository_remotes(repo_path):
    """Return the repository's configured remote URLs, or [] if it has none."""
    result = subprocess.run(["git", "-C", repo_path, "remote", "-v"],
                            text=True, capture_output=True)
    if result.returncode != 0:
        return []
    remotes = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] not in remotes:
            remotes.append(parts[1])
    return remotes


def scan_git_history(repo_path):
    """Scan every committed revision of the watched files for canary patterns."""
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        raise ValueError(f"Not a Git repository: {repo_path}")
    result = subprocess.run(
        ["git", "-C", repo_path, "log", "--all", "--format=%H"],
        check=True, text=True, capture_output=True)
    findings = []
    for commit in dict.fromkeys(result.stdout.splitlines()):
        for filename in SCANNED_FILES:
            blob = subprocess.run(
                ["git", "-C", repo_path, "show", f"{commit}:{filename}"],
                text=True, capture_output=True)
            if blob.returncode != 0:
                continue
            for kind, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(blob.stdout):
                    findings.append({"commit": commit, "kind": kind,
                                     "match": match.group(0), "file": filename})
    unique = {(item["commit"], item["match"], item["file"]): item for item in findings}
    return list(unique.values())


def load_observed_services(active_jsonl):
    """Read the Service records the active layer wrote, for the reachability rule."""
    if not active_jsonl or not os.path.exists(active_jsonl):
        return []
    services = []
    with open(active_jsonl, encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            record = json.loads(line)
            attrs = record["attrs"]
            if attrs.get("type") == "Service":
                services.append({"id": record["id"], "port": attrs.get("port"),
                                 "product": attrs.get("product"),
                                 # The service's self-description, when the
                                 # active layer captured one. The reachability
                                 # rule treats it as product evidence alongside
                                 # the version probe's own finding.
                                 "http_title": attrs.get("http_title", ""),
                                 "service": attrs.get("service"),
                                 "ip": attrs.get("ip") or _ip_from_service_id(record["id"])})
    return services


def _ip_from_service_id(service_id):
    parts = service_id.split("-")
    return parts[1] if len(parts) >= 3 else ""


def generate_jsonl(repo_path, output_jsonl, observed_services):
    findings = scan_git_history(repo_path)
    remotes = repository_remotes(repo_path)
    records = []
    for index, finding in enumerate(findings):
        edges = derive_repo_service_access(
            secret_kind=finding["kind"], remotes=remotes,
            observed_services=observed_services)
        records.append({
            "id": f"cred-git-{index + 1}",
            "attrs": {"type": "Credential", "secret_kind": finding["kind"],
                      "severity": 0.9, "source": "git-history",
                      "commit": finding["commit"], "file": finding["file"],
                      "repo_remotes": remotes, "origin": "identity"},
            "edges": edges,
        })
    with open(output_jsonl, "w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record) + "\n")
    linked = sum(1 for record in records if record["edges"])
    return output_jsonl, len(records), linked


def main():
    parser = argparse.ArgumentParser(description="Scan the synthetic Git repository history.")
    parser.add_argument("repo_path")
    parser.add_argument("--active-jsonl", default=None,
                        help="Active-layer JSONL, used to check which services are open")
    parser.add_argument("--out-dir", default=os.path.join(os.path.dirname(__file__), "..", "out"))
    args = parser.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    active_jsonl = args.active_jsonl or os.path.join(args.out_dir, "real_active.jsonl")
    services = load_observed_services(active_jsonl)
    output, count, linked = generate_jsonl(
        os.path.abspath(args.repo_path),
        os.path.join(args.out_dir, "real_secret.jsonl"), services)
    print(f"[+] Secret scan complete. Wrote {count} findings to {output}")
    print(f"    {linked} of {count} have an evidence-derived service link "
          f"({count - linked} declined for lack of evidence)")


if __name__ == "__main__":
    main()
