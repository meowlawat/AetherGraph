import argparse
import json
import os
import subprocess

NUCLEI_IMAGE = "projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
NUCLEI_VOLUME = "aethergraph-nuclei-templates"
NUCLEI_TEMPLATE_FILES = [
    "http/default-logins/dvwa/dvwa-default-login.yaml",
    "http/exposed-panels/gitea-login.yaml",
    "http/exposures/backups/backup-directory-listing.yaml",
    "http/exposures/configs/git-config.yaml",
    "http/technologies/nginx/nginx-version.yaml",
]


def ensure_templates():
    subprocess.run(["docker", "volume", "create", NUCLEI_VOLUME], check=True,
                   capture_output=True, text=True)
    command = [
        "docker", "run", "--rm", "-v", f"{NUCLEI_VOLUME}:/root/nuclei-templates",
        NUCLEI_IMAGE, "-validate", "-t",
        "/root/nuclei-templates/http/exposed-panels/gitea-login.yaml"
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True,
                   encoding="utf-8", errors="replace", timeout=180)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Nuclei template bootstrap timed out after 180 seconds") from error


def run_nuclei(urls, out_dir):
    """Run a pinned Nuclei image only against explicitly supplied local URLs."""
    ensure_templates()
    output_name = "nuclei.jsonl"
    output_path = os.path.join(out_dir, output_name)
    targets_path = os.path.join(out_dir, "nuclei_targets.txt")
    with open(targets_path, "w", encoding="utf-8") as targets:
        targets.write("\n".join(urls) + "\n")
    command = [
        "docker", "run", "--rm", "-v", f"{os.path.abspath(out_dir)}:/out",
        "-v", f"{NUCLEI_VOLUME}:/root/nuclei-templates",
        NUCLEI_IMAGE, "-l", "/out/nuclei_targets.txt",
        "-t", ",".join(f"/root/nuclei-templates/{path}" for path in NUCLEI_TEMPLATE_FILES),
        "-jsonl", "-silent", "-no-color", "-disable-update-check",
        "-rate-limit", "20", "-concurrency", "5", "-timeout", "5", "-retries", "0",
        "-o", f"/out/{output_name}"
    ]
    try:
        result = subprocess.run(command, text=True, capture_output=True,
                    encoding="utf-8", errors="replace", timeout=120)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Nuclei Docker scan timed out after 120 seconds") from error
    if result.returncode != 0 or not os.path.exists(output_path):
        raise RuntimeError(f"Nuclei Docker scan failed: {result.stderr.strip()}")
    return output_path


def parse_nuclei(path):
    records = []
    with open(path, encoding="utf-8") as findings:
        for line in findings:
            if not line.strip():
                continue
            finding = json.loads(line)
            info = finding.get("info", {})
            severity = {"info": 0.1, "low": 0.3, "medium": 0.5,
                        "high": 0.75, "critical": 0.95}.get(info.get("severity"), 0.3)
            template = finding.get("template-id", "unknown")
            records.append({
                "id": f"nuclei-{template}-{len(records) + 1}",
                "attrs": {
                    "type": "Finding", "class": "web-misconfig", "title": info.get("name", template),
                    "severity": severity, "severity_label": info.get("severity", "unknown"),
                    "template_id": template, "matched_at": finding.get("matched-at"),
                    "origin": "active"
                }, "edges": []
            })
    return records


def write_jsonl(records, output_jsonl):
    with open(output_jsonl, "w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record) + "\n")
    return output_jsonl


def main():
    parser = argparse.ArgumentParser(description="Run restricted Dockerized Nuclei checks.")
    parser.add_argument("urls", nargs="+", help="Local URLs to scan")
    parser.add_argument("--out-dir", default=os.path.join(os.path.dirname(__file__), "..", "out"))
    args = parser.parse_args()
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    raw_path = run_nuclei(args.urls, out_dir)
    output_path = os.path.join(out_dir, "real_nuclei.jsonl")
    records = parse_nuclei(raw_path)
    write_jsonl(records, output_path)
    print(f"[+] Nuclei complete. Wrote {len(records)} findings to {output_path}")


if __name__ == "__main__":
    main()
