"""Identity-layer collection.

Harvests email addresses from the target's HTML, checks them against the local
frozen corpus, and emits account relationships only where observed evidence
corroborates that the account exists on a service that was seen open.

The previous revision created an FTP account for every harvested address and
linked it to port 21 unconditionally. In the shipped testbed the FTP container
is provisioned with FTP_USER=test, so that account never existed: the node was a
fabrication that happened to look like a finding. This revision emits the
persona and any corpus match, then defers to core.derive for the account link.
"""
import argparse
import csv
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.derive import derive_account_access
from core.provenance import DERIVED, OBSERVED, edge

EMAIL_PATTERN = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")


def fetch_emails_from_target(url="http://127.0.0.1"):
    """Extract email addresses from HTML comments on the target page."""
    print(f"[*] Harvesting emails from {url}...")
    emails = set()
    try:
        response = urllib.request.urlopen(url, timeout=5)
        html = response.read().decode("utf-8", errors="replace")
        for comment in re.findall(r"<!--(.*?)-->", html, re.DOTALL):
            emails.update(EMAIL_PATTERN.findall(comment))
    except Exception as error:  # network failure must not fabricate results
        print(f"[-] Failed to fetch {url}: {error}")
    return sorted(emails)


def check_breach_corpus(email, corpus_path):
    """Look the address up in the frozen local CSV. Returns the row or None."""
    if not os.path.exists(corpus_path):
        print(f"[-] Corpus not found at {corpus_path}")
        return None
    with open(corpus_path, mode="r", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            if row["email"].lower() == email.lower():
                return row
    return None


def load_json_lines(path):
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as source:
        return [json.loads(line) for line in source if line.strip()]


def load_observed_services(active_jsonl):
    services = []
    for record in load_json_lines(active_jsonl):
        attrs = record["attrs"]
        if attrs.get("type") == "Service":
            parts = record["id"].split("-")
            services.append({"id": record["id"], "port": attrs.get("port"),
                             "product": attrs.get("product"),
                             "service": attrs.get("service"),
                             "ip": attrs.get("ip") or (parts[1] if len(parts) >= 3 else "")})
    return services


def load_corroborations(web_evidence_jsonl):
    """Read username corroborations produced by the web-evidence collector."""
    corroborations = []
    for record in load_json_lines(web_evidence_jsonl):
        attrs = record["attrs"]
        if attrs.get("type") == "Credential" and attrs.get("username"):
            for target in attrs.get("names_services", []):
                corroborations.append({"username": attrs["username"],
                                       "service_id": target,
                                       "source": attrs.get("source", "")})
    return corroborations


def generate_identity_jsonl(emails, corpus_path, output_jsonl,
                            observed_services=(), corroborations=()):
    records = []
    declined = 0
    for email in emails:
        username = email.split("@")[0]
        persona_id = f"persona-{username}"
        persona = {"id": persona_id,
                   "attrs": {"type": "Persona", "email": email, "origin": "identity"},
                   "edges": []}
        records.append(persona)

        breach = check_breach_corpus(email, corpus_path)
        if breach:
            # Observed: the address is literally present in the corpus file.
            records.append({
                "id": f"cred-{username}",
                "attrs": {"type": "Credential", "severity": 0.59,
                          "source": breach["breach_source"], "origin": "identity"},
                "edges": [edge(persona_id, "EXPOSES_CREDENTIAL", 0.90, OBSERVED,
                               justification=f"row for {email} in the frozen corpus")],
            })

        account_nodes, _ = derive_account_access(
            username, list(observed_services), list(corroborations))
        if account_nodes:
            for node in account_nodes:
                persona["edges"].append(
                    edge(node["id"], "OWNS_ACCOUNT", 0.75, DERIVED,
                         justification=(f"account {node['attrs']['username']} corroborated "
                                        f"on an observed service")))
            records.extend(account_nodes)
        else:
            declined += 1

    with open(output_jsonl, "w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record) + "\n")
    print(f"[+] Identity recon complete. Wrote {len(records)} nodes to {output_jsonl}")
    if declined:
        print(f"    {declined} persona(s) produced no account link: no corroborating evidence")
    return output_jsonl


def main():
    parser = argparse.ArgumentParser(description="Run identity-layer reconnaissance.")
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1")
    parser.add_argument("--url", default="http://127.0.0.1", help="Target URL to harvest")
    parser.add_argument("--active-jsonl", default=None)
    parser.add_argument("--web-evidence-jsonl", default=None)
    parser.add_argument("--out-dir", default=os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "out")))
    args = parser.parse_args()

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    corpus_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "corpus", "frozen.csv"))

    emails = fetch_emails_from_target(args.url)
    if not emails:
        print("[-] No emails found.")
        return
    print(f"[+] Found {len(emails)} email(s): {', '.join(emails)}")

    services = load_observed_services(
        args.active_jsonl or os.path.join(out_dir, "real_active.jsonl"))
    corroborations = load_corroborations(
        args.web_evidence_jsonl or os.path.join(out_dir, "real_web.jsonl"))
    generate_identity_jsonl(emails, corpus_path,
                            os.path.join(out_dir, "real_identity.jsonl"),
                            services, corroborations)


if __name__ == "__main__":
    main()
