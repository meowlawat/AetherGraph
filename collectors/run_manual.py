"""Convert an authorized synthetic VAPT report to graph records.

Two kinds of link come out of a manual report and they are not equivalent:

* The service the analyst tested. The report records a `location`; matching that
  location against services the active layer observed makes the link DERIVED,
  and makes it fail visibly when a report names a service nobody saw open.
* A correlation the analyst asserts to some other node. Nothing in the pipeline
  checks this, so it stays DECLARED and is excluded from the derived-only graph.

The earlier revision read a `target_service` field naming the port directly,
which meant the analyst was addressing graph nodes rather than describing where
they tested.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.derive import derive_finding_service
from core.provenance import DECLARED, edge


def load_observed_services(active_jsonl):
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
                parts = record["id"].split("-")
                services.append({"id": record["id"], "port": attrs.get("port"),
                                 "product": attrs.get("product"),
                                 "service": attrs.get("service"),
                                 "ip": attrs.get("ip") or (parts[1] if len(parts) >= 3 else "")})
    return services


def generate_manual_jsonl(report_path, output_jsonl, observed_services=(),
                          host_aliases=()):
    with open(report_path, encoding="utf-8") as report_file:
        report = json.load(report_file)
    records = []
    unmatched = []
    for finding in report.get("findings", []):
        declines = []
        edges = derive_finding_service(finding.get("location"), list(observed_services),
                                       host_aliases=host_aliases, declines=declines)
        if not edges:
            unmatched.append((finding["id"], "; ".join(declines) or "no location"))
        edges.extend(
            edge(credential, "CORRELATES", 0.75, DECLARED,
                 justification="asserted in the manual report")
            for credential in finding.get("related_credentials", [])
        )
        records.append({
            "id": f"finding-{finding['id']}",
            "attrs": {"type": "Finding", "class": finding["class"],
                      "title": finding["title"], "severity": finding["severity"],
                      "cvss_base": finding["cvss_base"], "location": finding["location"],
                      "evidence_refs": finding["evidence_refs"], "origin": "manual"},
            "edges": edges,
        })
    with open(output_jsonl, "w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record) + "\n")
    print(f"[+] Manual VAPT complete. Wrote {len(records)} findings to {output_jsonl}")
    for finding_id, reason in unmatched:
        print(f"    [declined] {finding_id}: {reason}")
    return output_jsonl


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default=os.path.join(os.path.dirname(__file__), "vapt_report.json"))
    parser.add_argument("--active-jsonl", default=None)
    parser.add_argument("--host-alias", action="append", default=[],
                        help="Address the analyst reached the testbed through that "
                             "should be treated as the scanned host (e.g. 127.0.0.1). "
                             "Declared explicitly because no evidence establishes it.")
    parser.add_argument("--out-dir", default=os.path.join(os.path.dirname(__file__), "..", "out"))
    args = parser.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    active_jsonl = args.active_jsonl or os.path.join(args.out_dir, "real_active.jsonl")
    generate_manual_jsonl(args.report,
                          os.path.join(args.out_dir, "real_manual.jsonl"),
                          load_observed_services(active_jsonl),
                          host_aliases=args.host_alias)


if __name__ == "__main__":
    main()
