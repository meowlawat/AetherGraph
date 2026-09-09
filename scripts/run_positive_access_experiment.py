"""Evaluate the positive ACCESS validation experiment and write its report.

Builds the graph from the live-collected streams, runs attack traversal with the
unmodified ATTACK_TRAVERSABLE set, and records whether a genuine capability
relationship and a non-empty attack path were produced. It also re-checks that
no fabrication pattern from the original defect is present, and that no secret
material appears in any artifact.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.provenance import MODES
from core.scorer import (AetherGraph, calculate_criticality,
                         enumerate_crosslayer_paths, load_records)
from core.semantics import ALL_TRAVERSABLE, ATTACK_TRAVERSABLE, EDGE_SEMANTICS

STREAMS = ["real_active.jsonl", "real_web.jsonl", "real_identity.jsonl",
           "real_secret.jsonl", "real_manual.jsonl"]

#: Patterns from the original defect that must not reappear.
FABRICATION_PATTERNS = [
    ("hardcoded secret target", re.compile(r'f"svc-\{[^}]*\}-3000"')),
    ("hardcoded ftp account", re.compile(r'f"account-\{username\}-ftp"')),
]


def build(run_dir, mode="all"):
    paths = [os.path.join(run_dir, s) for s in STREAMS
             if os.path.exists(os.path.join(run_dir, s))]
    graph = AetherGraph()
    load_records(graph, paths, allowed_provenances=MODES[mode], strict_endpoints=True)
    entries = [n for n, d in graph.g.nodes(data=True)
               if d.get("origin") in {"manual", "identity"}]
    jewels = [n for n, d in graph.g.nodes(data=True) if d.get("type") == "Service"]
    calculate_criticality(graph, entries, jewels)
    return graph, entries


def main(run_dir):
    run_dir = os.path.abspath(run_dir)
    graph, entries = build(run_dir)

    access_edges = [(u, v, d) for u, v, d in graph.g.edges(data=True)
                    if d.get("semantic") == "access"]

    print("=" * 78)
    print("POSITIVE ACCESS VALIDATION")
    print("=" * 78)
    print(f"nodes={graph.g.number_of_nodes()} edges={graph.g.number_of_edges()}")
    print(f"\ncapability (ACCESS) relationships: {len(access_edges)}")
    for u, v, d in access_edges:
        print(f"  {u} -[{d['etype']} conf={d['conf']} {d['provenance']}]-> {v}")
        print(f"      justification: {d['justification']}")

    results = {}
    for label, layers in (("two-origin {identity, active}", {"identity", "active"}),
                          ("three-origin {active, identity, manual}",
                           {"active", "identity", "manual"})):
        attack = enumerate_crosslayer_paths(graph, entries, required_layers=layers,
                                            traversable_semantics=ATTACK_TRAVERSABLE)
        evidence = enumerate_crosslayer_paths(graph, entries, required_layers=layers,
                                              traversable_semantics=ALL_TRAVERSABLE)
        results[label] = {"attack": attack, "evidence": evidence}
        print(f"\n{label}")
        print(f"  attack traversal (ACCESS only): {len(attack)} path(s)")
        for score, path in attack:
            print(f"    score={score}  {' -> '.join(path)}")
            for a, b in zip(path, path[1:]):
                d = graph.g.edges[a, b]
                print(f"        {a} -[{d['etype']} conf={d['conf']} "
                      f"{d['provenance']} sem={d['semantic']}]-> {b}")
            for node in path:
                print(f"        severity({node}) = "
                      f"{graph.g.nodes[node].get('severity')}")
        print(f"  evidence traversal (all types): {len(evidence)} path(s)")

    # Independence from the original defect.
    print("\n" + "=" * 78)
    print("INDEPENDENCE FROM THE ORIGINAL FABRICATION PATTERNS")
    print("=" * 78)
    source = ""
    for folder in ("collectors", "core"):
        for name in sorted(os.listdir(os.path.join(ROOT, folder))):
            if name.endswith(".py"):
                with open(os.path.join(ROOT, folder, name), encoding="utf-8") as fh:
                    source += fh.read()
    clean = True
    for label, pattern in FABRICATION_PATTERNS:
        hit = bool(pattern.search(source))
        clean = clean and not hit
        print(f"  {label}: {'PRESENT (FAIL)' if hit else 'absent'}")
    records = []
    for name in STREAMS:
        p = os.path.join(run_dir, name)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                records += [json.loads(l) for l in fh if l.strip()]
    blob = json.dumps(records)
    manual_injected = any(e["type"] == "ENABLES_ACCESS" and e.get("provenance") != "derived"
                          for r in records for e in r.get("edges", []))
    print(f"  every ACCESS edge is derived: {not manual_injected}")

    # Secret leakage.
    token = os.environ.get("GITEA_PAC_TOKEN", "").strip()
    leaked = bool(token) and token in blob
    hex40 = re.findall(r"\b[0-9a-f]{40}\b", blob)
    commit_hashes = {r["attrs"].get("commit") for r in records
                     if r["attrs"].get("commit")}
    stray = [h for h in hex40 if h not in commit_hashes]
    print(f"  token value present in artifacts: {leaked}")
    print(f"  stray 40-hex values (excluding commit ids): {len(stray)}")

    two = results["two-origin {identity, active}"]["attack"]
    three = results["three-origin {active, identity, manual}"]["attack"]
    report = {
        "experiment": "positive_access_live",
        "live_docker_run": True,
        "token_validated": os.environ.get("PAC_TOKEN_VALIDATED") == "true",
        "repository_remote_present": any(
            r["attrs"].get("repo_remotes") for r in records),
        "service_independently_observed": any(
            r["attrs"].get("http_title") for r in records),
        "credential_type_compatible": any(
            r["attrs"].get("secret_kind") == "gitea-token" for r in records),
        "access_edge_emitted": len(access_edges) > 0,
        "access_edge_count": len(access_edges),
        "access_edge_provenance": sorted({d["provenance"] for _, _, d in access_edges}),
        "access_edge_justification": [d["justification"] for _, _, d in access_edges],
        "attack_path_emitted": len(two) > 0,
        "attack_path_count_two_origin": len(two),
        "attack_path_count_three_origin": len(three),
        "path_score": two[0][0] if two else None,
        "path": two[0][1] if two else None,
        "no_fabrication_pattern_in_source": clean,
        "all_access_edges_derived": not manual_injected,
        "secret_leaked_into_artifacts": leaked,
        "nodes": graph.g.number_of_nodes(),
        "edges": graph.g.number_of_edges(),
    }
    out = os.path.join(run_dir, "experiment_report.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[+] Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else
                  os.path.join(ROOT, "out", "positive_access_live")))
