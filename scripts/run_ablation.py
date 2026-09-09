"""Ablation over collector layers and edge provenance.

Two questions, one harness:

1. Which layers contribute? Build the graph from increasing subsets of the
   collector streams and report what each subset recovers.
2. Which edges survive scrutiny? Build each subset three times, admitting only
   observed edges, then observed+derived, then everything including edges a
   human declared. A result that appears only in the third column depends on
   somebody having asserted it.

Recall is measured against testbed/seed_manifest.json, which is legitimate here
only because the environment is synthetic and we planted every item in it.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.provenance import MODES
from core.semantics import ALL_TRAVERSABLE, ATTACK_TRAVERSABLE
from core.scorer import (AetherGraph, calculate_criticality,
                         enumerate_crosslayer_paths, load_records)

STREAMS = [
    ("active", "real_active.jsonl"),
    ("web", "real_web.jsonl"),
    ("identity", "real_identity.jsonl"),
    ("secret", "real_secret.jsonl"),
    ("manual", "real_manual.jsonl"),
]

LAYER_SUBSETS = [
    ("active only", ["active"]),
    ("+ web evidence", ["active", "web"]),
    ("+ identity", ["active", "web", "identity", "secret"]),
    ("+ manual (all)", ["active", "web", "identity", "secret", "manual"]),
]


def existing(run_dir, names):
    paths = []
    for key, filename in STREAMS:
        if key in names:
            path = os.path.join(run_dir, filename)
            if os.path.exists(path):
                paths.append(path)
    return paths


def build(run_dir, names, mode, semantics=ATTACK_TRAVERSABLE):
    """Build the graph for one (layer subset, provenance mode) cell.

    `semantics` selects which edge meanings may be walked. The default admits
    only attacker-movement edges. Passing ALL_TRAVERSABLE reproduces the
    pre-correction behaviour, which walked evidence and containment edges as
    though they were transitions.
    """
    graph = AetherGraph()
    # An ablation deliberately withholds streams, so an edge into a withheld
    # node is expected rather than malformed. It is dropped and counted, never
    # turned into a phantom endpoint. The full run is loaded strictly instead.
    rejected = load_records(graph, existing(run_dir, names),
                            allowed_provenances=MODES[mode],
                            strict_endpoints=False)
    entries = [n for n, d in graph.g.nodes(data=True)
               if d.get("origin") in {"manual", "identity"}]
    jewels = [n for n, d in graph.g.nodes(data=True) if d.get("type") == "Service"]
    if entries:
        calculate_criticality(graph, entries, jewels)
        paths = enumerate_crosslayer_paths(
            graph, entries, required_layers={"active", "identity", "manual"},
            traversable_semantics=semantics)
    else:
        paths = []
    return graph, paths, rejected


def semantic_counts(graph):
    counts = {}
    for _, _, data in graph.g.edges(data=True):
        key = data.get("semantic") or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts


def provenance_counts(graph):
    counts = {"observed": 0, "derived": 0, "declared": 0}
    for _, _, data in graph.g.edges(data=True):
        key = data.get("provenance") or "declared"
        counts[key] = counts.get(key, 0) + 1
    return counts


def check_manifest(run_dir, manifest_path):
    """Check recovered structure against seeded ground truth."""
    with open(manifest_path, encoding="utf-8") as source:
        manifest = json.load(source)
    records = []
    for _, filename in STREAMS:
        path = os.path.join(run_dir, filename)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as stream:
                records.extend(json.loads(line) for line in stream if line.strip())
    types = {record["id"]: record["attrs"].get("type") for record in records}

    found, missing = [], []
    claimed = set()  # an edge may satisfy at most one expectation
    for expected in manifest["expected_links"]:
        rule = expected.get("match", {})
        hit = None
        for record in records:
            if types.get(record["id"]) != expected["from_type"]:
                continue
            if not record["id"].startswith(rule.get("from_prefix", "")):
                continue
            for link in record.get("edges", []):
                key = (record["id"], link["to"], link["type"])
                if key in claimed:
                    continue
                if link["type"] != expected["edge"]:
                    continue
                if not str(link["to"]).startswith(rule.get("to_prefix", "")):
                    continue
                if not str(link["to"]).endswith(rule.get("to_suffix", "")):
                    continue
                if types.get(link["to"], _infer_type(link["to"])) != expected["to_type"]:
                    continue
                if link.get("provenance", "declared") != expected["expected_provenance"]:
                    continue
                claimed.add(key)
                hit = f"{record['id']} -{link['type']}-> {link['to']}"
                break
            if hit:
                break
        (found if hit else missing).append((expected["id"], hit))

    violations = []
    for forbidden in manifest["forbidden_links"]:
        pattern = forbidden["pattern"]
        for record in records:
            if not record["id"].startswith(pattern["from_prefix"]):
                continue
            for link in record.get("edges", []):
                if str(link["to"]).endswith(pattern["to_suffix"]):
                    violations.append((forbidden["id"],
                                       f"{record['id']} -> {link['to']}"))
    return found, missing, violations


def _infer_type(node_id):
    for prefix, kind in (("svc-", "Service"), ("host-", "Host"), ("path-", "WebPath"),
                         ("persona-", "Persona"), ("account-", "Account"),
                         ("cred-", "Credential"), ("finding-", "Finding"),
                         ("exposure-", "Exposure")):
        if node_id.startswith(prefix):
            return kind
    return "?"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir")
    parser.add_argument("--manifest", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "testbed", "seed_manifest.json"))
    parser.add_argument("--json-out", default=None)
    args = parser.parse_args()
    run_dir = os.path.abspath(args.run_dir)

    print("=" * 78)
    print("LAYER x PROVENANCE ABLATION")
    print("=" * 78)
    print(f"{'layer subset':<18}{'mode':<16}{'nodes':>6}{'edges':>7}"
          f"{'attack paths':>14}{'evidence paths':>16}")
    print("-" * 78)
    results = {}
    for label, names in LAYER_SUBSETS:
        for mode in ("observed-only", "derived", "all"):
            graph, paths, rejected = build(run_dir, names, mode, ATTACK_TRAVERSABLE)
            _, evidence_paths, _ = build(run_dir, names, mode, ALL_TRAVERSABLE)
            results[f"{label}|{mode}"] = {
                "nodes": graph.g.number_of_nodes(),
                "edges": graph.g.number_of_edges(),
                "tri_layer_attack_paths": [{"score": s, "path": p} for s, p in paths],
                "tri_layer_evidence_paths": [{"score": s, "path": p}
                                             for s, p in evidence_paths],
                "provenance": provenance_counts(graph),
                "semantics": semantic_counts(graph),
                "edges_dropped_into_withheld_streams": len(rejected),
            }
            print(f"{label:<18}{mode:<16}{graph.g.number_of_nodes():>6}"
                  f"{graph.g.number_of_edges():>7}{len(paths):>14}"
                  f"{len(evidence_paths):>16}"
                  + (f"   ({len(rejected)} edge(s) into withheld streams)" if rejected else ""))
        print("-" * 78)
    print("attack paths   = walking only ACCESS edges (attacker movement)")
    print("evidence paths = walking every edge type, as the original implementation did")

    full = results["+ manual (all)|all"]
    print("\nEDGE PROVENANCE IN THE FULL GRAPH")
    for key, count in full["provenance"].items():
        print(f"  {key:<10} {count}")

    print("\nGROUND TRUTH (testbed/seed_manifest.json)")
    found, missing, violations = check_manifest(run_dir, args.manifest)
    for name, hit in found:
        print(f"  [recovered] {name:<26} {hit}")
    for name, _ in missing:
        print(f"  [MISSED   ] {name}")
    print(f"  recall: {len(found)}/{len(found) + len(missing)} expected links recovered")
    if violations:
        for name, detail in violations:
            print(f"  [FABRICATED] {name}: {detail}")
    else:
        print(f"  fabricated links: 0 of {2} forbidden patterns present")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as out:
            json.dump({"ablation": results,
                       "recall": {"found": found, "missing": missing},
                       "violations": violations}, out, indent=2)
        print(f"\n[+] Wrote {args.json_out}")
    return 0 if not violations and not missing else 1


if __name__ == "__main__":
    sys.exit(main())
