"""Regenerate the per-mode result files for a recorded run, strictly.

Strict loading is the point: the full graph must contain no edge into a node no
collector emitted. An ablation may legitimately withhold a stream, but the
complete run may not have a dangling reference.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.provenance import MODES
from core.scorer import (AetherGraph, calculate_criticality,
                         enumerate_crosslayer_paths, load_records)
from core.semantics import ALL_TRAVERSABLE, ATTACK_TRAVERSABLE

STREAMS = ["real_active.jsonl", "real_web.jsonl", "real_identity.jsonl",
           "real_secret.jsonl", "real_manual.jsonl"]


def main(run_dir):
    run_dir = os.path.abspath(run_dir)
    paths = [os.path.join(run_dir, s) for s in STREAMS
             if os.path.exists(os.path.join(run_dir, s))]
    for mode in ("observed-only", "derived", "all"):
        g = AetherGraph()
        load_records(g, paths, allowed_provenances=MODES[mode], strict_endpoints=True)
        entries = [n for n, d in g.g.nodes(data=True)
                   if d.get("origin") in {"manual", "identity"}]
        jewels = [n for n, d in g.g.nodes(data=True) if d.get("type") == "Service"]
        calculate_criticality(g, entries, jewels)
        attack = enumerate_crosslayer_paths(
            g, entries, required_layers={"active", "identity", "manual"},
            traversable_semantics=ATTACK_TRAVERSABLE)
        evidence = enumerate_crosslayer_paths(
            g, entries, required_layers={"active", "identity", "manual"},
            traversable_semantics=ALL_TRAVERSABLE)
        provenance, semantics = {}, {}
        for _, _, d in g.g.edges(data=True):
            provenance[d["provenance"]] = provenance.get(d["provenance"], 0) + 1
            semantics[d["semantic"]] = semantics.get(d["semantic"], 0) + 1
        result = {
            "mode": mode,
            "traversal": "attack (ACCESS edges only) unless stated",
            "nodes": g.g.number_of_nodes(),
            "edges": g.g.number_of_edges(),
            "provenance_counts": provenance,
            "semantic_counts": semantics,
            "entries": sorted(entries),
            "jewels": sorted(jewels),
            "tri_layer_attack_paths": [{"score": s, "path": p} for s, p in attack],
            "tri_layer_evidence_paths": [{"score": s, "path": p} for s, p in evidence],
            "node_scores": {n: d["CR"] for n, d in g.g.nodes(data=True)},
        }
        out = os.path.join(run_dir, f"experiment_results_{mode}.json")
        with open(out, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
        print(f"{mode:<15} nodes={result['nodes']:<3} edges={result['edges']:<3} "
              f"attack={len(attack)} evidence={len(evidence)}  -> {os.path.basename(out)}")
    print("\nStrict endpoint validation passed for every mode: no dangling references.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else
         os.path.join(ROOT, "out", "derived_experiment_20260908"))
