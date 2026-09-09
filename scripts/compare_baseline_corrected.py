"""Reproduce the pre-correction result from its own stored evidence, then show
what the corrected pipeline does with the same question.

Four graphs are built and compared:

  baseline / evidence-traversal   the original stored streams, every edge type
                                  walked as though it were attacker movement.
                                  This is what the original implementation did
                                  and is the configuration that yields 0.914.
  baseline / attack-traversal     the same stored streams, walking only edges
                                  whose semantics describe attacker movement.
  corrected / evidence-traversal   the rebuilt streams, all edge types walked.
  corrected / attack-traversal     the rebuilt streams, attacker movement only.

Nothing here regenerates evidence. The baseline directory is read as-is so the
original result stays reproducible from the artifacts that produced it.
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

BASELINE = os.path.join(ROOT, "out", "integrated_experiment_20260824_000517")
CORRECTED = os.path.join(ROOT, "out", "derived_experiment_20260908")

BASELINE_STREAMS = ["real_active.jsonl", "real_identity.jsonl",
                    "real_secret.jsonl", "real_manual.jsonl"]
CORRECTED_STREAMS = ["real_active.jsonl", "real_web.jsonl", "real_identity.jsonl",
                     "real_secret.jsonl", "real_manual.jsonl"]


def build(run_dir, streams, mode, semantics):
    paths = [os.path.join(run_dir, s) for s in streams
             if os.path.exists(os.path.join(run_dir, s))]
    g = AetherGraph()
    load_records(g, paths, allowed_provenances=MODES[mode], strict_endpoints=False)
    entries = [n for n, d in g.g.nodes(data=True)
               if d.get("origin") in {"manual", "identity"}]
    jewels = [n for n, d in g.g.nodes(data=True) if d.get("type") == "Service"]
    calculate_criticality(g, entries, jewels)
    found = enumerate_crosslayer_paths(
        g, entries, required_layers={"active", "identity", "manual"},
        traversable_semantics=semantics)
    return g, found


def describe(name, run_dir, streams, semantics, mode="all"):
    g, found = build(run_dir, streams, mode, semantics)
    prov = {}
    sem = {}
    for _, _, d in g.g.edges(data=True):
        prov[d.get("provenance") or "declared"] = prov.get(d.get("provenance") or "declared", 0) + 1
        sem[d.get("semantic")] = sem.get(d.get("semantic"), 0) + 1
    print(f"\n{name}")
    print(f"  nodes={g.g.number_of_nodes()}  edges={g.g.number_of_edges()}")
    print(f"  provenance={dict(sorted(prov.items()))}")
    print(f"  semantics ={dict(sorted(sem.items()))}")
    print(f"  tri-layer paths: {len(found)}")
    for score, path in found[:5]:
        print(f"    {score:<7} {' -> '.join(path)}")
    return {"nodes": g.g.number_of_nodes(), "edges": g.g.number_of_edges(),
            "provenance": prov, "semantics": sem,
            "tri_layer_paths": [{"score": s, "path": p} for s, p in found]}


def main():
    print("=" * 78)
    print("BASELINE vs CORRECTED")
    print("=" * 78)
    report = {}
    report["baseline_evidence_traversal"] = describe(
        "BASELINE, evidence-traversal (what the original implementation did)",
        BASELINE, BASELINE_STREAMS, ALL_TRAVERSABLE)
    report["baseline_attack_traversal"] = describe(
        "BASELINE, attack-traversal (ACCESS edges only)",
        BASELINE, BASELINE_STREAMS, ATTACK_TRAVERSABLE)
    report["corrected_evidence_traversal"] = describe(
        "CORRECTED, evidence-traversal (all edge types)",
        CORRECTED, CORRECTED_STREAMS, ALL_TRAVERSABLE)
    report["corrected_attack_traversal"] = describe(
        "CORRECTED, attack-traversal (ACCESS edges only)",
        CORRECTED, CORRECTED_STREAMS, ATTACK_TRAVERSABLE)

    print("\n" + "=" * 78)
    print("CHECKS")
    print("=" * 78)
    base = report["baseline_evidence_traversal"]["tri_layer_paths"]
    top = base[0]["score"] if base else None
    print(f"  baseline reproduces 0.914 from its own stored evidence : "
          f"{top == 0.914}  (top score = {top})")
    corrected_top = [p["score"] for p in
                     report["corrected_attack_traversal"]["tri_layer_paths"]]
    print(f"  corrected pipeline does NOT reproduce that path        : "
          f"{0.914 not in corrected_top}")
    print(f"  corrected attack-traversal path count                  : "
          f"{len(corrected_top)}")
    print(f"  baseline under attack-traversal path count             : "
          f"{len(report['baseline_attack_traversal']['tri_layer_paths'])}")

    out = os.path.join(CORRECTED, "baseline_vs_corrected.json")
    with open(out, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    print(f"\n[+] Wrote {out}")


if __name__ == "__main__":
    main()
