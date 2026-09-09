"""Verify the evidence-traversal scores quoted in the failure analysis.

The chain

    cred-web-1 --EXPOSED_BY--> path-...-80-backup --SERVES_PATH--> svc-...-80

is present in the recorded corrected graph and both of its relationships are
directly observed. It does not appear in the headline results because those
require a path to span all three evidence origins (active, identity, manual)
and this chain spans two. Relaxing the predicate to two origins and traversing
all edge types -- the semantics the pre-correction implementation used -- yields
the scores quoted in the paper.

This script exists so that those figures are reproducible from the artifacts
rather than asserted, and writes its result to evidence_chain_scores.json.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.scorer import AetherGraph, enumerate_crosslayer_paths, load_records
from core.semantics import ALL_TRAVERSABLE, ATTACK_TRAVERSABLE

STREAMS = ["real_active.jsonl", "real_web.jsonl", "real_identity.jsonl",
           "real_secret.jsonl", "real_manual.jsonl"]


def main(run_dir):
    run_dir = os.path.abspath(run_dir)
    graph = AetherGraph()
    load_records(graph, [os.path.join(run_dir, s) for s in STREAMS],
                 strict_endpoints=True)
    entries = [n for n, d in graph.g.nodes(data=True)
               if d.get("origin") in {"manual", "identity"}]

    result = {"run_dir": os.path.basename(run_dir), "configurations": {}}
    for name, layers, semantics in (
            ("three-origin, attack traversal (headline configuration)",
             {"active", "identity", "manual"}, ATTACK_TRAVERSABLE),
            ("three-origin, evidence traversal",
             {"active", "identity", "manual"}, ALL_TRAVERSABLE),
            ("two-origin, evidence traversal (quoted in the failure analysis)",
             {"active", "identity"}, ALL_TRAVERSABLE),
            ("two-origin, attack traversal",
             {"active", "identity"}, ATTACK_TRAVERSABLE)):
        found = enumerate_crosslayer_paths(graph, entries, required_layers=layers,
                                           traversable_semantics=semantics)
        result["configurations"][name] = [{"score": s, "path": p} for s, p in found]
        print(f"{name}: {len(found)} path(s)")
        for score, path in found:
            print(f"    {score:<7} {' -> '.join(path)}")

    out = os.path.join(run_dir, "evidence_chain_scores.json")
    with open(out, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    print(f"\n[+] Wrote {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else
         os.path.join(ROOT, "out", "derived_experiment_20260908"))
