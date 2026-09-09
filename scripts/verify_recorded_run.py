"""Recompute the graph summary from a recorded run's JSONL files and diff it
against that run's stored experiment_results.json.

This checks that the reported nodes, edges, entries, jewels, ranked paths and
criticality scores still follow from the stored evidence. It does not re-run
collection, so it does not re-contact the testbed.

Usage:
    python scripts/verify_recorded_run.py out/integrated_experiment_20260824_000517

Exits 0 when every field matches, 1 otherwise.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.scorer import (AetherGraph, calculate_criticality,
                         enumerate_crosslayer_paths, load_records)

RECORD_FILES = ("real_active.jsonl", "real_identity.jsonl",
                "real_secret.jsonl", "real_manual.jsonl")


def recompute(experiment_dir):
    graph = AetherGraph()
    present = [os.path.join(experiment_dir, name) for name in RECORD_FILES
               if os.path.exists(os.path.join(experiment_dir, name))]
    load_records(graph, present)
    entries = [node for node, data in graph.g.nodes(data=True)
               if data.get("origin") in {"manual", "identity"}]
    jewels = [node for node, data in graph.g.nodes(data=True)
              if data.get("type") == "Service"]
    calculate_criticality(graph, entries, jewels)
    paths = enumerate_crosslayer_paths(
        graph, entries, required_layers={"active", "identity", "manual"})
    return {
        "nodes": graph.g.number_of_nodes(),
        "edges": graph.g.number_of_edges(),
        "entries": entries,
        "jewels": jewels,
        "tri_layer_paths": [{"score": score, "path": path} for score, path in paths],
        "node_scores": {node: data["CR"] for node, data in graph.g.nodes(data=True)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment_dir")
    args = parser.parse_args()
    experiment_dir = os.path.abspath(args.experiment_dir)

    with open(os.path.join(experiment_dir, "experiment_results.json"), encoding="utf-8") as stored:
        reference = json.load(stored)
    computed = recompute(experiment_dir)

    all_match = True
    for field, value in computed.items():
        expected = reference.get(field)
        if field in ("entries", "jewels"):
            value, expected = sorted(value), sorted(expected or [])
        matched = value == expected
        all_match = all_match and matched
        print(f"{field:18} {'MATCH' if matched else 'DIFF'}")
        if not matched:
            print(f"   recomputed: {value}")
            print(f"   stored    : {expected}")

    print("\nALL MATCH" if all_match else "\nMISMATCH")
    return 0 if all_match else 1


if __name__ == "__main__":
    sys.exit(main())
