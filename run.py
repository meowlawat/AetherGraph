import argparse
import json
import os
import subprocess
import sys

import networkx as nx

ROOT = os.path.dirname(__file__)
sys.path.insert(0, ROOT)

from core.provenance import MODES
from core.semantics import ALL_TRAVERSABLE, ATTACK_TRAVERSABLE
from core.scorer import AetherGraph, calculate_criticality, enumerate_crosslayer_paths, load_records


def run(command):
    subprocess.run(command, cwd=ROOT, check=True)


def discovered_host(active_jsonl):
    with open(active_jsonl, encoding="utf-8") as active_file:
        for line in active_file:
            record = json.loads(line)
            if record["attrs"].get("type") == "Host":
                return record["attrs"]["ip"]
    raise RuntimeError("Active scan did not discover a host")


def main():
    parser = argparse.ArgumentParser(description="Run the real AetherGraph tri-layer pipeline.")
    parser.add_argument("--out-dir", default=os.path.join(ROOT, "out", "integrated-run"))
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--skip-nuclei", action="store_true")
    parser.add_argument("--vhost", action="append", default=[],
                        help="Name-based virtual host the target also serves. Declared "
                             "explicitly because nothing in the collected evidence "
                             "reveals which names a server answers to.")
    parser.add_argument("--mode", choices=sorted(MODES), default="derived",
                        help="Which edge provenance levels to admit (default: derived, "
                             "which excludes links a human merely asserted)")
    args = parser.parse_args()
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    print("=== AetherGraph Integrated Pipeline ===")
    run([sys.executable, os.path.join(ROOT, "collectors", "run_active.py"), args.target,
         "--ports", "21,80,8080,3000", "--out-dir", out_dir])
    active_jsonl = os.path.join(out_dir, "real_active.jsonl")
    target_ip = discovered_host(active_jsonl)
    nuclei_status = "skipped"
    if not args.skip_nuclei:
        nuclei_host = "host.docker.internal" if args.target in {"127.0.0.1", "localhost"} else args.target
        try:
            run([sys.executable, os.path.join(ROOT, "collectors", "run_nuclei.py"),
                 f"http://{nuclei_host}", f"http://{nuclei_host}:3000",
                 f"http://{nuclei_host}:8080", "--out-dir", out_dir])
            nuclei_status = "completed"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            nuclei_status = "failed"
    open(os.path.join(out_dir, "real_nuclei.jsonl"), "a", encoding="utf-8").close()
    # Web evidence must run before identity: it supplies the corroborations that
    # let the identity layer justify an account link instead of inventing one.
    web_cmd = [sys.executable, os.path.join(ROOT, "collectors", "run_web_evidence.py"),
               "--active-jsonl", active_jsonl, "--out-dir", out_dir,
               "--host", args.target]
    for vhost in args.vhost:
        web_cmd += ["--vhost", vhost]
    run(web_cmd)
    run([sys.executable, os.path.join(ROOT, "collectors", "run_identity.py"), target_ip,
         "--url", f"http://{args.target}", "--active-jsonl", active_jsonl,
         "--web-evidence-jsonl", os.path.join(out_dir, "real_web.jsonl"),
         "--out-dir", out_dir])
    run([sys.executable, os.path.join(ROOT, "testbed", "setup_gitea.py")])
    repo_dir = os.path.join(ROOT, "testbed", "gitea-seed", "internal-tools")
    run([sys.executable, os.path.join(ROOT, "collectors", "run_secret_scan.py"), repo_dir,
         "--active-jsonl", active_jsonl, "--out-dir", out_dir])
    # The analyst reaches the testbed on the published address while the scanner
    # records the Docker gateway. Nothing in the evidence establishes that these
    # are the same host, so the equivalence is declared on the command line.
    run([sys.executable, os.path.join(ROOT, "collectors", "run_manual.py"),
         "--active-jsonl", active_jsonl, "--host-alias", args.target,
         "--out-dir", out_dir])

    graph = AetherGraph()
    record_paths = [os.path.join(out_dir, filename) for filename in (
        "real_active.jsonl", "real_nuclei.jsonl", "real_web.jsonl",
        "real_identity.jsonl", "real_secret.jsonl", "real_manual.jsonl"
    ) if os.path.exists(os.path.join(out_dir, filename))]
    # Strict: the complete run may not reference a node no collector emitted.
    load_records(graph, record_paths, allowed_provenances=MODES[args.mode],
                 strict_endpoints=True)
    entries = [node for node, data in graph.g.nodes(data=True)
               if data.get("origin") in {"manual", "identity"}]
    jewels = [node for node, data in graph.g.nodes(data=True) if data.get("type") == "Service"]
    calculate_criticality(graph, entries, jewels)

    # Export Graph to GraphML for academic viewers (Gephi/yEd).
    # GraphML has no list type, and several collectors legitimately emit list
    # attributes (repository remotes, evidence references, named services).
    # Those are JSON-encoded in an export copy so the in-memory graph, which the
    # scoring and traversal below operate on, is left untouched.
    graphml_path = os.path.join(out_dir, "aethergraph_export.graphml")
    exportable = graph.g.copy()
    for _, data in exportable.nodes(data=True):
        for key, value in list(data.items()):
            if isinstance(value, (list, dict, tuple)):
                data[key] = json.dumps(value)
            elif value is None:
                data[key] = ""
    for _, _, data in exportable.edges(data=True):
        for key, value in list(data.items()):
            if isinstance(value, (list, dict, tuple)):
                data[key] = json.dumps(value)
            elif value is None:
                data[key] = ""
    nx.write_graphml(exportable, graphml_path)
    print(f"[*] Exported graph to {graphml_path}")

    # Attack paths walk only edges whose semantics describe attacker movement.
    # The evidence-graph traversal is reported alongside because it is what the
    # pre-correction implementation measured, and the two are not the same thing.
    paths = enumerate_crosslayer_paths(
        graph, entries, required_layers={"active", "identity", "manual"},
        traversable_semantics=ATTACK_TRAVERSABLE)
    evidence_paths = enumerate_crosslayer_paths(
        graph, entries, required_layers={"active", "identity", "manual"},
        traversable_semantics=ALL_TRAVERSABLE)
    result = {
        "mode": args.mode,
        "nodes": graph.g.number_of_nodes(),
        "edges": graph.g.number_of_edges(),
        "nuclei_status": nuclei_status,
        "gitea_publication": "enabled" if os.environ.get("GITEA_TOKEN") else "local-only",
        "entries": entries,
        "jewels": jewels,
        "tri_layer_attack_paths": [{"score": s_, "path": p_} for s_, p_ in paths],
        "tri_layer_evidence_paths": [{"score": s_, "path": p_}
                                     for s_, p_ in evidence_paths],
        "node_scores": {node: data["CR"] for node, data in graph.g.nodes(data=True)},
    }
    result_path = os.path.join(out_dir, "experiment_results.json")
    with open(result_path, "w", encoding="utf-8") as output:
        json.dump(result, output, indent=2)
    print(json.dumps(result, indent=2))
    print(f"[+] Integrated results written to {result_path}")


if __name__ == "__main__":
    main()
