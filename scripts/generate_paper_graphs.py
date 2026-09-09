"""Generate the manuscript figures from recorded artifacts.

Two graphs are drawn, side by side in the paper: the baseline graph with its
fabricated relationships marked, and the corrected graph coloured by edge
provenance. Neither figure may present the baseline's top-ranked path as a
legitimate finding, so the fabricated edges are drawn dashed and red and are
labelled as such in the legend.
"""
import argparse
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import networkx as nx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.semantics import EDGE_SEMANTICS

ORIGIN_COLORS = {"active": "#2f6f9f", "identity": "#b55d35", "manual": "#4b7f52"}
# Edge palette is deliberately disjoint from ORIGIN_COLORS so that a node colour
# and an edge colour can never be confused in the legend, and reserves red for
# the "unsupported relationship" marking used in the baseline figure only.
PROV_COLORS = {"observed": "#3b3b3b", "derived": "#c98a1b", "declared": "#7b3294"}

#: The two relationships the forensic reconstruction identified as fabricated,
#: as (source prefix, destination suffix) so they can be found in either graph.
FABRICATED = [("cred-git-", "-3000"), ("account-c.brown", "-21")]


def load(run_dir, streams):
    records = []
    for name in streams:
        path = os.path.join(run_dir, name)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as stream:
            records.extend(json.loads(l) for l in stream if l.strip())
    return records


def to_graph(records):
    g = nx.DiGraph()
    for r in records:
        g.add_node(r["id"], **r["attrs"])
    for r in records:
        for e in r.get("edges", []):
            if e["to"] not in g:                      # never draw a phantom
                continue
            g.add_edge(r["id"], e["to"], etype=e["type"],
                       provenance=e.get("provenance", "declared"),
                       semantic=EDGE_SEMANTICS.get(e["type"], "unknown"))
    return g


def is_fabricated(u, v):
    return any(u.startswith(a) and v.endswith(b) for a, b in FABRICATED)


def draw(g, title, path, edge_color_by):
    fig, ax = plt.subplots(figsize=(13, 8))
    pos = nx.spring_layout(g, seed=17, k=0.9)
    node_colors = [ORIGIN_COLORS.get(g.nodes[n].get("origin"), "#777777") for n in g]
    nx.draw_networkx_nodes(g, pos, node_color=node_colors, node_size=1500,
                           edgecolors="#333333", linewidths=1.0, ax=ax)
    nx.draw_networkx_labels(g, pos, font_size=6.5, ax=ax)

    normal = [(u, v) for u, v in g.edges if not is_fabricated(u, v)]
    fabricated = [(u, v) for u, v in g.edges if is_fabricated(u, v)]
    if edge_color_by == "provenance":
        colors = [PROV_COLORS.get(g.edges[e]["provenance"], "#777") for e in normal]
    else:
        colors = ["#555555"] * len(normal)
    nx.draw_networkx_edges(g, pos, edgelist=normal, edge_color=colors, arrows=True,
                           arrowsize=14, width=1.4, connectionstyle="arc3,rad=0.05", ax=ax)
    if fabricated:
        nx.draw_networkx_edges(g, pos, edgelist=fabricated, edge_color="#d62728",
                               style="dashed", arrows=True, arrowsize=16, width=2.4,
                               connectionstyle="arc3,rad=0.05", ax=ax)

    handles = [mpatches.Patch(color=c, label=f"{k} origin") for k, c in ORIGIN_COLORS.items()]
    if edge_color_by == "provenance":
        handles += [mpatches.Patch(color=c, label=f"{k} relationship") for k, c in PROV_COLORS.items()]
    if fabricated:
        handles.append(mpatches.Patch(color="#d62728",
                                      label="unsupported relationship (fabrication pattern)"))
    ax.legend(handles=handles, loc="lower left", fontsize=7, framealpha=0.9)
    ax.set_title(title, fontsize=11)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def counts_figure(records, path, title):
    counts = {"active": 0, "identity": 0, "manual": 0}
    for r in records:
        origin = r["attrs"].get("origin")
        if origin in counts:
            counts[origin] += 1
    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(list(counts), list(counts.values()),
                  color=[ORIGIN_COLORS[k] for k in counts])
    ax.bar_label(bars)
    ax.set_ylabel("Records emitted")
    ax.set_title(title, fontsize=10)
    fig.tight_layout()
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=os.path.join(
        ROOT, "out", "integrated_experiment_20260824_000517"))
    parser.add_argument("--corrected", default=os.path.join(
        ROOT, "out", "derived_experiment_20260908"))
    args = parser.parse_args()

    base = load(args.baseline, ["real_active.jsonl", "real_identity.jsonl",
                                "real_secret.jsonl", "real_manual.jsonl"])
    corr = load(args.corrected, ["real_active.jsonl", "real_web.jsonl",
                                 "real_identity.jsonl", "real_secret.jsonl",
                                 "real_manual.jsonl"])

    print("Figures:")
    draw(to_graph(base),
         "Baseline graph. Dashed red relationships were generated without "
         "evidentiary support; they are not discovered findings.",
         os.path.join(args.corrected, "Figure_baseline_graph.png"), "none")
    draw(to_graph(corr),
         "Corrected graph, relationships coloured by provenance. Neither "
         "previously identified fabrication pattern is present.",
         os.path.join(args.corrected, "Figure_corrected_graph.png"), "provenance")
    counts_figure(corr, os.path.join(args.corrected, "Figure_corrected_counts.png"),
                  "Records emitted by origin, corrected run (a count, not a coverage measure)")


if __name__ == "__main__":
    main()
