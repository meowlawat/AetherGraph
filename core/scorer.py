"""Graph construction, criticality scoring and path enumeration.

Three properties this module is responsible for enforcing:

1. Every edge carries a provenance label (core.provenance) and a declared
   semantic category (core.semantics). Neither has a default.
2. An edge may not reference a node that no collector emitted. NetworkX will
   silently create an attribute-less endpoint on add_edge; that behaviour is
   suppressed here so a malformed collector fails loudly instead of injecting a
   node with no type, no origin and severity 0.
3. Attack-path traversal walks only edges whose semantics describe attacker
   movement. Evidence-lineage and asset-containment edges are real and useful
   but do not mean an attacker can move along them.
"""
import json
import math

import networkx as nx

from core.provenance import ALL_PROVENANCES, DECLARED
from core.semantics import ATTACK_TRAVERSABLE, semantics_of

CONF_FLOOR = 0.60
LAMBDA = 0.95
#: Maximum number of NODES in an enumerated path (so at most MAXLEN-1 edges).
MAXLEN = 5
W = dict(sev=.40, reach=.25, blast=.25, asset=.10)
#: Asset-class weights. A prototype convention, not a validated asset model.
ASSET_W = {
    "identity-provider": 1.0,
    "database": .9,
    "internal-app": .6,
    "dmz-web": .5,
    "decoy": 0.0,
}
DEFAULT_ASSET_W = 0.1


class MissingEndpoint(KeyError):
    """Raised when an edge references a node that no collector emitted."""


def severity_of(attrs):
    """Severity as a float, treating absent *and explicitly null* as 0.0.

    Collectors legitimately omit severity for structural nodes (Host, Persona).
    A JSON ``"severity": null`` also reaches us as None, and float(None) raises,
    so both cases are normalised here rather than at each call site.
    """
    value = attrs.get("severity")
    if value is None:
        return 0.0
    return float(value)


class AetherGraph:
    def __init__(self):
        self.g = nx.DiGraph()

    def node(self, nid, **a):
        self.g.add_node(nid, **a)
        return nid

    def edge(self, u, v, etype, conf, provenance, justification="",
             require_endpoints=True):
        """Add an edge. Provenance is mandatory; semantics must be declared.

        `require_endpoints` exists only so unit tests can build small graphs in
        any order; production loading always validates.
        """
        if provenance not in ALL_PROVENANCES:
            raise ValueError(f"Unknown provenance {provenance!r} on {u} -> {v}")
        semantic = semantics_of(etype)          # raises UnknownEdgeType
        if require_endpoints:
            for endpoint in (u, v):
                if endpoint not in self.g:
                    raise MissingEndpoint(
                        f"Edge {u} -[{etype}]-> {v} references node {endpoint!r}, "
                        f"which no collector emitted. Refusing to create a phantom "
                        f"node. Check the collector that produced this record."
                    )
        self.g.add_edge(u, v, etype=etype, conf=round(conf, 2),
                        provenance=provenance, justification=justification,
                        semantic=semantic)


def load_records(fg: AetherGraph, jsonl_paths, allowed_provenances=None,
                 strict_endpoints=True):
    """Load JSONL record streams into the graph.

    Nodes from every stream are inserted first, then edges, so that a forward
    reference between collectors is legal while a reference to a node nobody
    emitted is an error. `allowed_provenances` restricts which edges are
    admitted, which is how the provenance ablation is performed; nodes are never
    filtered, so an excluded edge leaves an isolated node rather than deleting
    evidence.

    Edges written before provenance labelling default to DECLARED, the most
    conservative reading, so a legacy stream can be loaded for comparison
    without being silently promoted to observed.
    """
    pending = []
    for path in jsonl_paths:
        with open(path, "r", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                record = json.loads(line)
                fg.node(record["id"], **record["attrs"])
                for e in record.get("edges", []):
                    pending.append((record["id"], e, path))

    rejected = []
    for source, e, path in pending:
        provenance = e.get("provenance", DECLARED)
        if allowed_provenances is not None and provenance not in allowed_provenances:
            continue
        missing = [n for n in (source, e["to"]) if n not in fg.g]
        if missing:
            # Never fall through to add_edge here: NetworkX would materialise the
            # missing endpoint as an attribute-less node.
            if strict_endpoints:
                raise MissingEndpoint(
                    f"Edge {source} -[{e['type']}]-> {e['to']} references node "
                    f"{missing[0]!r}, which no collector emitted. Refusing to create "
                    f"a phantom node. (record from {path})")
            rejected.append((source, e["to"], e["type"]))
            continue
        fg.edge(source, e["to"], e["type"], e["conf"], provenance,
                e.get("justification", ""))
    return rejected


def calculate_criticality(fg: AetherGraph, entries, jewels):
    """Annotate every node with CR = .40S + .25R + .25B + .10A."""
    dg = fg.g
    jewel_set = set(jewels)
    present_entries = [s for s in entries if s in dg]
    for v, attr in dg.nodes(data=True):
        sev = severity_of(attr)

        distances = []
        for s in present_entries:
            try:
                if nx.has_path(dg, s, v):
                    distances.append(nx.shortest_path_length(dg, s, v))
            except (nx.NodeNotFound, nx.NetworkXNoPath, ValueError):
                continue
        d = min(distances) if distances else 99
        reach = 1.0 / (1.0 + d)

        descendants = nx.descendants(dg, v)
        blast = sum(1 for j in descendants if j in jewel_set) / max(len(jewel_set), 1)

        aw = ASSET_W.get(attr.get("asset_class", ""), DEFAULT_ASSET_W)

        dg.nodes[v]["CR"] = round(
            W["sev"] * sev + W["reach"] * reach + W["blast"] * blast + W["asset"] * aw, 3)


def enumerate_crosslayer_paths(fg: AetherGraph, entries, maxlen=MAXLEN,
                               required_layers=None,
                               traversable_semantics=ATTACK_TRAVERSABLE):
    """Enumerate cross-layer paths, walking only semantically eligible edges.

    P(pi) = (prod conf) * (sum severity) * LAMBDA^(len(pi)-1), over paths whose
    node origins cover `required_layers` and whose every edge clears CONF_FLOOR.

    `traversable_semantics` defaults to attacker-movement edges only. Pass
    core.semantics.ALL_TRAVERSABLE to walk the whole evidence graph, which is
    what the pre-correction implementation did implicitly; results obtained that
    way are evidence-graph connectivity, not attack paths.
    """
    dg = fg.g
    required_layers = set(required_layers or {"active", "identity"})
    out = []

    def passable(u, v):
        data = dg.edges[u, v]
        if data["conf"] < CONF_FLOOR:
            return False
        semantic = data.get("semantic") or semantics_of(data["etype"])
        return semantic in traversable_semantics

    for s in entries:
        if s not in dg:
            continue
        stack = [(s, [s])]
        while stack:
            v, pth = stack.pop()
            if len(pth) > maxlen:
                continue
            layers = {dg.nodes[n].get("origin") for n in pth if dg.nodes[n].get("origin")}
            if len(pth) > 1 and required_layers.issubset(layers):
                edges = [(pth[i], pth[i + 1]) for i in range(len(pth) - 1)]
                conf = math.prod(dg.edges[u, w]["conf"] for u, w in edges)
                gain = sum(severity_of(dg.nodes[n]) for n in pth)
                out.append((round(conf * gain * (LAMBDA ** (len(pth) - 1)), 3), pth))
            for nxt in dg.successors(v):
                if nxt not in pth and passable(v, nxt):
                    stack.append((nxt, pth + [nxt]))

    return sorted(out, reverse=True, key=lambda item: item[0])
