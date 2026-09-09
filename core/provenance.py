"""Edge provenance vocabulary.

Every edge in an AetherGraph graph carries a provenance label saying how it came
to exist. The distinction matters because a path is only as strong as its weakest
edge, and a reader cannot judge that from a confidence number alone.

OBSERVED  A tool reported this relationship directly. Nmap saw the service on the
          host; Gobuster saw the path on the service; a fetched file contained a
          credential. No inference step.

DERIVED   A rule combined two or more pieces of observed evidence to conclude the
          relationship, and recorded the justification. The rule must be able to
          decline: if the evidence is absent, no edge is emitted.

DECLARED  A human asserted the relationship in a report. It may well be true, but
          it entered the graph because someone typed it, not because the pipeline
          found it. Declared edges are excluded from the derived-only graph so
          that results cannot be circular.
"""

OBSERVED = "observed"
DERIVED = "derived"
DECLARED = "declared"

ALL_PROVENANCES = (OBSERVED, DERIVED, DECLARED)

#: Provenance levels admitted by each ablation mode.
MODES = {
    "observed-only": {OBSERVED},
    "derived": {OBSERVED, DERIVED},
    "all": {OBSERVED, DERIVED, DECLARED},
}


def edge(to, etype, conf, provenance, justification=""):
    """Build an edge record. `justification` is required for DERIVED edges."""
    if provenance not in ALL_PROVENANCES:
        raise ValueError(f"Unknown provenance: {provenance!r}")
    if provenance == DERIVED and not justification:
        raise ValueError(f"A {DERIVED} edge to {to!r} must record its justification")
    return {"to": to, "type": etype, "conf": conf,
            "provenance": provenance, "justification": justification}
