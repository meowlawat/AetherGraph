"""Edge semantics: what a relationship *means*, independent of how confident we
are in it and independent of how it was obtained.

Provenance (core.provenance) answers "how do we know this edge exists?".
Semantics answers "what does this edge assert about the world?". They are
different questions and a graph needs both, because path traversal is only
meaningful over edges whose meaning supports the interpretation being drawn.

The prototype originally traversed every edge type as though it were attacker
movement. That is wrong even when every edge is honest. A chain such as

    cred-web-1 --EXPOSED_BY--> path-80-backup --SERVES_PATH--> svc-80

is three correctly observed facts meaning "this credential was found at that
URL" and "that service serves that path". It does not mean an attacker can move
from the credential to the service, yet the original traversal scored it as a
cross-layer attack path -- and scored it *above* the fabricated 0.914 path.

Five categories, chosen to be mutually exclusive over the current edge set:

CONTAINMENT  Asset structure. "A contains / runs / serves B." Says nothing about
             an attacker, and in this schema points from the contained thing to
             its container, which is the opposite of attacker movement anyway.

EVIDENCE     Lineage. "Fact A was observed at / obtained from location B."
             Records where the pipeline learned something. Not a capability.

VALIDATION   Analyst attestation. "Finding A was confirmed about asset B."
             Evidence that a weakness exists, not a transition into it.

ACCESS       Capability. "Principal or credential A can authenticate to or act
             upon asset B." This is the only category that describes attacker
             movement, and the only one eligible for attack-path traversal.

CORRELATION  Asserted association with no stated mechanism. "A is somehow
             related to B." Never eligible for traversal: an association is not
             a capability, and treating one as a transition is exactly the error
             that produced the original result.
"""

CONTAINMENT = "containment"
EVIDENCE = "evidence"
VALIDATION = "validation"
ACCESS = "access"
CORRELATION = "correlation"

ALL_SEMANTICS = (CONTAINMENT, EVIDENCE, VALIDATION, ACCESS, CORRELATION)

#: Every edge type the pipeline can emit, and what it asserts.
#: A type absent from this table is rejected at load time rather than being
#: given a default, so a new collector cannot quietly introduce an edge whose
#: meaning nobody has decided.
EDGE_SEMANTICS = {
    # Asset structure.
    "HOSTS_SERVICE":      CONTAINMENT,   # service -> host it runs on
    "SERVES_PATH":        CONTAINMENT,   # web path -> service serving it
    # Where a fact was learned.
    "EXPOSED_BY":         EVIDENCE,      # credential/exposure -> location found at
    "IDENTIFIES":         EVIDENCE,      # exposure -> persona it names
    "EXPOSES_CREDENTIAL": EVIDENCE,      # corpus credential -> persona it matches
    # Analyst attestation.
    "VALIDATES":          VALIDATION,    # finding -> asset the analyst tested
    # Capability.
    "OWNS_ACCOUNT":       ACCESS,        # persona -> account it controls
    "ENABLES_ACCESS":     ACCESS,        # credential/account -> service it opens
    # Asserted association, mechanism unstated.
    "CORRELATES":         CORRELATION,   # finding -> some related node
}

#: The only semantics that may be walked when inferring an attack path.
#: Deliberately a single category. Widening this set is a research decision that
#: must be argued for, not a convenience.
ATTACK_TRAVERSABLE = frozenset({ACCESS})

#: Every category, for traversals that deliberately walk the whole evidence
#: graph (for example, reproducing the pre-correction baseline).
ALL_TRAVERSABLE = frozenset(ALL_SEMANTICS)


class UnknownEdgeType(ValueError):
    """Raised when an edge type has no declared semantics."""


def semantics_of(etype):
    """Return the semantic category of `etype`, or raise UnknownEdgeType."""
    try:
        return EDGE_SEMANTICS[etype]
    except KeyError:
        raise UnknownEdgeType(
            f"Edge type {etype!r} has no declared semantics. Add it to "
            f"core.semantics.EDGE_SEMANTICS and decide, explicitly, whether it "
            f"describes attacker movement."
        ) from None


def is_attack_traversable(etype):
    """True when walking this edge type can represent attacker movement."""
    return semantics_of(etype) in ATTACK_TRAVERSABLE
