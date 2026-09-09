"""Scoring and traversal tests.

These verify that the implementation matches the equations stated in the paper,
that structural nodes without a severity are handled rather than crashing, and
that attack-path traversal walks only edges whose semantics describe attacker
movement.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.provenance import DERIVED, OBSERVED
from core.scorer import (AetherGraph, calculate_criticality,
                         enumerate_crosslayer_paths, severity_of)
from core.semantics import ALL_TRAVERSABLE


def access_chain():
    """persona -> account -> service: two ACCESS edges, a real capability chain."""
    g = AetherGraph()
    g.node("persona-1", type="Persona", origin="identity")
    g.node("account-p1-ftp", type="Account", severity=0.3, origin="identity")
    g.node("svc-1-21", type="Service", severity=0.53, asset_class="dmz-web", origin="active")
    g.edge("persona-1", "account-p1-ftp", "OWNS_ACCOUNT", 0.75, DERIVED, "j")
    g.edge("account-p1-ftp", "svc-1-21", "ENABLES_ACCESS", 0.80, DERIVED, "j")
    return g


class TestSeverityHandling(unittest.TestCase):
    def test_absent_severity_is_zero(self):
        self.assertEqual(severity_of({"type": "Host"}), 0.0)

    def test_explicitly_null_severity_is_zero_not_a_crash(self):
        """A collector emitting "severity": null must not take the scorer down."""
        self.assertEqual(severity_of({"severity": None}), 0.0)

    def test_null_severity_survives_scoring_end_to_end(self):
        g = AetherGraph()
        g.node("a", origin="identity", severity=None)
        g.node("b", origin="active", severity=0.5)
        g.edge("a", "b", "ENABLES_ACCESS", 0.9, OBSERVED)
        calculate_criticality(g, ["a"], ["b"])
        paths = enumerate_crosslayer_paths(g, ["a"], required_layers={"active", "identity"})
        self.assertEqual(len(paths), 1)
        # conf 0.9 * severity sum 0.5 * 0.95^1
        self.assertAlmostEqual(paths[0][0], round(0.9 * 0.5 * 0.95, 3), places=3)


class TestCriticality(unittest.TestCase):
    def test_matches_the_published_equation(self):
        """CR = .40S + .25R + .25B + .10A, checked by hand on one node."""
        g = access_chain()
        calculate_criticality(g, entries=["persona-1"], jewels=["svc-1-21"])
        cr = g.g.nodes["account-p1-ftp"]["CR"]
        # S=0.3; R: distance 1 from persona-1 -> 1/(1+1)=0.5;
        # B: reaches svc-1-21, the only jewel -> 1.0; A: no asset_class -> 0.1
        expected = round(0.40 * 0.3 + 0.25 * 0.5 + 0.25 * 1.0 + 0.10 * 0.1, 3)
        self.assertEqual(cr, expected)

    def test_unreachable_node_gets_the_distance_99_floor(self):
        g = access_chain()
        g.node("island", type="Host", origin="active")
        calculate_criticality(g, entries=["persona-1"], jewels=["svc-1-21"])
        # R = 1/(1+99) = 0.01, B = 0, S = 0, A = 0.1
        self.assertEqual(g.g.nodes["island"]["CR"],
                         round(0.25 * 0.01 + 0.10 * 0.1, 3))


class TestAttackTraversalSemantics(unittest.TestCase):
    """Only ACCESS edges may be walked as attacker movement."""

    def test_access_chain_is_traversed(self):
        g = access_chain()
        paths = enumerate_crosslayer_paths(
            g, ["persona-1"], required_layers={"active", "identity"})
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0][1], ["persona-1", "account-p1-ftp", "svc-1-21"])

    def test_evidence_and_containment_edges_are_not_attacker_movement(self):
        """The exact shape the corrected graph contains. Every edge is honest and
        observed; none of them means an attacker can move. Under the original
        traversal this scored 1.354, above the fabricated 0.914 path."""
        g = AetherGraph()
        g.node("cred-web-1", type="Credential", severity=0.7, origin="identity")
        g.node("path-80-backup", type="WebPath", severity=0.5, origin="active")
        g.node("svc-80", type="Service", severity=0.3, origin="active")
        g.edge("cred-web-1", "path-80-backup", "EXPOSED_BY", 1.0, OBSERVED)
        g.edge("path-80-backup", "svc-80", "SERVES_PATH", 1.0, OBSERVED)

        attack = enumerate_crosslayer_paths(
            g, ["cred-web-1"], required_layers={"active", "identity"})
        self.assertEqual(attack, [], "evidence/containment edges must not be walked")

        # The same graph still has evidence-graph connectivity, which is a
        # legitimate but different question.
        evidence = enumerate_crosslayer_paths(
            g, ["cred-web-1"], required_layers={"active", "identity"},
            traversable_semantics=ALL_TRAVERSABLE)
        self.assertGreater(len(evidence), 0)

    def test_asserted_correlation_is_never_attacker_movement(self):
        """CORRELATES states an association with no mechanism. Treating it as a
        transition is what produced the original 0.914 path."""
        g = AetherGraph()
        g.node("finding-1", type="Finding", severity=0.6, origin="manual")
        g.node("cred-git-1", type="Credential", severity=0.9, origin="identity")
        g.node("svc-3000", type="Service", severity=0.3, origin="active")
        g.edge("finding-1", "cred-git-1", "CORRELATES", 0.75, "declared")
        g.edge("cred-git-1", "svc-3000", "ENABLES_ACCESS", 0.75, DERIVED, "j")
        paths = enumerate_crosslayer_paths(
            g, ["finding-1"], required_layers={"active", "identity", "manual"})
        self.assertEqual(paths, [])

    def test_confidence_floor_still_applies(self):
        g = access_chain()
        g.g.edges["account-p1-ftp", "svc-1-21"]["conf"] = 0.5
        self.assertEqual(
            enumerate_crosslayer_paths(g, ["persona-1"],
                                       required_layers={"active", "identity"}), [])

    def test_maxlen_counts_nodes(self):
        g = access_chain()
        self.assertEqual(
            enumerate_crosslayer_paths(g, ["persona-1"], maxlen=2,
                                       required_layers={"active", "identity"}), [])
        self.assertEqual(
            len(enumerate_crosslayer_paths(g, ["persona-1"], maxlen=3,
                                           required_layers={"active", "identity"})), 1)


if __name__ == "__main__":
    unittest.main()
