"""Graph construction integrity.

Regression tests for the failure modes that let the original result stand:
edges to nodes nobody emitted, edges with no provenance, edge types whose
meaning was never decided, and provenance filtering that silently promotes
asserted relationships to discovered ones.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.provenance import DECLARED, DERIVED, MODES, OBSERVED, edge
from core.scorer import AetherGraph, MissingEndpoint, load_records
from core.semantics import UnknownEdgeType, is_attack_traversable, semantics_of


def write_stream(directory, name, records):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as out:
        for record in records:
            out.write(json.dumps(record) + "\n")
    return path


class TestPhantomNodes(unittest.TestCase):
    def test_edge_to_unemitted_node_is_rejected(self):
        g = AetherGraph()
        g.node("exposure-x", type="Exposure", origin="active")
        with self.assertRaises(MissingEndpoint):
            g.edge("exposure-x", "persona-ghost", "IDENTIFIES", 0.9, DERIVED, "j")
        self.assertNotIn("persona-ghost", g.g)

    def test_loader_rejects_dangling_edge_and_names_the_stream(self):
        record = {"id": "exposure-x", "attrs": {"type": "Exposure", "origin": "active"},
                  "edges": [edge("persona-ghost", "IDENTIFIES", 0.9, DERIVED, "j")]}
        with tempfile.TemporaryDirectory() as d:
            path = write_stream(d, "real_web.jsonl", [record])
            g = AetherGraph()
            with self.assertRaises(MissingEndpoint) as ctx:
                load_records(g, [path])
            self.assertIn("persona-ghost", str(ctx.exception))
            self.assertIn("real_web.jsonl", str(ctx.exception))

    def test_forward_reference_across_streams_is_legal(self):
        """Collector order must not matter: all nodes load before any edge."""
        web = {"id": "exposure-x", "attrs": {"type": "Exposure", "origin": "active"},
               "edges": [edge("persona-c.brown", "IDENTIFIES", 0.9, DERIVED, "j")]}
        identity = {"id": "persona-c.brown",
                    "attrs": {"type": "Persona", "origin": "identity"}, "edges": []}
        with tempfile.TemporaryDirectory() as d:
            a = write_stream(d, "real_web.jsonl", [web])
            b = write_stream(d, "real_identity.jsonl", [identity])
            g = AetherGraph()
            load_records(g, [a, b])          # web listed first, persona defined later
            self.assertTrue(g.g.has_edge("exposure-x", "persona-c.brown"))

    def test_no_attribute_less_node_can_exist_after_a_clean_load(self):
        web = {"id": "exposure-x", "attrs": {"type": "Exposure", "origin": "active"},
               "edges": [edge("persona-c.brown", "IDENTIFIES", 0.9, DERIVED, "j")]}
        identity = {"id": "persona-c.brown",
                    "attrs": {"type": "Persona", "origin": "identity"}, "edges": []}
        with tempfile.TemporaryDirectory() as d:
            paths = [write_stream(d, "a.jsonl", [web]),
                     write_stream(d, "b.jsonl", [identity])]
            g = AetherGraph()
            load_records(g, paths)
            for node, attrs in g.g.nodes(data=True):
                self.assertTrue(attrs, f"{node} has no attributes")
                self.assertIn("type", attrs)


class TestProvenanceIsMandatory(unittest.TestCase):
    def test_edge_without_provenance_is_a_type_error(self):
        g = AetherGraph()
        g.node("a", type="X", origin="active")
        g.node("b", type="Y", origin="active")
        with self.assertRaises(TypeError):
            g.edge("a", "b", "ENABLES_ACCESS", 1.0)      # provenance omitted

    def test_unknown_provenance_is_rejected(self):
        g = AetherGraph()
        g.node("a", type="X", origin="active")
        g.node("b", type="Y", origin="active")
        with self.assertRaises(ValueError):
            g.edge("a", "b", "ENABLES_ACCESS", 1.0, "guessed")

    def test_derived_edge_without_justification_is_rejected(self):
        with self.assertRaises(ValueError):
            edge("svc-1", "ENABLES_ACCESS", 0.75, DERIVED)

    def test_legacy_edge_without_provenance_loads_as_declared_not_observed(self):
        """A pre-provenance stream must not be promoted to discovered."""
        record = {"id": "a", "attrs": {"type": "X", "origin": "identity"},
                  "edges": [{"to": "b", "type": "ENABLES_ACCESS", "conf": 0.8}]}
        other = {"id": "b", "attrs": {"type": "Y", "origin": "active"}, "edges": []}
        with tempfile.TemporaryDirectory() as d:
            path = write_stream(d, "legacy.jsonl", [record, other])
            g = AetherGraph()
            load_records(g, [path])
            self.assertEqual(g.g.edges["a", "b"]["provenance"], DECLARED)


class TestProvenanceFiltering(unittest.TestCase):
    RECORDS = [
        {"id": "a", "attrs": {"type": "Persona", "origin": "identity"},
         "edges": [edge("b", "OWNS_ACCOUNT", 0.8, OBSERVED)]},
        {"id": "b", "attrs": {"type": "Account", "origin": "identity"},
         "edges": [edge("c", "ENABLES_ACCESS", 0.8, DERIVED, "j")]},
        {"id": "c", "attrs": {"type": "Service", "origin": "active"},
         "edges": [edge("d", "CORRELATES", 0.8, DECLARED)]},
        {"id": "d", "attrs": {"type": "Credential", "origin": "identity"}, "edges": []},
    ]

    def _edges_for(self, mode):
        with tempfile.TemporaryDirectory() as d:
            path = write_stream(d, "s.jsonl", self.RECORDS)
            g = AetherGraph()
            load_records(g, [path], allowed_provenances=MODES[mode])
            return g.g.number_of_edges(), g.g.number_of_nodes()

    def test_observed_only_admits_one_edge(self):
        self.assertEqual(self._edges_for("observed-only")[0], 1)

    def test_derived_mode_adds_the_derived_edge(self):
        self.assertEqual(self._edges_for("derived")[0], 2)

    def test_all_mode_adds_the_declared_edge(self):
        self.assertEqual(self._edges_for("all")[0], 3)

    def test_nodes_are_never_filtered_only_edges(self):
        for mode in ("observed-only", "derived", "all"):
            self.assertEqual(self._edges_for(mode)[1], 4,
                             f"{mode} dropped a node; filtering must not delete evidence")


class TestEdgeSemantics(unittest.TestCase):
    def test_every_emitted_edge_type_has_declared_semantics(self):
        for etype in ("HOSTS_SERVICE", "SERVES_PATH", "EXPOSED_BY", "IDENTIFIES",
                      "EXPOSES_CREDENTIAL", "VALIDATES", "OWNS_ACCOUNT",
                      "ENABLES_ACCESS", "CORRELATES"):
            self.assertIsNotNone(semantics_of(etype))

    def test_undeclared_edge_type_is_rejected_not_defaulted(self):
        with self.assertRaises(UnknownEdgeType):
            semantics_of("TOTALLY_NEW_RELATION")

    def test_only_access_edges_are_attack_traversable(self):
        self.assertTrue(is_attack_traversable("ENABLES_ACCESS"))
        self.assertTrue(is_attack_traversable("OWNS_ACCOUNT"))
        for etype in ("HOSTS_SERVICE", "SERVES_PATH", "EXPOSED_BY",
                      "IDENTIFIES", "EXPOSES_CREDENTIAL", "VALIDATES", "CORRELATES"):
            self.assertFalse(is_attack_traversable(etype),
                             f"{etype} must not count as attacker movement")


if __name__ == "__main__":
    unittest.main()
