"""Ground-truth regression tests against testbed/seed_manifest.json.

These run over the recorded corrected artifacts, so they fail if a future change
reintroduces a fabricated relationship or drops an expected one. The two
forbidden patterns are the specific defects that produced the original result;
they are permanent regression tests, not one-off checks.

Recall here means "recovers what we planted in a testbed we built". It is not a
detection-performance estimate and must not be reported as one.
"""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.run_ablation import STREAMS, check_manifest

RUN_DIR = os.path.join(ROOT, "out", "derived_experiment_20260908")
MANIFEST = os.path.join(ROOT, "testbed", "seed_manifest.json")


def load_records(run_dir):
    records = []
    for _, filename in STREAMS:
        path = os.path.join(run_dir, filename)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as stream:
                records.extend(json.loads(l) for l in stream if l.strip())
    return records


@unittest.skipUnless(os.path.isdir(RUN_DIR), "recorded corrected run not present")
class TestSeedManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.found, cls.missing, cls.violations = check_manifest(RUN_DIR, MANIFEST)
        cls.records = load_records(RUN_DIR)
        with open(MANIFEST, encoding="utf-8") as stream:
            cls.manifest = json.load(stream)

    def test_no_forbidden_relationship_is_present(self):
        self.assertEqual(self.violations, [],
                         f"fabricated relationship reintroduced: {self.violations}")

    def test_hardcoded_secret_to_gitea_target_cannot_return(self):
        """run_secret_scan.py once emitted svc-{ip}-3000 for every repo secret."""
        for record in self.records:
            if record["id"].startswith("cred-git-"):
                for e in record.get("edges", []):
                    self.assertFalse(str(e["to"]).endswith("-3000"),
                                     f"{record['id']} -> {e['to']} is the hardcoded target")

    def test_arbitrary_credential_gets_no_automatic_service_access(self):
        """The AWS canary has no remote and no compatible product: it must be an
        isolated node, not a node with an invented capability."""
        canaries = [r for r in self.records if r["id"].startswith("cred-git-")]
        self.assertTrue(canaries, "expected the recorded canary credential")
        for record in canaries:
            self.assertEqual(record["edges"], [],
                             f"{record['id']} acquired an unjustified relationship")

    def test_harvested_identity_creates_no_ftp_account(self):
        """run_identity.py once created account-{user}-ftp for every email, on a
        container provisioned FTP_USER=test."""
        for record in self.records:
            self.assertFalse(record["id"].startswith("account-c.brown"),
                             f"fabricated account node {record['id']} is back")

    def test_expected_links_are_recovered(self):
        self.assertEqual(self.missing, [], f"expected links not recovered: {self.missing}")

    def test_every_expected_link_has_its_required_provenance(self):
        by_id = {e["id"]: e for e in self.manifest["expected_links"]}
        self.assertEqual(len(self.found), len(by_id))
        for name, detail in self.found:
            self.assertIsNotNone(detail, f"{name} matched nothing concrete")

    def test_declared_edges_remain_declared(self):
        """The analyst's asserted correlation must not drift to derived."""
        declared = [(r["id"], e) for r in self.records for e in r.get("edges", [])
                    if e["type"] == "CORRELATES"]
        self.assertTrue(declared, "expected the analyst's declared correlation")
        for node, e in declared:
            self.assertEqual(e["provenance"], "declared",
                             f"{node} -> {e['to']} was promoted out of declared")

    def test_every_edge_carries_provenance(self):
        for record in self.records:
            for e in record.get("edges", []):
                self.assertIn("provenance", e, f"{record['id']} -> {e['to']} has none")

    def test_every_derived_edge_carries_a_justification(self):
        for record in self.records:
            for e in record.get("edges", []):
                if e.get("provenance") == "derived":
                    self.assertTrue(e.get("justification"),
                                    f"{record['id']} -> {e['to']} is derived with no reason")

    def test_no_password_material_is_persisted(self):
        """The testbed plants a known plaintext password behind /backup."""
        blob = json.dumps(self.records)
        self.assertNotIn("super_secret_password_123", blob)
        for record in self.records:
            self.assertNotIn("password", {k.lower() for k in record["attrs"]}
                             - {"secret_kind"})

    def test_every_edge_endpoint_exists_in_the_recorded_run(self):
        """No stream may reference a node no collector emitted."""
        ids = {r["id"] for r in self.records}
        for record in self.records:
            for e in record.get("edges", []):
                self.assertIn(e["to"], ids,
                              f"{record['id']} -> {e['to']} is a dangling endpoint")


if __name__ == "__main__":
    unittest.main()
