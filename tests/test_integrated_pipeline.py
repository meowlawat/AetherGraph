import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.run_manual import generate_manual_jsonl
from collectors.run_nuclei import parse_nuclei
from core.scorer import AetherGraph, enumerate_crosslayer_paths


class TestIntegratedPipeline(unittest.TestCase):
    SERVICES = [{"id": "svc-10.0.0.1-8080", "port": "8080", "ip": "10.0.0.1",
                 "product": "Apache httpd", "service": "http"}]
    #: The analyst reached the testbed on loopback; the scanner saw 10.0.0.1.
    #: Nothing in the evidence establishes that, so it is declared explicitly.
    ALIASES = ["127.0.0.1"]

    def _run_manual(self, finding, services):
        report = {"findings": [finding]}
        with tempfile.TemporaryDirectory() as directory:
            report_path = os.path.join(directory, "report.json")
            output_path = os.path.join(directory, "manual.jsonl")
            with open(report_path, "w", encoding="utf-8") as output:
                json.dump(report, output)
            generate_manual_jsonl(report_path, output_path, services,
                                  host_aliases=self.ALIASES)
            with open(output_path, encoding="utf-8") as output:
                return json.loads(output.readline())

    FINDING = {"id": "MAN-1", "class": "chain", "title": "test", "severity": 0.6,
               "cvss_base": 6.0, "location": "http://127.0.0.1:8080/login.php",
               "evidence_refs": ["x"], "related_credentials": ["cred-git-1"]}

    def test_finding_location_derives_the_validated_service(self):
        record = self._run_manual(dict(self.FINDING), self.SERVICES)
        self.assertEqual(record["attrs"]["origin"], "manual")
        validates = [e for e in record["edges"] if e["type"] == "VALIDATES"]
        self.assertEqual(len(validates), 1)
        self.assertEqual(validates[0]["to"], "svc-10.0.0.1-8080")
        self.assertEqual(validates[0]["provenance"], "derived")

    def test_asserted_correlation_stays_declared(self):
        record = self._run_manual(dict(self.FINDING), self.SERVICES)
        correlates = [e for e in record["edges"] if e["type"] == "CORRELATES"]
        self.assertEqual(len(correlates), 1)
        self.assertEqual(correlates[0]["to"], "cred-git-1")
        self.assertEqual(correlates[0]["provenance"], "declared")

    def test_location_naming_no_observed_service_yields_no_validates_edge(self):
        """A report may name something the scanner never saw. That must not
        silently become an edge."""
        finding = dict(self.FINDING, location="http://127.0.0.1:9999/")
        record = self._run_manual(finding, self.SERVICES)
        self.assertEqual([e for e in record["edges"] if e["type"] == "VALIDATES"], [])

    def test_tri_layer_path_requires_all_origins(self):
        graph = AetherGraph()
        graph.node("manual", origin="manual", severity=0.6)
        graph.node("credential", origin="identity", severity=0.9)
        graph.node("service", origin="active", severity=0.5)
        graph.edge("manual", "credential", "ENABLES_ACCESS", 0.75, "derived", "j")
        graph.edge("credential", "service", "ENABLES_ACCESS", 0.75, "derived", "j")
        paths = enumerate_crosslayer_paths(
            graph, ["manual"], required_layers={"active", "identity", "manual"}
        )
        self.assertEqual(paths[0][1], ["manual", "credential", "service"])

    def test_nuclei_parser_maps_severity(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as output:
            json.dump({"template-id": "test-template", "matched-at": "http://local",
                       "info": {"name": "Test finding", "severity": "high"}}, output)
            output.write("\n")
            nuclei_path = output.name
        try:
            records = parse_nuclei(nuclei_path)
        finally:
            os.unlink(nuclei_path)
        self.assertEqual(records[0]["attrs"]["severity"], 0.75)
        self.assertEqual(records[0]["attrs"]["origin"], "active")


if __name__ == '__main__':
    unittest.main()
