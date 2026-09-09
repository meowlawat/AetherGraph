"""Tests for evidence-derived edge construction.

The rules under test must emit an edge only when observed evidence justifies it,
and must decline otherwise. Declining is the important half: the previous
implementation hardcoded cross-layer targets, so every run produced the same
edges regardless of what was actually found.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.derive import (derive_account_access, derive_finding_service,
                         derive_repo_service_access,
                         extract_credentials_from_content, parse_exposed_git_config)
from core.provenance import DECLARED, DERIVED, OBSERVED

GITEA_SERVICE = {"id": "svc-10.0.0.1-3000", "port": "3000", "product": "Gitea",
                 "service": "http", "ip": "10.0.0.1"}
FTP_SERVICE = {"id": "svc-10.0.0.1-21", "port": "21", "product": "vsftpd",
               "service": "ftp", "ip": "10.0.0.1"}


class TestRepoServiceAccess(unittest.TestCase):
    """Rule: a repository secret reaches a service only when a remote points at
    that service AND the secret kind can authenticate to its product."""

    def test_emits_edge_when_remote_and_kind_both_match(self):
        edges = derive_repo_service_access(
            secret_kind="gitea-pat",
            remotes=["http://10.0.0.1:3000/c.brown/internal-tools.git"],
            observed_services=[GITEA_SERVICE, FTP_SERVICE],
        )
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["to"], "svc-10.0.0.1-3000")
        self.assertEqual(edges[0]["type"], "ENABLES_ACCESS")
        self.assertEqual(edges[0]["provenance"], DERIVED)
        self.assertIn("3000", edges[0]["justification"])

    def test_declines_when_no_remote(self):
        """The current seed repo has no remote; nothing may be emitted."""
        edges = derive_repo_service_access(
            secret_kind="gitea-pat", remotes=[],
            observed_services=[GITEA_SERVICE],
        )
        self.assertEqual(edges, [])

    def test_declines_when_secret_kind_cannot_authenticate_to_product(self):
        """An AWS key does not authenticate to Gitea, even from the right repo."""
        edges = derive_repo_service_access(
            secret_kind="aws-access-key",
            remotes=["http://10.0.0.1:3000/c.brown/internal-tools.git"],
            observed_services=[GITEA_SERVICE],
        )
        self.assertEqual(edges, [])

    def test_declines_when_remote_port_was_not_observed_open(self):
        edges = derive_repo_service_access(
            secret_kind="gitea-pat",
            remotes=["http://10.0.0.1:9999/c.brown/internal-tools.git"],
            observed_services=[GITEA_SERVICE],
        )
        self.assertEqual(edges, [])

    def test_declines_for_remote_on_a_host_that_was_not_scanned(self):
        edges = derive_repo_service_access(
            secret_kind="gitea-pat",
            remotes=["https://github.com/corp-testbed/internal-tools.git"],
            observed_services=[GITEA_SERVICE],
        )
        self.assertEqual(edges, [])


class TestProductIdentificationEvidence(unittest.TestCase):
    """Product identity may come from the version probe or from the service's
    own self-description. Neither is privileged, and absent both the rule
    declines rather than assuming."""

    #: Nmap reports Gitea only as its underlying server; the http-title script
    #: captures what the service says it is. Both are active-layer observations.
    GITEA_BY_TITLE = {"id": "svc-10.0.0.1-3000", "port": "3000", "ip": "10.0.0.1",
                      "service": "http", "product": "Golang net/http server",
                      "http_title": "Gitea: Git with a cup of tea"}

    def test_derives_when_only_the_observed_title_identifies_the_product(self):
        edges = derive_repo_service_access(
            secret_kind="gitea-token",
            remotes=["http://10.0.0.1:3000/u/r.git"],
            observed_services=[self.GITEA_BY_TITLE])
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["provenance"], DERIVED)
        self.assertIn("observed http title", edges[0]["justification"])
        self.assertIn("Gitea", edges[0]["justification"])

    def test_declines_when_neither_product_nor_title_identifies_it(self):
        service = dict(self.GITEA_BY_TITLE, http_title="Site doesn't have a title")
        self.assertEqual(
            derive_repo_service_access(secret_kind="gitea-token",
                                       remotes=["http://10.0.0.1:3000/u/r.git"],
                                       observed_services=[service]), [])

    def test_declines_when_no_title_was_observed_and_product_is_generic(self):
        service = dict(self.GITEA_BY_TITLE)
        service.pop("http_title")
        self.assertEqual(
            derive_repo_service_access(secret_kind="gitea-token",
                                       remotes=["http://10.0.0.1:3000/u/r.git"],
                                       observed_services=[service]), [])


class TestAccountAccess(unittest.TestCase):
    """Rule: an account on a service requires corroboration that the account
    exists there. A harvested email alone is not corroboration."""

    def test_declines_without_corroboration(self):
        nodes, edges = derive_account_access(
            username="c.brown", observed_services=[FTP_SERVICE], corroborations=[])
        self.assertEqual(nodes, [])
        self.assertEqual(edges, [])

    def test_emits_when_username_appears_in_observed_service_content(self):
        nodes, edges = derive_account_access(
            username="admin", observed_services=[FTP_SERVICE],
            corroborations=[{"service_id": "svc-10.0.0.1-21", "username": "admin",
                             "source": "http://10.0.0.1/backup/secret.txt"}])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["attrs"]["username"], "admin")
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["provenance"], DERIVED)
        self.assertIn("secret.txt", edges[0]["justification"])

    def test_declines_when_corroboration_names_a_different_service(self):
        nodes, edges = derive_account_access(
            username="admin", observed_services=[FTP_SERVICE],
            corroborations=[{"service_id": "svc-10.0.0.1-3000", "username": "admin",
                             "source": "somewhere"}])
        self.assertEqual(nodes, [])
        self.assertEqual(edges, [])


class TestFindingServiceMatching(unittest.TestCase):
    """Rule: a finding attaches to the service the analyst recorded testing, and
    the host equivalence must be declared rather than assumed from the port."""

    SERVICES = [dict(GITEA_SERVICE), dict(FTP_SERVICE)]

    def test_matches_when_host_is_identical(self):
        edges = derive_finding_service("ftp://10.0.0.1:21", self.SERVICES)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["to"], "svc-10.0.0.1-21")
        self.assertEqual(edges[0]["provenance"], DERIVED)

    def test_declines_when_host_differs_and_no_alias_is_declared(self):
        """Port agreement alone is not evidence. An earlier revision matched on
        port only, so any service on 21 anywhere would have matched."""
        declines = []
        edges = derive_finding_service("ftp://127.0.0.1:21", self.SERVICES,
                                       declines=declines)
        self.assertEqual(edges, [])
        self.assertIn("no alias declared", declines[0])

    def test_matches_when_the_alias_is_declared(self):
        edges = derive_finding_service("ftp://127.0.0.1:21", self.SERVICES,
                                       host_aliases=["127.0.0.1"])
        self.assertEqual(len(edges), 1)
        self.assertIn("declared an alias", edges[0]["justification"])

    def test_declines_when_the_port_was_never_observed(self):
        declines = []
        self.assertEqual(
            derive_finding_service("http://10.0.0.1:9999/", self.SERVICES,
                                   declines=declines), [])
        self.assertIn("no observed service on port 9999", declines[0])

    def test_declines_when_the_match_is_ambiguous(self):
        """Two hosts both running port 21: attaching to either would be a guess."""
        services = self.SERVICES + [{"id": "svc-10.0.0.2-21", "port": "21",
                                     "ip": "10.0.0.2", "product": "vsftpd",
                                     "service": "ftp"}]
        declines = []
        edges = derive_finding_service("ftp://127.0.0.1:21", services,
                                       host_aliases=["127.0.0.1"], declines=declines)
        self.assertEqual(edges, [])
        self.assertIn("ambiguous", declines[0])

    def test_declines_on_a_scheme_with_no_port_and_no_default(self):
        declines = []
        self.assertEqual(
            derive_finding_service("ldap://10.0.0.1/", self.SERVICES,
                                   declines=declines), [])
        self.assertTrue(declines)


class TestCredentialExtraction(unittest.TestCase):
    """Rule: credentials found in fetched content are observed, not inferred."""

    def test_extracts_user_and_pass_pairs(self):
        found = extract_credentials_from_content(
            "Database credentials:\nUSER=admin\nPASS=super_secret_password_123\n",
            source="http://10.0.0.1/backup/secret.txt")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["username"], "admin")
        self.assertEqual(found[0]["provenance"], OBSERVED)
        self.assertEqual(found[0]["source"], "http://10.0.0.1/backup/secret.txt")

    def test_does_not_store_the_password_value(self):
        """Records reference the exposure, not the secret material."""
        found = extract_credentials_from_content(
            "USER=admin\nPASS=super_secret_password_123\n", source="x")
        self.assertNotIn("super_secret_password_123", repr(found))

    def test_returns_nothing_for_unrelated_content(self):
        self.assertEqual(extract_credentials_from_content("<html>hello</html>", "x"), [])


class TestExposedGitConfig(unittest.TestCase):
    """Rule: an exposed .git/config is observed evidence tying a persona to a repo."""

    CONFIG = """[core]
\trepositoryformatversion = 0
[remote "origin"]
\turl = https://github.com/corp-testbed/internal-tools.git
[user]
\temail = c.brown@corp-testbed.local
\tname = Charlie Brown
"""

    def test_parses_email_and_remote(self):
        parsed = parse_exposed_git_config(self.CONFIG)
        self.assertEqual(parsed["email"], "c.brown@corp-testbed.local")
        self.assertEqual(parsed["remote"], "https://github.com/corp-testbed/internal-tools.git")
        self.assertEqual(parsed["repo_name"], "internal-tools")

    def test_returns_empty_for_non_config_content(self):
        self.assertEqual(parse_exposed_git_config("<html>404</html>"), {})


class TestProvenanceVocabulary(unittest.TestCase):
    def test_three_distinct_levels(self):
        self.assertEqual(len({OBSERVED, DERIVED, DECLARED}), 3)


if __name__ == "__main__":
    unittest.main()
