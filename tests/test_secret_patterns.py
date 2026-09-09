"""Secret-pattern tests.

Gitea 1.22 issues unprefixed 40-character hexadecimal tokens, which are
indistinguishable from commit hashes in isolation. The pattern must therefore
require an adjacent keyword, and must not match bare hex.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.run_secret_scan import SECRET_PATTERNS

HEX40 = "2380190b95c1d4f8e7a6b5c4d3e2f1a09b8c7d6e"


def kinds_matching(text):
    return {kind for kind, pattern in SECRET_PATTERNS if pattern.search(text)}


class TestGiteaTokenPattern(unittest.TestCase):
    def test_matches_a_keyword_qualified_token(self):
        self.assertIn("gitea-token", kinds_matching(f'GITEA_API_TOKEN = "{HEX40}"'))

    def test_matches_common_assignment_spellings(self):
        for line in (f"gitea_token: {HEX40}",
                     f"GITEA_PAT='{HEX40}'",
                     f'gitea_api_key = "{HEX40}"'):
            self.assertIn("gitea-token", kinds_matching(line), line)

    def test_does_not_match_a_bare_hex_value(self):
        """Otherwise every commit hash in a repository becomes a credential."""
        self.assertEqual(kinds_matching(HEX40), set())

    def test_does_not_match_a_commit_hash_in_context(self):
        self.assertEqual(kinds_matching(f"parent commit {HEX40}\n"), set())

    def test_does_not_match_an_unrelated_keyword(self):
        self.assertEqual(kinds_matching(f'GITHUB_TOKEN = "{HEX40}"'), set())

    def test_prefixed_format_still_matches(self):
        self.assertIn("gitea-pat",
                      kinds_matching("gitea_pat_" + "a" * 40))

    def test_aws_canary_still_matches_and_is_a_distinct_kind(self):
        self.assertIn("synthetic-aws-key", kinds_matching("AKIAEXAMPLE000000000"))


if __name__ == "__main__":
    unittest.main()
