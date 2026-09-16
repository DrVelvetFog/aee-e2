"""The whole byte-pure verifier, bytes in and verdict out."""

import json
import unittest

from aee.findings import INVALID, VALID
from aee.jcs import canonicalize
from aee.verify import verify_bytes, verify_statement

from . import fixtures as f


def raw(statement):
    """Canonical bytes for a fixture, so the profile check has real input."""
    return canonicalize(statement)


class TestAcceptance(unittest.TestCase):
    def test_a_clean_artifact_statement_is_valid(self):
        verdict = verify_bytes(raw(f.statement()))
        self.assertEqual(verdict.verdict, VALID)
        self.assertEqual(verdict.result, "pass_indirect")
        self.assertEqual(verdict.findings, ())

    def test_a_substrate_statement_is_valid(self):
        verdict = verify_bytes(raw(f.substrate_statement()))
        self.assertEqual(verdict.verdict, VALID)
        self.assertEqual(verdict.result, "fail")

    def test_the_result_token_travels_with_an_accepted_verdict(self):
        for result, statement in (
            ("pass", f.clean_substrate_statement()),
            ("pass_indirect", f.statement()),
            ("fail", f.statement(rows=[f.row(observed="egress_captured")], result="fail")),
        ):
            with self.subTest(result=result):
                self.assertEqual(verify_bytes(raw(statement)).result, result)

    def test_a_degraded_statement(self):
        env = f.environment(manifest_obj=f.manifest(classes={"CO": ["CO-EXFIL-1"], "XX": ["XX-1"]}))
        statement = f.statement(
            env=env,
            coverage={"assessedClasses": ["CO"], "outOfScope": {"XX": "no vantage"}, "routedElsewhere": {}},
            result="degraded",
        )
        verdict = verify_bytes(raw(statement))
        self.assertEqual(verdict.verdict, VALID)
        self.assertEqual(verdict.result, "degraded")


class TestRefusal(unittest.TestCase):
    def test_a_statement_outside_the_profile_is_invalid(self):
        verdict = verify_bytes(b'{"a":1,"a":2}')
        self.assertEqual(verdict.verdict, INVALID)
        self.assertEqual(verdict.codes, ("ijson-profile",))

    def test_the_profile_check_runs_before_anything_else(self):
        # A statement that is both outside the profile and structurally broken
        # reports only the profile failure: no later step may read its values.
        verdict = verify_bytes(b'{"predicate":{"result":"pass","result":"fail"}}')
        self.assertEqual(verdict.codes, ("ijson-profile",))

    def test_an_invalid_statement_carries_no_result(self):
        verdict = verify_bytes(raw(f.statement(result="pass")))
        self.assertEqual(verdict.verdict, INVALID)
        self.assertIsNone(verdict.result)

    def test_well_formedness_and_coverage_findings_are_both_reported(self):
        statement = f.substrate_statement()
        statement["predicate"]["batchRoot"] = "00" * 32
        statement["predicate"]["issuedAt"] = "nope"
        codes = verify_bytes(raw(statement)).codes
        self.assertIn("wf-timestamp-profile", codes)
        self.assertIn("cv-batch-root", codes)

    def test_not_json_at_all(self):
        self.assertEqual(verify_bytes(b"nonsense").verdict, INVALID)

    def test_empty_input(self):
        self.assertEqual(verify_bytes(b"").verdict, INVALID)


class TestTwoValuedVerdict(unittest.TestCase):
    def test_only_valid_or_invalid_is_ever_emitted(self):
        samples = [
            raw(f.statement()),
            raw(f.substrate_statement()),
            b"{}",
            b"[]",
            b"nonsense",
            raw(f.statement(result="pass")),
        ]
        self.assertEqual(
            {verify_bytes(x).verdict for x in samples}, {VALID, INVALID}
        )


class TestParsedEntryPoint(unittest.TestCase):
    def test_verify_statement_matches_verify_bytes(self):
        statement = f.substrate_statement()
        a = verify_statement(statement)
        b = verify_bytes(raw(statement))
        self.assertEqual((a.verdict, a.result), (b.verdict, b.result))

    def test_a_statement_loaded_with_plain_json_still_verifies(self):
        # The corpus files are read as bytes by the harness, but a caller
        # holding a parsed object gets the same answer.
        statement = json.loads(raw(f.statement()))
        self.assertEqual(verify_statement(statement).verdict, VALID)


if __name__ == "__main__":
    unittest.main()
