"""Statement well-formedness, one mutation per rule."""

import unittest

from aee.bindings import vocabulary_digest
from aee.wellformed import check_wellformed

from . import fixtures as f


def codes(statement):
    return [finding.code for finding in check_wellformed(statement)]


class TestTheFixtureIsValid(unittest.TestCase):
    def test_a_clean_artifact_statement_has_no_findings(self):
        self.assertEqual(check_wellformed(f.statement()), [])

    def test_a_substrate_statement_has_no_findings(self):
        statement = f.statement(
            rows=[f.row(basis="substrate", observation_refs_unused=None)],
            result="pass",
        )
        del statement["predicate"]["attackResults"][0]["observation_refs_unused"]
        self.assertEqual(check_wellformed(statement), [])

    def test_a_caught_statement_has_no_findings(self):
        statement = f.statement(
            rows=[f.row(observed="egress_captured")], result="fail"
        )
        self.assertEqual(check_wellformed(statement), [])


class TestStatementShape(unittest.TestCase):
    def test_not_an_object(self):
        self.assertEqual(codes("statement"), ["wf-statement-shape"])

    def test_wrong_statement_type(self):
        self.assertIn("wf-statement-type", codes(f.mutate(f.statement(), ("_type",), "x")))

    def test_wrong_predicate_type(self):
        self.assertIn(
            "wf-predicate-type", codes(f.mutate(f.statement(), ("predicateType",), "x"))
        )

    def test_absent_subject(self):
        self.assertIn("wf-subject", codes(f.drop(f.statement(), ("subject",))))

    def test_empty_subject(self):
        self.assertIn("wf-subject", codes(f.mutate(f.statement(), ("subject",), [])))

    def test_subject_digest_not_hex(self):
        bad = f.mutate(f.statement(), ("subject", 0, "digest", "sha256"), "nope")
        self.assertIn("wf-subject", codes(bad))

    def test_absent_predicate(self):
        self.assertIn("wf-missing-member", codes(f.drop(f.statement(), ("predicate",))))


class TestVocabularyRules(unittest.TestCase):
    def vocabulary(self, labels, caught):
        env = f.environment(labels=labels, caught=caught)
        return f.statement(env=env, rows=[f.row(observed=labels[0])] if labels else [])

    def test_unsorted_labels(self):
        env = f.environment()
        env["observationVocabulary"]["labels"] = ["no_egress", "egress_captured"]
        env["observationVocabulary"]["digest"]["sha256"] = vocabulary_digest(
            ["no_egress", "egress_captured"], f.CAUGHT
        )
        self.assertIn("wf-array-order", codes(f.statement(env=env)))

    def test_duplicate_label(self):
        labels = ["egress_captured", "egress_captured", "no_egress"]
        env = f.environment(labels=labels)
        self.assertIn("wf-array-duplicate", codes(f.statement(env=env)))

    def test_supplementary_plane_label(self):
        labels = ["no_egress", "\U0001d400"]
        env = f.environment(labels=labels, caught=[])
        self.assertIn("wf-vocabulary-bmp", codes(f.statement(env=env)))

    def test_caught_not_a_subset(self):
        env = f.environment(labels=["no_egress"], caught=["tripped"])
        self.assertIn("wf-caught-subset", codes(f.statement(env=env)))

    def test_vocabulary_digest_mismatch(self):
        statement = f.statement()
        bad = f.mutate(
            statement,
            ("predicate", "observationEnvironment", "observationVocabulary", "digest", "sha256"),
            f.HEX % 9,
        )
        self.assertIn("wf-vocabulary-digest", codes(bad))

    def test_labels_absent(self):
        env = f.environment()
        del env["observationVocabulary"]["labels"]
        self.assertIn("wf-vocabulary-shape", codes(f.statement(env=env)))


class TestPosture(unittest.TestCase):
    def test_unregistered_posture(self):
        env = f.environment(posture="wide_open")
        self.assertIn("wf-posture-vocabulary", codes(f.statement(env=env)))

    def test_every_registered_posture_is_accepted(self):
        for posture in ("allowlist", "no_network", "sinkhole", "unsafe_bypass_egress"):
            with self.subTest(posture=posture):
                env = f.environment(posture=posture)
                self.assertEqual(check_wellformed(f.statement(env=env)), [])

    def test_absent_posture(self):
        env = f.environment()
        del env["networkPosture"]["posture"]
        self.assertIn("wf-posture-vocabulary", codes(f.statement(env=env)))


class TestManifest(unittest.TestCase):
    def test_zero_attack_identifiers(self):
        env = f.environment(manifest_obj=f.manifest(classes={}))
        statement = f.statement(env=env, rows=[], coverage={"assessedClasses": [], "outOfScope": {}, "routedElsewhere": {}}, result="pass")
        self.assertIn("wf-manifest-floor", codes(statement))

    def test_a_named_class_with_an_empty_array_is_also_zero(self):
        # The floor is phrased over identifiers, so this shape is caught too.
        env = f.environment(manifest_obj=f.manifest(classes={"CO": []}))
        statement = f.statement(
            env=env,
            rows=[],
            coverage={"assessedClasses": ["CO"], "outOfScope": {}, "routedElsewhere": {}},
            result="pass",
        )
        self.assertIn("wf-manifest-floor", codes(statement))

    def test_attack_under_two_classes(self):
        env = f.environment(
            manifest_obj=f.manifest(classes={"CO": ["A"], "XX": ["A"]})
        )
        statement = f.statement(
            env=env,
            rows=[f.row(attack_id="A")],
            coverage={"assessedClasses": ["CO", "XX"], "outOfScope": {}, "routedElsewhere": {}},
        )
        self.assertIn("wf-manifest-class-overlap", codes(statement))

    def test_corpus_digest_mismatch(self):
        bad = f.mutate(
            f.statement(),
            ("predicate", "observationEnvironment", "corpus", "digest", "sha256"),
            f.HEX % 9,
        )
        self.assertIn("wf-corpus-digest", codes(bad))


class TestExpectedPayloads(unittest.TestCase):
    def build(self, expected):
        env = f.environment(
            manifest_obj=f.manifest(expected_payloads=expected)
        )
        return f.statement(env=env)

    def test_a_well_formed_map_is_accepted(self):
        self.assertEqual(check_wellformed(self.build({"CO-EXFIL-1": ["ab" * 32]})), [])

    def test_undeclared_attack_id(self):
        self.assertIn(
            "wf-expected-payloads", codes(self.build({"NOT-DECLARED": ["ab" * 32]}))
        )

    def test_empty_array(self):
        self.assertIn("wf-expected-payloads", codes(self.build({"CO-EXFIL-1": []})))

    def test_uppercase_hex(self):
        self.assertIn(
            "wf-expected-payloads", codes(self.build({"CO-EXFIL-1": ["AB" * 32]}))
        )

    def test_wrong_length(self):
        self.assertIn("wf-expected-payloads", codes(self.build({"CO-EXFIL-1": ["ab"]})))

    def test_unsorted_array(self):
        self.assertIn(
            "wf-array-order", codes(self.build({"CO-EXFIL-1": ["bb" * 32, "aa" * 32]}))
        )

    def test_duplicate_entry(self):
        self.assertIn(
            "wf-array-duplicate",
            codes(self.build({"CO-EXFIL-1": ["ab" * 32, "ab" * 32]})),
        )


class TestRows(unittest.TestCase):
    def test_missing_required_member(self):
        for member in ("attackId", "containmentObserved", "basis", "method", "attribution", "actualLayer"):
            r = f.row()
            del r[member]
            with self.subTest(member=member):
                self.assertIn("wf-row-member", codes(f.statement(rows=[r], result="fail")))

    def test_out_of_vocabulary_axis(self):
        statement = f.statement(rows=[f.row(basis="hearsay")], result="fail")
        self.assertIn("wf-row-vocabulary", codes(statement))

    def test_duplicate_attack_id(self):
        statement = f.statement(rows=[f.row(), f.row()])
        self.assertIn("wf-duplicate-attack-id", codes(statement))

    def test_undeclared_attack_id(self):
        statement = f.statement(rows=[f.row(attack_id="CO-OTHER")])
        self.assertIn("wf-unknown-attack-id", codes(statement))

    def test_clean_row_must_say_none(self):
        statement = f.statement(rows=[f.row(actual_layer="policy.egress_sinkhole")])
        self.assertIn("wf-clean-row-actual-layer", codes(statement))

    def test_caught_row_may_say_none(self):
        statement = f.statement(
            rows=[f.row(observed="egress_captured", actual_layer="none")], result="fail"
        )
        self.assertEqual(check_wellformed(statement), [])


class TestObservationRefs(unittest.TestCase):
    def build(self, refs, record_count=1):
        records = [f.record() for _ in range(record_count)]
        return f.statement(
            rows=[f.row(observationRefs=refs)],
            records=records,
            batch_root=f.HEX % 8,
        )

    def test_in_range_index(self):
        self.assertEqual(check_wellformed(self.build([0])), [])

    def test_out_of_range_index(self):
        self.assertIn("wf-observation-ref-range", codes(self.build([1])))

    def test_negative_index(self):
        self.assertIn("wf-observation-ref-range", codes(self.build([-1])))

    def test_index_with_no_records_at_all(self):
        statement = f.statement(rows=[f.row(observationRefs=[0])])
        self.assertIn("wf-observation-ref-range", codes(statement))

    def test_boolean_is_not_an_index(self):
        # bool subclasses int; True must not pass as index 1.
        self.assertIn("wf-observation-ref-range", codes(self.build([True], 2)))

    def test_non_array(self):
        statement = f.statement(rows=[f.row(observationRefs=0)], records=[f.record()], batch_root=f.HEX % 8)
        self.assertIn("wf-observation-refs", codes(statement))


class TestCoverage(unittest.TestCase):
    def test_class_in_two_sets(self):
        coverage = {"assessedClasses": ["CO"], "outOfScope": {"CO": "gap"}, "routedElsewhere": {}}
        statement = f.statement(coverage=coverage, result="degraded")
        self.assertIn("wf-coverage-partition", codes(statement))

    def test_manifest_class_in_no_set(self):
        env = f.environment(manifest_obj=f.manifest(classes={"CO": ["CO-EXFIL-1"], "XX": ["XX-1"]}))
        coverage = {"assessedClasses": ["CO"], "outOfScope": {}, "routedElsewhere": {}}
        statement = f.statement(env=env, coverage=coverage)
        self.assertIn("wf-coverage-partition", codes(statement))

    def test_a_disclosed_gap_is_a_move_not_a_copy(self):
        env = f.environment(manifest_obj=f.manifest(classes={"CO": ["CO-EXFIL-1"], "XX": ["XX-1"]}))
        coverage = {"assessedClasses": ["CO"], "outOfScope": {"XX": "no vantage"}, "routedElsewhere": {}}
        statement = f.statement(env=env, coverage=coverage, result="degraded")
        self.assertEqual(check_wellformed(statement), [])

    def test_a_row_omitted_inside_an_assessed_class(self):
        env = f.environment(manifest_obj=f.manifest(classes={"CO": ["CO-EXFIL-1", "CO-EXFIL-2"]}))
        statement = f.statement(env=env, rows=[f.row(attack_id="CO-EXFIL-1")])
        self.assertIn("wf-coverage-integrity", codes(statement))

    def test_a_row_for_an_unassessed_class(self):
        env = f.environment(manifest_obj=f.manifest(classes={"CO": ["CO-EXFIL-1"], "XX": ["XX-1"]}))
        coverage = {"assessedClasses": ["CO"], "outOfScope": {"XX": "no vantage"}, "routedElsewhere": {}}
        statement = f.statement(
            env=env,
            coverage=coverage,
            rows=[f.row(), f.row(attack_id="XX-1")],
            result="degraded",
        )
        self.assertIn("wf-coverage-integrity", codes(statement))


class TestRunEntropy(unittest.TestCase):
    def test_required_when_a_row_is_substrate(self):
        env = f.environment(run_entropy=False)
        statement = f.statement(env=env, rows=[f.row(basis="substrate")], result="pass")
        self.assertIn("wf-run-entropy", codes(statement))

    def test_not_required_when_no_row_is_substrate(self):
        env = f.environment(run_entropy=False)
        self.assertEqual(check_wellformed(f.statement(env=env)), [])


class TestTimestamp(unittest.TestCase):
    def test_absent(self):
        statement = f.drop(f.statement(), ("predicate", "issuedAt"))
        self.assertIn("wf-timestamp-profile", codes(statement))

    def test_lowercase_separators_are_outside_the_profile(self):
        for bad in ("2026-06-23t16:08:07Z", "2026-06-23T16:08:07z"):
            with self.subTest(value=bad):
                statement = f.statement(issued_at=bad)
                self.assertIn("wf-timestamp-profile", codes(statement))

    def test_non_zero_offset(self):
        statement = f.statement(issued_at="2026-06-23T16:08:07+05:00")
        self.assertIn("wf-timestamp-profile", codes(statement))

    def test_admitted_zone_forms(self):
        for good in ("2026-06-23T16:08:07Z", "2026-06-23T16:08:07+00:00", "2026-06-23T16:08:07-00:00"):
            with self.subTest(value=good):
                self.assertEqual(check_wellformed(f.statement(issued_at=good)), [])

    def test_fractional_seconds(self):
        self.assertEqual(check_wellformed(f.statement(issued_at="2026-06-23T16:08:07.125Z")), [])

    def test_impossible_date(self):
        statement = f.statement(issued_at="2026-02-30T16:08:07Z")
        self.assertIn("wf-timestamp-profile", codes(statement))


class TestBatchRootPresence(unittest.TestCase):
    def test_required_with_records(self):
        statement = f.statement(records=[f.record()])
        self.assertIn("wf-batch-root", codes(statement))

    def test_not_required_without_records(self):
        self.assertEqual(check_wellformed(f.statement()), [])


class TestResult(unittest.TestCase):
    def test_absent_token(self):
        statement = f.drop(f.statement(), ("predicate", "result"))
        self.assertIn("wf-result-token", codes(statement))

    def test_unregistered_token(self):
        self.assertIn("wf-result-token", codes(f.statement(result="ok")))

    def test_a_token_the_recompute_does_not_reproduce(self):
        statement = f.statement(result="pass")
        self.assertIn("wf-result-recompute", codes(statement))

    def test_the_recompute_reasons_travel_with_the_finding(self):
        findings = check_wellformed(f.statement(result="pass"))
        recompute = [x for x in findings if x.code == "wf-result-recompute"][0]
        self.assertIn("clean attackResults[0]", recompute.where)


class TestDoesNotAssert(unittest.TestCase):
    def test_absent_is_fine(self):
        self.assertEqual(check_wellformed(f.statement()), [])

    def test_array_of_strings_is_fine(self):
        self.assertEqual(
            check_wellformed(f.statement(doesNotAssert=["host integrity"])), []
        )

    def test_wrong_shape(self):
        self.assertIn("wf-does-not-assert", codes(f.statement(doesNotAssert="no")))

    def test_the_snake_case_spelling_is_not_an_alias(self):
        # "which is not accepted as an alias" -- it is simply an unread member,
        # so the canonical one is still absent and nothing complains about it.
        self.assertEqual(check_wellformed(f.statement(does_not_assert=["x"])), [])


class TestAccumulation(unittest.TestCase):
    def test_every_broken_rule_is_reported_not_just_the_first(self):
        statement = f.statement(
            rows=[f.row(basis="hearsay"), f.row(basis="hearsay")],
            result="ok",
            issued_at="nope",
        )
        found = set(codes(statement))
        self.assertLessEqual(
            {"wf-row-vocabulary", "wf-duplicate-attack-id", "wf-result-token", "wf-timestamp-profile"},
            found,
        )


if __name__ == "__main__":
    unittest.main()
