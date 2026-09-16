"""Coverage validity, one mutation per requirement."""

import base64
import copy
import unittest

from aee import coverage as cv
from aee.coverage import check_coverage_validity
from aee.jcs import canonicalize
from aee.merkle import root_for_records
from aee.wellformed import check_wellformed

from . import fixtures as f


def codes(statement):
    return [finding.code for finding in check_coverage_validity(statement)]


def rebuild_root(statement):
    """Re-derive batchRoot after the records have been edited."""
    predicate = statement["predicate"]
    predicate["batchRoot"] = root_for_records(predicate["observationRecords"])
    return statement


def edit_record(statement, index, **changes):
    out = copy.deepcopy(statement)
    records = out["predicate"]["observationRecords"]
    records[index] = f.repayload(records[index], **changes)
    return rebuild_root(out)


INTERCEPTION, ARMING, SEALED = 0, 1, 2


class TestTheFixtureIsValid(unittest.TestCase):
    def test_both_gates_are_clean(self):
        statement = f.substrate_statement()
        self.assertEqual(check_wellformed(statement), [])
        self.assertEqual(check_coverage_validity(statement), [])

    def test_a_statement_with_no_records_has_nothing_to_check(self):
        self.assertEqual(check_coverage_validity(f.statement()), [])


class TestPerRowRequirements(unittest.TestCase):
    def test_substrate_row_with_no_refs(self):
        statement = copy.deepcopy(f.substrate_statement())
        del statement["predicate"]["attackResults"][0]["observationRefs"]
        self.assertIn("cv-refs-empty", codes(statement))

    def test_substrate_row_with_empty_refs(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][0]["observationRefs"] = []
        self.assertIn("cv-refs-empty", codes(statement))

    def test_caught_intercepted_row_resolving_no_interception(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][0]["observationRefs"] = [ARMING]
        self.assertIn("cv-record-class", codes(statement))

    def test_clean_intercepted_row_resolving_no_arming(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][1]["observationRefs"] = [SEALED]
        self.assertIn("cv-record-class", codes(statement))

    def test_clean_intercepted_row_resolving_no_sealed(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][1]["observationRefs"] = [ARMING]
        self.assertIn("cv-record-class", codes(statement))

    def test_reconstructed_row_resolving_no_examination(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][0]["method"] = "reconstructed"
        self.assertIn("cv-record-class", codes(statement))

    def test_method_stronger_than_the_weakest_covering_record(self):
        # The row says intercepted; the only record it resolves is an
        # examination, whose aeeMethod is reconstructed.
        statement = copy.deepcopy(f.substrate_statement())
        statement = edit_record(statement, INTERCEPTION, aeeKind="examination",
                                aeeMethod="reconstructed",
                                aeePayloadCommitment=f.REMOVE)
        self.assertIn("cv-method-strength", codes(statement))

    def test_run_binding_mismatch(self):
        statement = edit_record(f.substrate_statement(), INTERCEPTION,
                                aeeRunBinding="00" * 32)
        self.assertIn("cv-run-binding", codes(statement))


class TestPayloadProfile(unittest.TestCase):
    def test_media_type_not_json(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["observationRecords"][INTERCEPTION]["payloadType"] = "text/plain"
        rebuild_root(statement)
        self.assertIn("cv-media-type", codes(statement))

    def test_payload_is_not_json(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["observationRecords"][INTERCEPTION]["payload"] = base64.b64encode(b"not json").decode()
        rebuild_root(statement)
        self.assertIn("cv-payload-parse", codes(statement))

    def test_payload_is_not_an_object(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["observationRecords"][INTERCEPTION]["payload"] = base64.b64encode(b"[1,2]").decode()
        rebuild_root(statement)
        self.assertIn("cv-payload-parse", codes(statement))

    def test_payload_is_not_canonical(self):
        # Well-formed JSON, valid I-JSON, but the members are not in RFC 8785
        # order, so the bytes are not the canonical form of what they parse to.
        statement = copy.deepcopy(f.substrate_statement())
        body = b'{"aeeRunBinding":"x","aeeMethod":"intercepted","aeeKind":"interception"}'
        statement["predicate"]["observationRecords"][INTERCEPTION]["payload"] = base64.b64encode(body).decode()
        rebuild_root(statement)
        self.assertIn("cv-payload-canonical", codes(statement))

    def test_payload_with_a_duplicate_member_is_refused(self):
        statement = copy.deepcopy(f.substrate_statement())
        body = b'{"aeeKind":"interception","aeeKind":"arming"}'
        statement["predicate"]["observationRecords"][INTERCEPTION]["payload"] = base64.b64encode(body).decode()
        rebuild_root(statement)
        self.assertIn("cv-payload-parse", codes(statement))

    def test_missing_reserved_member(self):
        for member in ("aeeRunBinding", "aeeKind", "aeeMethod"):
            with self.subTest(member=member):
                statement = edit_record(f.substrate_statement(), INTERCEPTION,
                                        **{member: f.REMOVE})
                self.assertIn("cv-payload-reserved", codes(statement))

    def test_no_signatures_entry(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["observationRecords"][INTERCEPTION]["signatures"] = []
        rebuild_root(statement)
        self.assertIn("cv-record-signatures", codes(statement))


class TestKindConstraints(unittest.TestCase):
    def test_interception_needs_a_commitment_array(self):
        statement = edit_record(f.substrate_statement(), INTERCEPTION,
                                aeePayloadCommitment=f.REMOVE)
        self.assertIn("cv-record-member", codes(statement))

    def test_commitment_entries_must_be_lowercase_hex(self):
        statement = edit_record(f.substrate_statement(), INTERCEPTION,
                                aeePayloadCommitment=["AA" * 32])
        self.assertIn("cv-record-member", codes(statement))

    def test_commitment_array_must_be_sorted(self):
        statement = edit_record(f.substrate_statement(), INTERCEPTION,
                                aeePayloadCommitment=["bb" * 32, "aa" * 32])
        self.assertIn("cv-array-order", codes(statement))

    def test_arming_posture_digest_must_match(self):
        statement = edit_record(f.substrate_statement(), ARMING,
                                aeePostureDigest="00" * 32)
        self.assertIn("cv-posture-digest", codes(statement))

    def test_arming_armed_at_must_be_in_profile(self):
        statement = edit_record(f.substrate_statement(), ARMING, armedAt="nope")
        self.assertIn("cv-record-member", codes(statement))

    def test_arming_armed_at_must_not_be_after_issued_at(self):
        statement = edit_record(f.substrate_statement(), ARMING,
                                armedAt="2026-06-23T17:00:00Z")
        self.assertIn("cv-armed-after-issued", codes(statement))

    def test_arming_method_must_be_intercepted(self):
        statement = edit_record(f.substrate_statement(), ARMING,
                                aeeMethod="reconstructed")
        self.assertIn("cv-record-method", codes(statement))

    def test_assessed_attacks_must_be_declared_identifiers(self):
        statement = edit_record(f.substrate_statement(), ARMING,
                                aeeAssessedAttacks=["NOT-DECLARED"])
        self.assertIn("cv-record-member", codes(statement))

    def test_sealed_still_armed_must_be_true(self):
        # R4. Absent, non-boolean and false all mean the seal covers nothing,
        # and the kind check reports it whether or not a row resolves the seal.
        for value in ("yes", False, f.REMOVE):
            with self.subTest(value=value):
                statement = edit_record(f.substrate_statement(), SEALED,
                                        aeeStillArmed=value)
                self.assertIn("cv-seal-covers-nothing", codes(statement))

    def test_sealed_drop_count_must_be_an_integer(self):
        statement = edit_record(f.substrate_statement(), SEALED,
                                aeeDropCount="none")
        self.assertIn("cv-record-member", codes(statement))

    def test_examination_method_must_be_reconstructed(self):
        extra = f._payload_record({"aeeRunBinding": "x", "aeeKind": "examination",
                                   "aeeMethod": "intercepted"})
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["observationRecords"].append(extra)
        rebuild_root(statement)
        # The record does not bind to the run, so the kind check does not reach
        # it; that is the documented gate. Bind it and the constraint applies.
        self.assertNotIn("cv-record-method", codes(statement))


class TestUncoverableSubstrateRow(unittest.TestCase):
    """R5. The other half of R1's line.

    "A producer MUST NOT declare basis: substrate on a row it cannot cover
    under the coverage validity requirements above: such a row is not merely
    mislabeled, it makes the attestation invalid."
    """

    def substrate_row(self, **changes):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][0].update(changes)
        return statement

    def test_missing_method(self):
        statement = copy.deepcopy(f.substrate_statement())
        del statement["predicate"]["attackResults"][0]["method"]
        self.assertIn("cv-uncoverable-substrate-row", codes(statement))

    def test_out_of_vocabulary_method(self):
        self.assertIn(
            "cv-uncoverable-substrate-row",
            codes(self.substrate_row(method="example.method-x")),
        )

    def test_missing_attribution(self):
        statement = copy.deepcopy(f.substrate_statement())
        del statement["predicate"]["attackResults"][0]["attribution"]
        self.assertIn("cv-uncoverable-substrate-row", codes(statement))

    def test_out_of_vocabulary_attribution(self):
        self.assertIn(
            "cv-uncoverable-substrate-row",
            codes(self.substrate_row(attribution="example_strong")),
        )

    def test_an_artifact_row_is_untouched_by_this(self):
        # The same value on a non-substrate row only drives the recompute's
        # fail-closed arm, which leaves the statement valid. R1 and R5 are two
        # halves of one line and must not collapse into each other.
        statement = f.statement(rows=[f.row(method="example.method-x")], result="fail")
        self.assertEqual(check_wellformed(statement), [])
        self.assertEqual(check_coverage_validity(statement), [])


class TestChainOfRunsMembers(unittest.TestCase):
    """R3. Syntax only: nothing else normative reads these within one statement."""

    def arming(self, **changes):
        return edit_record(f.substrate_statement(), ARMING, **changes)

    def test_a_well_formed_chain_is_accepted(self):
        statement = self.arming(aeeRunSeq=1, aeeChainScope=["subject"])
        self.assertEqual(check_coverage_validity(statement), [])

    def test_a_later_run_carries_its_predecessor(self):
        statement = self.arming(aeeRunSeq=2, aeeChainScope=["subject"],
                                aeePrevRunBinding="ab" * 32)
        self.assertEqual(check_coverage_validity(statement), [])

    def test_sequence_must_be_positive(self):
        for bad in (0, -1):
            with self.subTest(sequence=bad):
                statement = self.arming(aeeRunSeq=bad, aeeChainScope=["subject"])
                self.assertIn("cv-chain-members", codes(statement))

    def test_sequence_must_be_an_integer(self):
        statement = self.arming(aeeRunSeq="1", aeeChainScope=["subject"])
        self.assertIn("cv-chain-members", codes(statement))

    def test_scope_is_required_whenever_the_sequence_is_present(self):
        statement = self.arming(aeeRunSeq=1)
        self.assertIn("cv-chain-members", codes(statement))

    def test_scope_must_be_an_array(self):
        statement = self.arming(aeeRunSeq=1, aeeChainScope="subject")
        self.assertIn("cv-chain-members", codes(statement))

    def test_scope_tokens_are_a_closed_vocabulary(self):
        statement = self.arming(aeeRunSeq=1, aeeChainScope=["subject", "tenant"])
        self.assertIn("cv-chain-members", codes(statement))

    def test_scope_must_be_in_canonical_order(self):
        statement = self.arming(aeeRunSeq=1, aeeChainScope=["subject", "corpus"])
        self.assertIn("cv-array-order", codes(statement))

    def test_scope_must_be_duplicate_free(self):
        statement = self.arming(aeeRunSeq=1, aeeChainScope=["subject", "subject"])
        self.assertIn("cv-array-duplicate", codes(statement))

    def test_the_empty_scope_array_is_admissible(self):
        # "the empty array is the single global per-key counter" -- it makes the
        # chain rules vacuous and leaks run volume, which the spec says plainly,
        # but it is not a syntax violation.
        statement = self.arming(aeeRunSeq=1, aeeChainScope=[])
        self.assertEqual(check_coverage_validity(statement), [])

    def test_genesis_must_not_carry_a_predecessor(self):
        statement = self.arming(aeeRunSeq=1, aeeChainScope=["subject"],
                                aeePrevRunBinding="ab" * 32)
        self.assertIn("cv-chain-members", codes(statement))

    def test_a_later_run_must_carry_a_well_formed_predecessor(self):
        for bad in ("EXAMPLE-NOT-64-HEX", "AB" * 32, f.REMOVE):
            with self.subTest(value=bad):
                statement = self.arming(aeeRunSeq=2, aeeChainScope=["subject"],
                                        aeePrevRunBinding=bad)
                self.assertIn("cv-chain-members", codes(statement))

    def test_any_member_without_the_sequence_is_a_violation(self):
        for member in ("aeePrevRunBinding", "aeeChainScope"):
            value = "ab" * 32 if member == "aeePrevRunBinding" else ["subject"]
            with self.subTest(member=member):
                statement = self.arming(**{member: value})
                self.assertIn("cv-chain-members", codes(statement))

    def test_absent_entirely_is_fine(self):
        self.assertEqual(check_coverage_validity(f.substrate_statement()), [])


class TestSealCovering(unittest.TestCase):
    def test_a_seal_that_is_no_longer_armed_covers_nothing(self):
        statement = f.substrate_statement(still_armed=False)
        self.assertIn("cv-record-class", codes(statement))

    def test_a_drop_count_above_its_bound_covers_nothing(self):
        statement = f.substrate_statement(drop_count=5, drop_bound=2)
        self.assertIn("cv-record-class", codes(statement))

    def test_a_drop_count_within_its_bound_still_covers(self):
        statement = f.substrate_statement(drop_count=2, drop_bound=5)
        self.assertEqual(check_coverage_validity(statement), [])

    def test_a_non_zero_drop_count_with_no_bound_covers_nothing(self):
        statement = f.substrate_statement(drop_count=1)
        self.assertIn("cv-record-class", codes(statement))


class TestStatementWideRequirements(unittest.TestCase):
    def test_batch_root_mismatch(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["batchRoot"] = "00" * 32
        self.assertIn("cv-batch-root", codes(statement))

    def test_clean_row_resolving_an_interception(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][1]["observationRefs"] = [INTERCEPTION, ARMING, SEALED]
        self.assertIn("cv-clean-row-interception", codes(statement))

    def test_an_interception_no_caught_row_resolves(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][0]["observationRefs"] = [ARMING]
        self.assertIn("cv-orphan-interception", codes(statement))

    def test_observed_set_mismatch(self):
        statement = edit_record(f.substrate_statement(), SEALED,
                                aeeObservedSet="00" * 32)
        self.assertIn("cv-observed-set", codes(statement))

    def test_observed_attacks_without_a_caught_row(self):
        statement = f.substrate_statement(observed_attacks=["CO-EXFIL-2"])
        self.assertIn("cv-observed-attacks-row", codes(statement))

    def test_assessed_attacks_must_cover_the_assessed_classes(self):
        statement = f.substrate_statement(assessed_attacks=["CO-EXFIL-1"])
        self.assertIn("cv-assessed-subset", codes(statement))

    def test_sealed_existence(self):
        statement = copy.deepcopy(f.substrate_statement())
        del statement["predicate"]["observationRecords"][SEALED]
        statement["predicate"]["attackResults"][1]["observationRefs"] = [ARMING]
        rebuild_root(statement)
        self.assertIn("cv-sealed-existence", codes(statement))


class TestPinnedAttribution(unittest.TestCase):
    def test_pinned_row_resolving_no_interception(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][0]["observationRefs"] = [ARMING]
        self.assertIn("cv-pinned-no-interception", codes(statement))

    def test_pinned_row_whose_attack_has_no_expectation(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][1]["attribution"] = "pinned"
        statement["predicate"]["attackResults"][1]["observationRefs"] = [INTERCEPTION, ARMING, SEALED]
        self.assertIn("cv-pinned-no-expectation", codes(statement))

    def test_pinned_row_whose_record_commits_to_something_else(self):
        statement = edit_record(f.substrate_statement(), INTERCEPTION,
                                aeePayloadCommitment=["bb" * 32])
        self.assertIn("cv-pinned-commitment", codes(statement))

    def test_paired_rows_are_not_checked_against_expectations(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][0]["attribution"] = "paired"
        found = codes(statement)
        self.assertNotIn("cv-pinned-commitment", found)
        self.assertNotIn("cv-pinned-no-expectation", found)


class TestDriftSwitch(unittest.TestCase):
    """The prediction DRIFT.md makes, run both ways.

    Hunk 1333c1392,1393. The shape that differs is a seal whose
    aeePostureDigest does not match and on which no clean row depends. Here the
    statement's rows are all caught, so nothing relies on the seal for
    covering, and only the kind constraint and the existence requirement can
    reach it.
    """

    def all_caught(self):
        statement = copy.deepcopy(f.substrate_statement(seal_posture_digest="00" * 32))
        predicate = statement["predicate"]
        predicate["attackResults"] = [predicate["attackResults"][0]]
        return statement

    def test_the_head_reading_refuses_it(self):
        self.assertTrue(cv.SEALED_POSTURE_IS_A_KIND_CONSTRAINT)
        found = codes(self.all_caught())
        self.assertIn("cv-posture-digest", found)
        self.assertIn("cv-sealed-existence", found)

    def test_the_corpus_pinned_reading_accepts_it(self):
        original = cv.SEALED_POSTURE_IS_A_KIND_CONSTRAINT
        cv.SEALED_POSTURE_IS_A_KIND_CONSTRAINT = False
        try:
            found = codes(self.all_caught())
        finally:
            cv.SEALED_POSTURE_IS_A_KIND_CONSTRAINT = original
        self.assertNotIn("cv-posture-digest", found)
        self.assertNotIn("cv-sealed-existence", found)

    def test_the_head_is_strictly_stricter_here(self):
        # The direction DRIFT.md predicts: this reading refuses where the other
        # accepts, never the reverse.
        statement = self.all_caught()
        head = set(codes(statement))
        original = cv.SEALED_POSTURE_IS_A_KIND_CONSTRAINT
        cv.SEALED_POSTURE_IS_A_KIND_CONSTRAINT = False
        try:
            pinned = set(codes(statement))
        finally:
            cv.SEALED_POSTURE_IS_A_KIND_CONSTRAINT = original
        self.assertLess(pinned, head)

    def test_a_matching_seal_is_accepted_under_both_readings(self):
        statement = copy.deepcopy(f.substrate_statement())
        predicate = statement["predicate"]
        predicate["attackResults"] = [predicate["attackResults"][0]]
        head = codes(statement)
        original = cv.SEALED_POSTURE_IS_A_KIND_CONSTRAINT
        cv.SEALED_POSTURE_IS_A_KIND_CONSTRAINT = False
        try:
            pinned = codes(statement)
        finally:
            cv.SEALED_POSTURE_IS_A_KIND_CONSTRAINT = original
        self.assertEqual(head, pinned)


if __name__ == "__main__":
    unittest.main()


class TestSecondRoundRules(unittest.TestCase):
    """R9, R10, R11, R14 -- found by working the remaining seventeen."""

    def test_an_out_of_vocabulary_label_makes_a_substrate_row_uncoverable(self):
        statement = copy.deepcopy(f.substrate_statement())
        statement["predicate"]["attackResults"][0]["containmentObserved"] = "example_label_a"
        self.assertIn("cv-uncoverable-substrate-row", codes(statement))

    def test_but_not_an_artifact_row(self):
        statement = f.statement(rows=[f.row(observed="example_label_a")], result="fail")
        self.assertEqual(check_coverage_validity(statement), [])

    def test_a_negative_drop_count_covers_nothing(self):
        # It would otherwise pass an upper-bound comparison vacuously.
        statement = f.substrate_statement(drop_count=-1, drop_bound=5)
        self.assertIn("cv-seal-covers-nothing", codes(statement))

    def test_an_unimplemented_binding_version_covers_nothing(self):
        statement = edit_record(f.substrate_statement(), ARMING, aeeBindingVersion="3")
        self.assertIn("cv-binding-version", codes(statement))

    def test_the_implemented_binding_version_may_be_declared_explicitly(self):
        statement = edit_record(f.substrate_statement(), ARMING, aeeBindingVersion="2")
        self.assertEqual(check_coverage_validity(statement), [])

    def test_non_canonical_base64_is_undecodable(self):
        # Trailing bits outside the decoded bytes: two distinct payload strings
        # decoding to the same bytes is the divergence the profile exists to
        # prevent, so a lenient decode is not good enough.
        statement = copy.deepcopy(f.substrate_statement())
        record = statement["predicate"]["observationRecords"][INTERCEPTION]
        carried = record["payload"]
        assert carried.endswith("=")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last = carried.rstrip("=")[-1]
        record["payload"] = carried.rstrip("=")[:-1] + alphabet[alphabet.index(last) + 1] + "=" * (len(carried) - len(carried.rstrip("=")))
        # The root is deliberately not rebuilt: a record whose payload cannot be
        # decoded has no leaf hash, so there is no root to rebuild, which is
        # itself part of what the refusal means.
        found = codes(statement)
        self.assertIn("cv-payload-parse", found)
        self.assertIn("cv-batch-root", found)
