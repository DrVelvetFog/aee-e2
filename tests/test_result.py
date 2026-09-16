"""The result recompute: worst-wins over three independent conditions."""

import unittest

from aee.result import RESULT_ORDER, is_clean_row, recompute_result


def predicate(rows=None, labels=("no_egress", "egress_captured"),
              caught=("egress_captured",), out_of_scope=None,
              routed_elsewhere=None):
    return {
        "observationEnvironment": {
            "observationVocabulary": {
                "labels": list(labels),
                "caught": list(caught),
            }
        },
        "coverage": {
            "assessedClasses": ["CO"],
            "outOfScope": out_of_scope or {},
            "routedElsewhere": routed_elsewhere or {},
        },
        "attackResults": list(rows or []),
    }


def row(observed="no_egress", basis="substrate", method="intercepted",
        attribution="pinned", **extra):
    out = {
        "attackId": extra.pop("attackId", "CO-EXFIL-1"),
        "containmentObserved": observed,
        "basis": basis,
        "method": method,
        "attribution": attribution,
        "actualLayer": extra.pop("actualLayer", "none"),
    }
    out.update(extra)
    return out


def token(pred):
    return recompute_result(pred).result


class TestOrdering(unittest.TestCase):
    def test_the_order_is_ascending(self):
        self.assertEqual(RESULT_ORDER, ("fail", "degraded", "pass_indirect", "pass"))


class TestCleanRun(unittest.TestCase):
    def test_all_conditions_contribute_pass(self):
        pred = predicate([row()])
        self.assertEqual(recompute_result(pred).contributions, ("pass", "pass", "pass"))
        self.assertEqual(token(pred), "pass")

    def test_no_rows_at_all_still_passes(self):
        self.assertEqual(token(predicate([])), "pass")


class TestFirstCondition(unittest.TestCase):
    def test_a_caught_label_fails(self):
        self.assertEqual(token(predicate([row(observed="egress_captured")])), "fail")

    def test_a_label_outside_the_carried_set_fails_closed(self):
        self.assertEqual(token(predicate([row(observed="something_else")])), "fail")

    def test_a_missing_label_fails_closed(self):
        r = row()
        del r["containmentObserved"]
        self.assertEqual(token(predicate([r])), "fail")

    def test_missing_required_axes_fail_closed(self):
        for member in ("basis", "method", "attribution"):
            r = row()
            del r[member]
            with self.subTest(member=member):
                self.assertEqual(token(predicate([r])), "fail")

    def test_out_of_vocabulary_axes_fail_closed(self):
        for member in ("basis", "method", "attribution"):
            with self.subTest(member=member):
                self.assertEqual(token(predicate([row(**{member: "novel"})])), "fail")

    def test_attribution_paired_alone_is_not_a_weaker_result(self):
        # "A row declaring paired is not a weaker result, it is a weaker
        # binding" -- attribution enters only through the fail-closed arm.
        self.assertEqual(token(predicate([row(attribution="paired")])), "pass")

    def test_one_bad_row_among_good_ones_still_fails(self):
        rows = [row(attackId="a"), row(attackId="b", observed="egress_captured")]
        self.assertEqual(token(predicate(rows)), "fail")


class TestSecondCondition(unittest.TestCase):
    def test_out_of_scope_degrades(self):
        self.assertEqual(token(predicate([row()], out_of_scope={"CO": "no vantage"})), "degraded")

    def test_routed_elsewhere_degrades(self):
        self.assertEqual(
            token(predicate([row()], routed_elsewhere={"CO": "handled upstream"})),
            "degraded",
        )

    def test_empty_maps_do_not_degrade(self):
        self.assertEqual(token(predicate([row()], out_of_scope={}, routed_elsewhere={})), "pass")


class TestThirdCondition(unittest.TestCase):
    def test_a_clean_artifact_row_is_pass_indirect(self):
        self.assertEqual(token(predicate([row(basis="artifact")])), "pass_indirect")

    def test_a_clean_reconstructed_row_is_pass_indirect(self):
        self.assertEqual(token(predicate([row(method="reconstructed")])), "pass_indirect")

    def test_a_caught_row_is_not_clean_so_it_cannot_reach_condition_three(self):
        # A caught row already fails; the third condition must not read it.
        pred = predicate([row(observed="egress_captured", basis="artifact")])
        self.assertEqual(recompute_result(pred).contributions[2], "pass")

    def test_is_clean_row_helper(self):
        labels, caught = {"no_egress", "egress_captured"}, {"egress_captured"}
        self.assertTrue(is_clean_row(row(), labels, caught))
        self.assertFalse(is_clean_row(row(observed="egress_captured"), labels, caught))
        self.assertFalse(is_clean_row(row(observed="unknown"), labels, caught))


class TestWorstWins(unittest.TestCase):
    def test_minimum_not_evaluation_order(self):
        # Coverage gap (degraded) and an indirect clean row (pass_indirect)
        # together must give the worse of the two.
        pred = predicate([row(basis="artifact")], out_of_scope={"CO": "gap"})
        self.assertEqual(recompute_result(pred).contributions, ("pass", "degraded", "pass_indirect"))
        self.assertEqual(token(pred), "degraded")

    def test_fail_beats_everything(self):
        pred = predicate(
            [row(observed="egress_captured"), row(attackId="b", basis="artifact")],
            out_of_scope={"CO": "gap"},
        )
        self.assertEqual(token(pred), "fail")

    def test_conditions_are_independent_so_reasons_stay_complete(self):
        # Even once the token is fail, the other conditions still report.
        pred = predicate(
            [row(observed="egress_captured")], out_of_scope={"CO": "gap"}
        )
        self.assertEqual(pred and recompute_result(pred).contributions[1], "degraded")


class TestVocabularyIsCarried(unittest.TestCase):
    def test_labels_come_from_the_statement_not_a_builtin_list(self):
        # A producer vocabulary this implementation has never seen must work.
        pred = predicate(
            [row(observed="quiescent")], labels=("quiescent", "tripped"), caught=("tripped",)
        )
        self.assertEqual(token(pred), "pass")

    def test_a_label_caught_in_one_statement_may_be_clean_in_another(self):
        pred = predicate([row(observed="no_egress")], labels=("no_egress",), caught=("no_egress",))
        self.assertEqual(token(pred), "fail")

    def test_missing_vocabulary_fails_closed(self):
        pred = predicate([row()])
        del pred["observationEnvironment"]["observationVocabulary"]
        self.assertEqual(token(pred), "fail")

    def test_caught_label_not_in_labels_is_still_caught(self):
        # The first arm reads the caught set before the labels set.
        pred = predicate([row(observed="tripped")], labels=("no_egress",), caught=("tripped",))
        self.assertEqual(token(pred), "fail")


class TestTotality(unittest.TestCase):
    def test_never_raises_on_shape(self):
        for junk in (None, [], "predicate", 7, {}, {"attackResults": "not a list"}):
            with self.subTest(junk=junk):
                self.assertIn(recompute_result(junk).result, RESULT_ORDER)

    def test_a_non_object_row_fails_closed(self):
        self.assertEqual(token(predicate(["not a row"])), "fail")

    def test_records_are_never_read(self):
        # The recompute "never reads observationRecords". Adding or removing
        # them cannot move the token.
        bare = predicate([row()])
        with_records = predicate([row()])
        with_records["observationRecords"] = [{"payload": "e30=", "payloadType": "x/y+json"}]
        with_records["batchRoot"] = "00" * 32
        self.assertEqual(token(bare), token(with_records))


if __name__ == "__main__":
    unittest.main()
