"""Digest bindings re-derived from carried bytes."""

import hashlib
import unittest

from aee.bindings import (
    BINDING_VERSION,
    POSTURE_VALUES,
    BindingError,
    corpus_digest,
    network_posture_digest,
    run_binding_digest,
    sha256_jcs,
    vocabulary_digest,
)

HEX = "%064d"


def environment(**overrides):
    env = {
        "substrate": {"name": "sub", "digest": {"sha256": HEX % 1}},
        "corpus": {
            "name": "corpus",
            "uri": "pkg:example/corpus@1",
            "digest": {"sha256": HEX % 2},
            "manifest": {"classes": {"CO": ["CO-EXFIL-1"]}},
        },
        "catchPolicy": {"digest": {"sha256": HEX % 3}},
        "networkPosture": {"posture": "sinkhole", "digest": {"sha256": HEX % 4}},
        "observationVocabulary": {
            "digest": {"sha256": HEX % 5},
            "labels": ["egress_captured", "no_egress"],
            "caught": ["egress_captured"],
        },
        "runEntropy": {"digest": {"sha256": HEX % 6}},
    }
    env.update(overrides)
    return env


SUBJECT = [{"name": "artifact", "digest": {"sha256": HEX % 7}}]


class TestPrimitive(unittest.TestCase):
    def test_sha256_jcs_is_lowercase_64_hex(self):
        value = sha256_jcs({"a": 1})
        self.assertEqual(len(value), 64)
        self.assertEqual(value, value.lower())

    def test_it_hashes_the_canonical_form_not_the_written_form(self):
        # Member order in the source object cannot move the digest.
        self.assertEqual(sha256_jcs({"a": 1, "b": 2}), sha256_jcs({"b": 2, "a": 1}))

    def test_against_a_hand_written_canonical_form(self):
        self.assertEqual(
            sha256_jcs({"b": 2, "a": 1}),
            hashlib.sha256(b'{"a":1,"b":2}').hexdigest(),
        )


class TestCorpusDigest(unittest.TestCase):
    def test_derived_from_the_carried_manifest(self):
        manifest = {"classes": {"CO": ["CO-EXFIL-1"]}}
        self.assertEqual(corpus_digest(manifest), sha256_jcs(manifest))

    def test_a_dropped_attack_changes_it(self):
        full = {"classes": {"CO": ["CO-EXFIL-1", "CO-EXFIL-2"]}}
        trimmed = {"classes": {"CO": ["CO-EXFIL-1"]}}
        self.assertNotEqual(corpus_digest(full), corpus_digest(trimmed))

    def test_a_renamed_class_changes_it(self):
        self.assertNotEqual(
            corpus_digest({"classes": {"CO": ["A"]}}),
            corpus_digest({"classes": {"XX": ["A"]}}),
        )

    def test_expected_payloads_sit_inside_the_pre_image(self):
        bare = {"classes": {"CO": ["A"]}}
        enriched = {"classes": {"CO": ["A"]}, "expectedPayloads": {"A": ["ab" * 32]}}
        self.assertNotEqual(corpus_digest(bare), corpus_digest(enriched))


class TestVocabularyDigest(unittest.TestCase):
    def test_pre_image_is_the_two_arrays_alone(self):
        self.assertEqual(
            vocabulary_digest(["b", "a"], ["a"]),
            hashlib.sha256(b'{"caught":["a"],"labels":["b","a"]}').hexdigest(),
        )

    def test_array_order_is_carried_not_normalised(self):
        # The arrays are required to be sorted, but that is a well-formedness
        # rule; the digest is over what is carried, so an unsorted array gives
        # a different value rather than being quietly fixed here.
        self.assertNotEqual(
            vocabulary_digest(["a", "b"], []), vocabulary_digest(["b", "a"], [])
        )

    def test_moving_a_label_into_caught_changes_it(self):
        self.assertNotEqual(
            vocabulary_digest(["a", "b"], ["a"]), vocabulary_digest(["a", "b"], ["a", "b"])
        )

    def test_the_carried_digest_member_is_not_part_of_the_pre_image(self):
        env = environment()
        vocabulary = env["observationVocabulary"]
        self.assertEqual(
            vocabulary_digest(vocabulary["labels"], vocabulary["caught"]),
            sha256_jcs({"caught": vocabulary["caught"], "labels": vocabulary["labels"]}),
        )


class TestNetworkPostureDigest(unittest.TestCase):
    def test_is_taken_over_the_whole_carried_object(self):
        posture = {"posture": "sinkhole", "digest": {"sha256": HEX % 4}}
        self.assertEqual(network_posture_digest(posture), sha256_jcs(posture))

    def test_is_not_the_configuration_digest_member(self):
        posture = {"posture": "sinkhole", "digest": {"sha256": HEX % 4}}
        self.assertNotEqual(network_posture_digest(posture), posture["digest"]["sha256"])

    def test_changing_the_posture_token_moves_it(self):
        a = {"posture": "sinkhole", "digest": {"sha256": HEX % 4}}
        b = {"posture": "no_network", "digest": {"sha256": HEX % 4}}
        self.assertNotEqual(network_posture_digest(a), network_posture_digest(b))

    def test_registered_vocabulary(self):
        self.assertEqual(
            POSTURE_VALUES,
            {"allowlist", "no_network", "sinkhole", "unsafe_bypass_egress"},
        )


class TestRunBinding(unittest.TestCase):
    def test_binding_version_is_the_string_two(self):
        self.assertEqual(BINDING_VERSION, "2")

    def test_matches_a_hand_built_pre_image(self):
        env = environment()
        expected = sha256_jcs(
            {
                "aeeBindingVersion": "2",
                "catchPolicy": HEX % 3,
                "corpus": HEX % 2,
                "networkPosture": network_posture_digest(env["networkPosture"]),
                "observationVocabulary": HEX % 5,
                "runEntropy": HEX % 6,
                "subject": HEX % 7,
                "substrate": HEX % 1,
            }
        )
        self.assertEqual(
            run_binding_digest({"observationEnvironment": env}, SUBJECT), expected
        )

    def test_every_input_moves_it(self):
        base = run_binding_digest({"observationEnvironment": environment()}, SUBJECT)
        mutations = {
            "substrate": ("substrate", {"name": "sub", "digest": {"sha256": HEX % 9}}),
            "catchPolicy": ("catchPolicy", {"digest": {"sha256": HEX % 9}}),
            "runEntropy": ("runEntropy", {"digest": {"sha256": HEX % 9}}),
        }
        for name, (member, value) in mutations.items():
            with self.subTest(member=name):
                env = environment(**{member: value})
                moved = run_binding_digest({"observationEnvironment": env}, SUBJECT)
                self.assertNotEqual(base, moved)

    def test_the_subject_moves_it(self):
        base = run_binding_digest({"observationEnvironment": environment()}, SUBJECT)
        other = [{"name": "artifact", "digest": {"sha256": HEX % 8}}]
        self.assertNotEqual(base, run_binding_digest({"observationEnvironment": environment()}, other))

    def test_only_the_first_subject_entry_is_read(self):
        extended = SUBJECT + [{"name": "second", "digest": {"sha256": HEX % 9}}]
        self.assertEqual(
            run_binding_digest({"observationEnvironment": environment()}, SUBJECT),
            run_binding_digest({"observationEnvironment": environment()}, extended),
        )

    def test_missing_inputs_are_refused_by_name(self):
        for member in ("substrate", "corpus", "catchPolicy", "observationVocabulary", "runEntropy"):
            env = environment()
            del env[member]
            with self.subTest(member=member):
                with self.assertRaises(BindingError) as caught:
                    run_binding_digest({"observationEnvironment": env}, SUBJECT)
                self.assertIn(member, str(caught.exception))

    def test_missing_network_posture_is_refused(self):
        env = environment()
        del env["networkPosture"]
        with self.assertRaises(BindingError):
            run_binding_digest({"observationEnvironment": env}, SUBJECT)

    def test_absent_subject_is_refused(self):
        for bad in ([], None, "subject"):
            with self.subTest(subject=bad):
                with self.assertRaises(BindingError):
                    run_binding_digest({"observationEnvironment": environment()}, bad)

    def test_absent_environment_is_refused(self):
        with self.assertRaises(BindingError):
            run_binding_digest({}, SUBJECT)

    def test_rows_cannot_reach_the_binding(self):
        # "Every input is a property of the run's configuration and is fixed
        # before corpus injection" -- an outcome can never be an input.
        env = environment()
        bare = {"observationEnvironment": env}
        with_rows = {
            "observationEnvironment": env,
            "attackResults": [{"attackId": "CO-EXFIL-1"}],
            "result": "fail",
        }
        self.assertEqual(
            run_binding_digest(bare, SUBJECT), run_binding_digest(with_rows, SUBJECT)
        )


if __name__ == "__main__":
    unittest.main()
