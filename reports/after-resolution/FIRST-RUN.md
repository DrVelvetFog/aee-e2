# First run

Raw output of the first execution of this implementation against the
pinned corpus. Written before any fix. Nothing below has been edited in
response to what it says.

    taken           2026-09-16T12:47:44Z
    spec            25ac8581fbc9398a3add2577c65e2d09163e3db3
    spec sha256     2b7f3bc08123cbe1981d287cf20193858ae5ea6d55ca067e06363a1e71a573d7
    corpus          astrogilda/agent-evidence-vectors @ v0.10.1
    corpus digest   8b035678def9e5ac00ba761b8c640e4412c57163134afb9d2c1a90f49d573a52
    suite           adversarial-execution-evidence-conformance, suiteRevision 28
    language        Python, standard library only

## Corpus verified before scoring

    release/CORPUS-DIGESTS.txt sha256  ok
    manifest corpusDigest              ok
    manifest suite                     ok
    vector count                       ok

## Score

Scored surface is `verdict`, and `result` on an accepted statement. Codes
are measured, not scored, and are reported separately below.

    vectors                 272
    verdict matches         272 / 272
    result matches          61 / 61 (accepted statements only)
    fully matching          272 / 272
    divergences             0

## Divergences

None.

## Reason parity

Reported as its own figure, per the manifest's comparison surface. This
rail's codes are declared in `aee/findings.py` and are not intended to
match the reference verifier's vocabulary.

| code | vectors |
|---|---|
| `cv-record-class` | 39 |
| `cv-payload-parse` | 27 |
| `cv-record-member` | 21 |
| `cv-observed-set` | 18 |
| `cv-run-binding` | 18 |
| `cv-seal-covers-nothing` | 15 |
| `cv-sealed-existence` | 12 |
| `wf-result-recompute` | 12 |
| `cv-batch-root` | 11 |
| `ijson-profile` | 8 |
| `cv-orphan-interception` | 7 |
| `wf-observation-ref-range` | 7 |
| `cv-chain-members` | 6 |
| `cv-observed-attacks-row` | 6 |
| `cv-uncoverable-substrate-row` | 6 |
| `wf-missing-member` | 6 |
| `cv-pinned-commitment` | 5 |
| `cv-posture-digest` | 5 |
| `cv-record-method` | 5 |
| `wf-coverage-partition` | 5 |
| `wf-expected-payloads` | 5 |
| `wf-timestamp-profile` | 5 |
| `cv-method-strength` | 4 |
| `cv-record-signatures` | 4 |
| `wf-coverage-integrity` | 4 |
| `cv-payload-reserved` | 3 |
| `cv-pinned-no-interception` | 3 |
| `wf-clean-row-actual-layer` | 3 |
| `wf-posture-vocabulary` | 3 |
| `wf-subject-cardinality` | 3 |
| `cv-array-order` | 2 |
| `cv-assessed-subset` | 2 |
| `cv-pinned-no-expectation` | 2 |
| `wf-array-order` | 2 |
| `wf-digest-not-canonical` | 2 |
| `wf-manifest-floor` | 2 |
| `wf-result-token` | 2 |
| `cv-armed-after-issued` | 1 |
| `cv-binding-version` | 1 |
| `cv-clean-row-interception` | 1 |
| `cv-media-type` | 1 |
| `cv-payload-bmp` | 1 |
| `cv-payload-canonical` | 1 |
| `cv-refs-empty` | 1 |
| `wf-actual-layer-type` | 1 |
| `wf-array-duplicate` | 1 |
| `wf-batch-root` | 1 |
| `wf-batch-root-orphaned` | 1 |
| `wf-caught-subset` | 1 |
| `wf-corpus-digest` | 1 |
| `wf-duplicate-attack-id` | 1 |
| `wf-manifest-class-overlap` | 1 |
| `wf-manifest-shape` | 1 |
| `wf-member-spelling` | 1 |
| `wf-predicate-type` | 1 |
| `wf-row-member` | 1 |
| `wf-run-entropy` | 1 |
| `wf-statement-type` | 1 |
| `wf-subject` | 1 |
| `wf-unknown-attack-id` | 1 |
| `wf-vocabulary-bmp` | 1 |
| `wf-vocabulary-digest` | 1 |
| `wf-vocabulary-shape` | 1 |

