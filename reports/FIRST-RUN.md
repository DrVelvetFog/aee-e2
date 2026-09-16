# First run

Raw output of the first execution of this implementation against the
pinned corpus. Written before any fix. Nothing below has been edited in
response to what it says.

    taken           2026-09-16T12:30:18Z
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
    verdict matches         236 / 272
    result matches          54 / 61 (accepted statements only)
    fully matching          236 / 272
    divergences             36

## Divergences

| id | conditions | expected | got | codes emitted |
|---|---|---|---|---|
| `v51e9223d08fcc4e1` | `aee-c-5`, `aee-c-44` | valid / fail | invalid | `wf-row-vocabulary` |
| `vea21d85d4e531e66` | `aee-c-43` | valid / fail | invalid | `wf-row-vocabulary` |
| `v48542b44ffd26237` | `aee-c-5`, `aee-c-42`, `aee-c-44` | valid / fail | invalid | `wf-row-member` |
| `v948fbb64b96197e6` | `aee-c-5`, `aee-c-43` | valid / fail | invalid | `wf-row-vocabulary` |
| `v164cf7f3f529eaff` | `aee-c-23`, `aee-c-45`, `aee-c-71` | valid / pass | invalid | `cv-method-strength` |
| `v7d2a79cb1ddc59a5` | `aee-c-23`, `aee-c-45`, `aee-c-106`, `aee-c-107` | valid / pass | invalid | `cv-method-strength` |
| `v18bdbadef67b38f4` | `aee-c-1` | valid / fail | invalid | `wf-row-member` |
| `v081d9eeddbd5634f` | `aee-c-75` | invalid | valid / pass | - |
| `v577011f7dd9a08fe` | `aee-c-31` | invalid | valid / pass_indirect | - |
| `v539055896bf3a954` | `aee-c-4`, `aee-c-44` | invalid | valid / fail | - |
| `v3eb268f467674845` | `aee-c-88` | invalid | valid / fail | - |
| `v6f6941efba2cbe28` | `aee-c-58` | invalid | valid / pass | - |
| `v495bb03f306ef6aa` | `aee-c-59` | invalid | valid / pass | - |
| `vbd93d974436e11eb` | `aee-c-59` | invalid | valid / pass | - |
| `va54b6faefcfb1f9e` | `aee-c-4`, `aee-c-44`, `aee-c-53` | invalid | valid / fail | - |
| `v423dab49f4ed4d29` | `aee-c-58` | invalid | valid / pass_indirect | - |
| `vef2571e9001d7bd1` | `aee-c-89` | invalid | valid / pass | - |
| `v3cf298b019a0405f` | `aee-c-89` | invalid | valid / pass | - |
| `v2bac3fa36d7a5947` | `aee-c-89` | invalid | valid / pass | - |
| `v8a7008d1673711a9` | `aee-c-89` | invalid | valid / pass | - |
| `v4360d4e15f84145f` | `aee-c-89` | invalid | valid / pass | - |
| `v04993666ec44cda9` | `aee-c-89` | invalid | valid / pass | - |
| `v8a7532ae4cffa163` | `aee-c-89` | invalid | valid / pass | - |
| `v5a842871df5bfe33` | `aee-c-82` | invalid | valid / fail | - |
| `vb3c92d4ecb62bbfb` | `aee-c-82` | invalid | valid / degraded | - |
| `ved230b46692c0ada` | `aee-c-82` | invalid | valid / degraded | - |
| `v4ff6cb70764bf703` | `aee-c-19` | invalid | valid / fail | - |
| `v3c3a76f63bf8dda8` | `aee-c-84` | invalid | valid / pass | - |
| `v1ec06de44fe4000d` | `aee-c-65` | invalid | valid / pass | - |
| `v4da2f99ac2897154` | `aee-c-108` | invalid | valid / pass | - |
| `v80e2a3fba582ed4d` | `aee-c-108` | invalid | valid / pass | - |
| `vd7be865fc69eacc2` | `aee-c-108` | invalid | valid / pass | - |
| `vfb979cb9ce40f1be` | `aee-c-108` | invalid | valid / pass | - |
| `vb1337e5ecad985c2` | `aee-c-108` | invalid | valid / pass | - |
| `vd538496f284b4761` | `aee-c-96` | invalid | valid / fail | - |
| `v399c693cbf60143b` | `aee-c-58` | invalid | valid / pass | - |

### Divergences grouped by condition

- `aee-c-89` — 7: `vef2571e9001d7bd1`, `v3cf298b019a0405f`, `v2bac3fa36d7a5947`, `v8a7008d1673711a9`, `v4360d4e15f84145f`, `v04993666ec44cda9`, `v8a7532ae4cffa163`
- `aee-c-108` — 5: `v4da2f99ac2897154`, `v80e2a3fba582ed4d`, `vd7be865fc69eacc2`, `vfb979cb9ce40f1be`, `vb1337e5ecad985c2`
- `aee-c-44` — 4: `v51e9223d08fcc4e1`, `v48542b44ffd26237`, `v539055896bf3a954`, `va54b6faefcfb1f9e`
- `aee-c-5` — 3: `v51e9223d08fcc4e1`, `v48542b44ffd26237`, `v948fbb64b96197e6`
- `aee-c-58` — 3: `v6f6941efba2cbe28`, `v423dab49f4ed4d29`, `v399c693cbf60143b`
- `aee-c-82` — 3: `v5a842871df5bfe33`, `vb3c92d4ecb62bbfb`, `ved230b46692c0ada`
- `aee-c-23` — 2: `v164cf7f3f529eaff`, `v7d2a79cb1ddc59a5`
- `aee-c-4` — 2: `v539055896bf3a954`, `va54b6faefcfb1f9e`
- `aee-c-43` — 2: `vea21d85d4e531e66`, `v948fbb64b96197e6`
- `aee-c-45` — 2: `v164cf7f3f529eaff`, `v7d2a79cb1ddc59a5`
- `aee-c-59` — 2: `v495bb03f306ef6aa`, `vbd93d974436e11eb`
- `aee-c-1` — 1: `v18bdbadef67b38f4`
- `aee-c-106` — 1: `v7d2a79cb1ddc59a5`
- `aee-c-107` — 1: `v7d2a79cb1ddc59a5`
- `aee-c-19` — 1: `v4ff6cb70764bf703`
- `aee-c-31` — 1: `v577011f7dd9a08fe`
- `aee-c-42` — 1: `v48542b44ffd26237`
- `aee-c-53` — 1: `va54b6faefcfb1f9e`
- `aee-c-65` — 1: `v1ec06de44fe4000d`
- `aee-c-71` — 1: `v164cf7f3f529eaff`
- `aee-c-75` — 1: `v081d9eeddbd5634f`
- `aee-c-84` — 1: `v3c3a76f63bf8dda8`
- `aee-c-88` — 1: `v3eb268f467674845`
- `aee-c-96` — 1: `vd538496f284b4761`

## Reason parity

Reported as its own figure, per the manifest's comparison surface. This
rail's codes are declared in `aee/findings.py` and are not intended to
match the reference verifier's vocabulary.

| code | vectors |
|---|---|
| `cv-record-class` | 36 |
| `cv-record-member` | 25 |
| `cv-payload-parse` | 20 |
| `cv-run-binding` | 18 |
| `cv-observed-set` | 17 |
| `wf-result-recompute` | 12 |
| `cv-sealed-existence` | 11 |
| `cv-batch-root` | 8 |
| `ijson-profile` | 8 |
| `cv-orphan-interception` | 7 |
| `wf-observation-ref-range` | 7 |
| `wf-row-vocabulary` | 7 |
| `cv-method-strength` | 6 |
| `cv-observed-attacks-row` | 6 |
| `wf-missing-member` | 6 |
| `wf-row-member` | 6 |
| `cv-pinned-commitment` | 5 |
| `cv-posture-digest` | 5 |
| `cv-record-method` | 5 |
| `wf-expected-payloads` | 5 |
| `wf-timestamp-profile` | 5 |
| `cv-record-signatures` | 4 |
| `wf-coverage-integrity` | 4 |
| `cv-payload-reserved` | 3 |
| `cv-pinned-no-interception` | 3 |
| `wf-clean-row-actual-layer` | 3 |
| `wf-posture-vocabulary` | 3 |
| `cv-assessed-subset` | 2 |
| `cv-pinned-no-expectation` | 2 |
| `wf-array-order` | 2 |
| `wf-coverage-partition` | 2 |
| `wf-manifest-floor` | 2 |
| `wf-result-token` | 2 |
| `cv-armed-after-issued` | 1 |
| `cv-array-order` | 1 |
| `cv-clean-row-interception` | 1 |
| `cv-media-type` | 1 |
| `cv-payload-bmp` | 1 |
| `cv-payload-canonical` | 1 |
| `cv-refs-empty` | 1 |
| `wf-array-duplicate` | 1 |
| `wf-batch-root` | 1 |
| `wf-caught-subset` | 1 |
| `wf-corpus-digest` | 1 |
| `wf-duplicate-attack-id` | 1 |
| `wf-manifest-class-overlap` | 1 |
| `wf-manifest-shape` | 1 |
| `wf-predicate-type` | 1 |
| `wf-run-entropy` | 1 |
| `wf-statement-type` | 1 |
| `wf-subject` | 1 |
| `wf-unknown-attack-id` | 1 |
| `wf-vocabulary-bmp` | 1 |
| `wf-vocabulary-digest` | 1 |
| `wf-vocabulary-shape` | 1 |

