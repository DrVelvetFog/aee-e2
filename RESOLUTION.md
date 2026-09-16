# Resolution log

Step four of the order agreed on [in-toto/attestation#570][pr] and confirmed by
the spec author: spec text pinned by digest, corpus digest as published, first
run with raw output before any fix, then this.

The first run is `reports/FIRST-RUN.md`, committed at `c3686c4` with no source
file changed between the run and the commit. Everything below was written after
reading it. Nothing below has been applied yet: this state of the log is the
diagnosis and the disposition, so that what gets changed and why is on the
record before the change, not reconstructed after it.

    vectors            272
    verdict matches    236  (86.8%)
    result matches      54 / 54 of the accepts we agreed on (100%)
    divergences         36  — 29 too permissive, 7 too strict

Sources used for diagnosis: the two vendored spec texts, and the vector bytes.
Not used, and still unopened: the Rust `aee-checker` and its parity report, the
reference Go reader, the suite's interpretation registry,
`vectors/interpretation-decisions.json`, `vectors/CHANGES.md`, `crosswalks/`,
`DISPOSITIONS.md`.

---

## R1 — Fail-closed row members were checked at the wrong altitude

**Vectors (5, too strict).** `v18bdbadef67b38f4` (`aee-c-1`),
`v51e9223d08fcc4e1` (`aee-c-5`, `aee-c-44`), `vea21d85d4e531e66` (`aee-c-43`),
`v48542b44ffd26237` (`aee-c-5`, `aee-c-42`, `aee-c-44`), `v948fbb64b96197e6`
(`aee-c-5`, `aee-c-43`). All expect `valid` with `result: fail`. This
implementation refused them, emitting `wf-row-member` or `wf-row-vocabulary`.

**What the vectors carry.** A single row with a missing `basis`, a missing
`method`, or an out-of-vocabulary value — `basis: "substrate_observed"`,
`method: "example_unknown_method"`, `method: "inferred"`.

**What the spec says.** The first condition of the `result` recompute holds when
a row carries "a missing or out-of-vocabulary `basis`, `method` or
`attribution` (fail-closed), and it contributes `fail`". The altitude is then
stated outright under `actualLayer`:

> fail-closed-row semantics are reserved for members the recompute or the
> documented consumer gating reads (`containmentObserved`, `basis`, `method`);
> `actualLayer` is read by neither, so its absence is a malformed statement, not
> weak evidence.

So a missing or unknown `basis`/`method`/`attribution` makes the statement
**valid with `result: fail`**. A missing `actualLayer` makes it **malformed**.
The two are deliberately opposite, and this implementation applied the
`actualLayer` treatment to all four members.

**Verdict on the divergence.** This implementation is wrong. The rule is stated
explicitly and was quoted correctly in `aee/result.py`'s own docstring, then
contradicted in `aee/wellformed.py`, which listed `basis`, `method` and
`attribution` among the members whose absence is a well-formedness fault and
added a closed-vocabulary check beside it. The recompute already handled all
five vectors correctly; the well-formedness gate overrode it.

**Disposition.** Remove `basis`, `method` and `attribution` from the
well-formedness required-member list and delete the row-vocabulary check.
`attackId`, `containmentObserved` and `actualLayer` stay. Expected effect: five
divergences resolved, and no vector currently matching should move, because the
recompute's fail-closed arm already produces `fail` for exactly these rows.

---

## R2 — Method strength was compared against records that cover nothing

**Vectors (2, too strict).** `v164cf7f3f529eaff` (`aee-c-23`, `aee-c-45`,
`aee-c-71`) and `v7d2a79cb1ddc59a5` (`aee-c-23`, `aee-c-45`, `aee-c-106`,
`aee-c-107`). Both expect `valid` with `result: pass`. This implementation
refused them with `cv-method-strength`.

**What the vectors carry.** A clean `basis: substrate`, `method: intercepted`
row resolving an `arming` record and a `sealed` record, both
`aeeMethod: intercepted` — and alongside them a record of a kind that covers
nothing: `aee-future-x` (unrecognised) in the first, `moat-drop` and
`uncommitted-observation` in the second, each `aeeMethod: reconstructed`.

**What the spec says.** The requirement is that "the row's `method` is no
stronger than the weakest `aeeMethod` across **its covering records**". The
kinds in question cover nothing by registration or by not being recognised:
`moat-drop` and `uncommitted-observation` "cover nothing, carry no constraints
of their own", and a "record whose `aeeKind` the consumer does not recognize
covers nothing".

**Verdict on the divergence.** This implementation is wrong. It took the minimum
`aeeMethod` across every resolved record rather than across the covering ones,
so a record that contributes nothing to the row's claim was allowed to weaken
it. One word of the requirement, dropped.

**Disposition.** Restrict the strength comparison to records whose `aeeKind` is
in `COVERING_KINDS`. Expected effect: two divergences resolved.

---

## R3 — The chain-of-runs reserved members are not implemented

**Vectors (7, too permissive).** `vef2571e9001d7bd1`, `v3cf298b019a0405f`,
`v2bac3fa36d7a5947`, `v8a7008d1673711a9`, `v4360d4e15f84145f`,
`v04993666ec44cda9`, `v8a7532ae4cffa163` — all `aee-c-89`, all expecting
`invalid` with the reference code `arming-covers-nothing`. This implementation
accepted every one.

**What the vectors carry.** An `arming` record with one of `aeeRunSeq: 0`;
`aeeRunSeq: 1` and no `aeeChainScope`; `aeePrevRunBinding:
"EXAMPLE-NOT-64-HEX"`; `aeeChainScope` as a string rather than an array.

**What the spec says.** A third reserved-member family this implementation never
read, at the head's lines 1672-1712: `aeeRunSeq` (a positive safe-range
integer), `aeePrevRunBinding` (lowercase 64-hex, "absent exactly when
`aeeRunSeq` is `1`"), and `aeeChainScope` (a closed-vocabulary array over
`subject`, `corpus`, `networkPosture`, in UTF-16 code-unit order, duplicate-free,
"REQUIRED whenever `aeeRunSeq` is present"). The consequence is stated:

> A violation of the syntax rules (a non-positive or non-integer `aeeRunSeq`, a
> malformed `aeePrevRunBinding`, a missing `aeeChainScope` when the sequence is
> present, a non-array `aeeChainScope`, an array carrying a token outside the
> registered vocabulary, an array not in canonical order ..., or any of the
> three present without `aeeRunSeq`) is handled as any reserved-member
> violation: the record covers nothing.

Each of the four sample vectors hits a different clause of that list.

**Verdict on the divergence.** Not a disagreement and not an ambiguity: an
omission. The scope read for this implementation enumerated the four reserved
members under `observationRecords` and missed this family, which sits several
hundred lines later under the producer-vocabulary rules rather than beside the
other four.

**Disposition.** Implement the syntax rules as arming-kind constraints. Note
that "nothing else normative reads them" within one attestation — they are
syntax-checked in the reserved-member walk and touch neither the recompute, the
coverage requirements, nor the tier — so the implementation is a syntax gate and
must not reach further. Expected effect: seven divergences resolved.

---

## R4 — A seal reporting its moat down is a violation even when unresolved

**Vectors (5, too permissive).** `v4da2f99ac2897154`, `v80e2a3fba582ed4d`,
`vd7be865fc69eacc2`, `vfb979cb9ce40f1be`, `vb1337e5ecad985c2` — all `aee-c-108`,
all expecting `invalid` with the reference code `sealed-covers-nothing`. This
implementation accepted every one.

**What the vectors carry.** Three records: an `arming`, a `sealed` with
`aeeStillArmed: false`, and a second `sealed` with `aeeStillArmed: true`. The
row resolves indexes 0 and 2, so the seal it depends on is the good one and the
moat-down seal is carried but unresolved.

**What the spec says.** This exact shape is the worked example the universal
partner requirement is written against:

> A constraint evaluated only where a row points is a constraint whose subject
> the producer chooses: a substrate signs a `sealed` record reporting its moat
> down, the producer carries that record and points the row at a second seal,
> and the run reads clean with the record that says otherwise sitting in the
> statement and inside `batchRoot`.

The requirement itself: "every carried record that binds to this run and whose
payload `aeeKind` names a covering kind ... satisfies every constraint of that
kind, whether or not any row resolves an `observationRefs` index to it".

**Verdict on the divergence.** This implementation is wrong, and the spec names
the case. `_check_kind` for `sealed` checked that `aeeStillArmed` is present and
a boolean, but not that the conditions stated at the kind's class definition
hold. The covering conditions — `aeeStillArmed` true, `aeeDropCount` zero or
within a declared `aeeDropBound` — are constraints of the kind, and the
universal partner evaluates them against every carried binding seal.

**Disposition.** Fold the class-definition conditions into the sealed kind
check, so a carried binding seal that covers nothing is a finding whether or not
a row resolves it. Keep the row-scoped `_seal_covers` separately, since it also
compares against "the `aeePostureDigest` of every `arming` record the row
resolves", which is row-relative and cannot move to the kind check. Expected
effect: five divergences resolved.

**Note on the drift constant.** This entry sits next to
`SEALED_POSTURE_IS_A_KIND_CONSTRAINT` and is not the same question. R4 is about
`aeeStillArmed`, which both spec revisions treat identically. The drift hunk is
about `aeePostureDigest`, and no vector in this corpus exercises it — see below.

---

## The drift hunk was not exercised

Zero divergences cite `cv-posture-digest` or `cv-sealed-existence`. The head
reading and the `0dbe10bc` reading produce the same score on all 272 vectors, so
the choice between them did not affect this run. `DRIFT.md`'s prediction — that
a divergence traceable to hunk `1333c1392,1393` could only run one direction —
is neither confirmed nor falsified here, because the corpus contains nothing
that separates the two texts.

That is worth reporting on the PR as a result in its own right: the pending
head-versus-`0dbe10bc` decision is moot for this corpus at this suiteRevision.

---

## Still open

Seventeen divergences are not yet diagnosed. Recording them now, undiagnosed,
rather than after the fact:

| condition | divergences | direction |
|---|---|---|
| `aee-c-58` | 3 | too permissive |
| `aee-c-82` | 3 | too permissive |
| `aee-c-59` | 2 | too permissive |
| `aee-c-4` | 2 | too permissive |
| `aee-c-19`, `aee-c-31`, `aee-c-53`, `aee-c-65`, `aee-c-75`, `aee-c-84`, `aee-c-88`, `aee-c-96` | 1 each | too permissive |

All seventeen are in the permissive direction, which is consistent with the
shape of the first three resolved entries: the gaps in this implementation are
rules not reached, not rules read differently. Whether any of them turns out to
be a genuine disagreement rather than an omission is not yet known, and this log
will say which when each is worked.

## What the run establishes about the implementation

Two things worth separating from the score.

The `result` recompute was correct on every statement it was asked about: 54 of
54 accepted statements carried the token this implementation derived, across all
four values. No divergence anywhere in the run is a `result` disagreement on an
accepted statement.

Every divergence diagnosed so far is an implementation fault, not a reading the
spec leaves open. Three are omissions and one is an altitude error. None of the
nine readings recorded in `NOTES.md` before the run has produced a divergence.

[pr]: https://github.com/in-toto/attestation/pull/570
