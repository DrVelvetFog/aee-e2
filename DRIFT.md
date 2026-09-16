# Spec drift: which rules the four hunks touch

The corpus at `agent-evidence-vectors` v0.10.1 declares
`specUpstreamCommit 0dbe10bc` / `specDigest 759d2383…` (147,709 bytes, 2,322
lines). This implementation is written against the PR head `25ac8581` /
`2b7f3bc0…` (152,102 bytes, 2,383 lines). Both texts are vendored under `spec/`.

**This file is written before the first run, from the two spec texts alone. No
vector has been opened.** Its purpose is to fix the "known drift" label in
advance: a divergence that lands on a rule named here can be labelled as drift
because the label already existed, and a divergence that does not land on one
cannot borrow the label afterwards. A drift label invented after seeing a
divergence is an excuse, not a finding.

Method: `diff` the two vendored texts, locate each hunk in its section, and ask
of each — does it state, change or remove a rule that a verifier evaluates? The
question is answered from the surrounding normative text, not from what any
implementation does with it.

Raw diff: four hunks, 65 lines added, 4 removed.

---

## Hunk 1 — `644a645,676` (+32) — refusal-naming discipline

**Section.** The diagnostic tail of *Coverage validity*, immediately after the
paragraph on reporting the unmet existence requirement beside a defective
record's refusal.

**What it adds.** "Where a refusal names a comparison, the set it names MUST be
the set the implementation evaluated", followed by four shapes that break it: a
comparison over an empty operand set, a set wider than the check ranged over, a
commitment comparison described as ranging over a membership it cannot exhibit,
and a conjunct short-circuiting skipped.

**Rules touched.** None that decide a verdict. The added text closes with the
same disclaimer the paragraph above it carries: *"this document defines no
condition vocabulary, so what is fixed is what a refusal may claim to have
compared, never the identifier it is drawn under, and the obligation is
diagnostic and never a validity rule."*

**Can it move `verdict`?** No. **`result`?** No.

**Where it can show up.** In refusal text only — which the corpus manifest's
`comparisonSurface` marks as `measured`, not scored. A reason-parity difference
traceable here is drift; a verdict difference is not.

**Absent from `0dbe10bc` entirely**: that text contains no occurrence of "Where
a refusal names a comparison".

---

## Hunk 2 — `755a788,814` (+27) — the limit that `basis` names a vantage class

**Section.** The run of stated limits following the `aee*` reserved members,
after "One limit is common to all four and is stronger than any of them".

**What it adds.** That `basis` names a class of vantage and not the substrate
holding it, so syscall supervision from the host kernel and a hypervisor's read
of guest state are one value on the wire and derive the same tier, and a
consumer who did not provision the deployment cannot tell them apart.

**Rules touched.** None. The paragraph opens by saying so: *"A further limit
belongs to no member here and would not be closed by adding one."* It describes
what the existing two-value `basis` vocabulary cannot express; it does not
change the vocabulary, its membership, or any check that reads it.

**Can it move `verdict`?** No. **`result`?** No.

---

## Hunk 3 — `1333c1392,1393` — the sealed record's posture digest

**This is the only hunk that can change a verdict.**

**Section.** Inside `observationRecords`, in the constraint list for the
`sealed` kind.

**What it changes.** One line. `0dbe10bc` reads:

> `aeePostureDigest`, the effective posture at run-end; `aeeObservedSet`; and
> `aeeObservedAttacks`

`25ac8581` reads:

> `aeePostureDigest`, the effective posture at run-end, **equal to the pinned
> `networkPosture` digest**; `aeeObservedSet`; and `aeeObservedAttacks`

**Why this is not merely a restatement.** Both texts already carry, identically
and byte-for-byte, the covering condition further down:

> A `sealed` record covers no clean row unless its `aeeStillArmed` is `true`,
> its `aeeDropCount` is zero or does not exceed an `aeeDropBound` declared in
> the same signed payload, and its `aeePostureDigest` equals the pinned
> `networkPosture` digest and the `aeePostureDigest` of every `arming` record
> the row resolves

So under both texts a seal with a mismatched posture digest **covers nothing**.
What the head adds is the same equality as a constraint *of the kind*, and the
kind constraints have a wider reach. Coverage validity states:

> every carried record that binds to this run and whose payload `aeeKind` names
> a covering kind — `interception`, `arming`, `sealed`, `examination` —
> satisfies every constraint of that kind, **whether or not any row resolves an
> `observationRefs` index to it**

and, separately:

> a statement carrying at least one `basis: substrate` row carries at least one
> `sealed` record that **satisfies every constraint of its kind** and whose
> `aeeRunBinding` equals the derived run binding, whether or not any row
> resolves an index to it

Under `0dbe10bc` the posture equality is a *covering* condition, so it is
evaluated against the seals a clean row resolves. Under `25ac8581` it is also a
*kind* constraint, so it is evaluated against every carried seal that binds to
the run, resolved or not.

**The shape that differs.** A statement carrying a `sealed` record whose
`aeePostureDigest` does not equal the pinned `networkPosture` digest, where no
clean row depends on that seal for covering — for example a statement whose
rows are all caught, or one carrying a second seal beside the one relied on.
Under `0dbe10bc` such a statement can be valid. Under `25ac8581` it is invalid,
by the universal-partner requirement, and if it is the only seal then the
existence requirement is unmet as well.

**Can it move `verdict`?** Yes, `valid` → `invalid`, in that shape and no other
identified here. **`result`?** No: the recompute "never reads
`observationRecords`", so no record constraint can reach it.

**Direction.** The head is strictly stricter. Any divergence from this hunk
should show this implementation refusing a vector the corpus expects to be
accepted, never the reverse. A divergence in the opposite direction is not this
hunk and must not be labelled as it.

**Implemented at.** `aee/coverage.py`, behind `SEALED_POSTURE_IS_A_KIND_CONSTRAINT`.
Setting that to `False` gives the `0dbe10bc` behaviour.

---

## Hunk 4 — `1704,1706c1764,1767` — two axes becomes three

**Section.** The rules governing producer-defined axes inside a signed payload.

**What it changes.** "The two axes this predicate does order, `basis` and
`method`, are ordered because a normative reader consumes them" becomes "The
three axes this predicate does define, `basis`, `method` and `attribution`, are
defined because a normative reader consumes them".

**Rules touched.** None. `attribution` is already a required row member with a
closed vocabulary in `0dbe10bc`, which states at its own line 1093 that
"`basis`, `method` and `attribution` are REQUIRED on every row and all three
vocabularies are closed". The sentence corrected here was internally
inconsistent with that, and the correction is to the prose, not to the member.
The verb also moves from "order" to "define", which is the more accurate word
for `attribution`: it is not ranked by any ordering this document states.

**Can it move `verdict`?** No. **`result`?** No.

---

## Summary

| hunk | rule touched | moves `verdict` | moves `result` |
|---|---|---|---|
| `644a645,676` | refusal wording only, explicitly "never a validity rule" | no | no |
| `755a788,814` | none — a stated limit belonging to no member | no | no |
| `1333c1392,1393` | sealed kind constraint gains the posture equality | **yes**, one shape | no |
| `1704,1706c1764,1767` | prose correction; the member was already required | no | no |

One hunk of four can change a verdict, in one nameable shape, in one direction.
The other three cannot change either scored value, and a divergence attributed
to them would be a mistake wearing a drift label.
