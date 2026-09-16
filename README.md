# aee-e2 — independent E2 validator for Adversarial Execution Evidence v0.7

Second implementation (E2) for [in-toto/attestation#570][pr], written from the specification
text alone, per §e3 of the [ITE draft at `58eee06`][ite]. Seat accepted by the spec author on
2026-09-15; terms and the head-vs-corpus spec drift are declared in [comment 5696811312][c].

## Language and tooling

Python, standard library only. No third-party dependencies, at any point.

**This implementation was written with an AI coding agent, Claude Code, essentially
throughout — the validator, the tests, the reading notes and the drift map.** The work was
directed and the claims and outward text were decided and reviewed by a person, but the code
is agent-written.

This is declared because the ITE's E2 definition asks for language and tooling to be declared
and, on the argument in [comment 5698439760][d], agent assistance belongs in that declaration:
agent-written implementations of one specification tend to fail together, concentrated where
the specification is hard or ambiguous. Two independently written rails is the property the
tier is buying; two rails out of the same model family is a weaker thing wearing the same
name, and nobody can see the difference unless it is declared. The other implementation of
this predicate, `aee-checker`, is also agent-written and declared so on the same day.

## Evidence order

This repository is committed in the order agreed on the PR before any code was written:

1. **Spec text pinned by digest** — `spec/SPEC-PIN.json`, with both revisions vendored as bytes.
2. **Corpus digest as published at v0.10.1** — `spec/CORPUS-PIN.json`, digests file vendored.
3. **First run with raw output, before any fix** — `reports/FIRST-RUN.md`, commit `c3686c4`.
4. **Resolution log** — `RESOLUTION.md`.

`git diff 0598d14 c3686c4 -- aee/ tools/ tests/ spec/` is empty: nothing but `reports/`
changed between the harness commit and the first-run commit, so the run is reproducible
from the committed tree.

**A limit of that, stated rather than left to be found.** This repository was created at
2026-09-16T12:55:28Z and pushed four seconds later with all sixteen commits already in it, so
every date in the history is one the author asserted. The ordering above is true, and nothing
outside this repository can check that it is true — which is a weaker claim than an
externally witnessed sequence. Pushing after the pin commit, or timestamping the pins, is what
would have made it checkable; the corpus ships `.sig`, `.ots` and `.tsr` beside its own
digests, so the remedy is in-ecosystem. Anything pre-registered here in future will use it.

## Reading notes

`NOTES.md` records places where the text underdetermines a reading, with the
reading taken, the reason, and the alternative left on the table. Entries are
written as they arise and before the first run, so that a divergence traced to
one of them can be told apart from a mistake.

None of the nine produced a divergence against the corpus. That was originally reported as
evidence the specification is determinate at those passages, and that reading has been
withdrawn: two agent-built rails agreeing tells you they share a prior, not that the text is
determinate. What the run establishes is the fifteen defects it corrected, which are
corrections rather than agreements.

## Independence

Not consulted, and not to be consulted before step 3 is committed: the Rust `aee-checker`,
including the interpretation-decisions section of its `PARITY-REPORT.md`; the reference Go
reader in the corpus repository; the suite's interpretation registry, including
`vectors/interpretation-decisions.json`; `vectors/CHANGES.md`; `crosswalks/`;
`DISPOSITIONS.md`. The manifest is read at scoring time, which is unavoidable; it is not read
to tune behaviour beforehand.

The registry and the parity report are on that list for the reason the other implementer put
best: after the first run they are a reconciliation surface, and before it they are an answer
key.

## Spec drift

`DRIFT.md` maps each of the four hunks between the corpus-pinned text and the head to the
rules it touches, written from the two spec texts before the first run. One hunk of four can
change a verdict, in one shape, in one direction; the other three cannot change either scored
value. Fixing that map in advance is what makes a "known drift" label a finding rather than an
excuse.

## Running the tests

```
python3 -m unittest discover -s tests -t .
```

No installation, no virtual environment, no third-party package. The modules
import cleanly under `python3 -S`.

## Scored surface

Per the corpus manifest's `comparisonSurface`: `verdict`, and on an accepted statement `result`,
are normative. Refusal `codes` are measured, not scored — this rail declares its own vocabulary
and reports reason parity as a separate figure.

[pr]: https://github.com/in-toto/attestation/pull/570
[ite]: https://github.com/in-toto/ITE/blob/58eee06534576ea250ff12f92a57fa5518b2c661/ITE/0000/README.adoc#e3
[c]: https://github.com/in-toto/attestation/pull/570#issuecomment-5696811312
[d]: https://github.com/in-toto/attestation/pull/570#issuecomment-5698439760
