# aee-e2 — independent E2 validator for Adversarial Execution Evidence v0.7

Second implementation (E2) for [in-toto/attestation#570][pr], written from the specification
text alone, per §e3 of the [ITE draft at `58eee06`][ite]. Seat accepted by the spec author on
2026-09-15; terms and the head-vs-corpus spec drift are declared in [comment 5696811312][c].

Python, standard library only. No third-party dependencies, at any point.

## Evidence order

This repository is committed in the order agreed on the PR before any code was written:

1. **Spec text pinned by digest** — `spec/SPEC-PIN.json`, with both revisions vendored as bytes.
2. **Corpus digest as published at v0.10.1** — `spec/CORPUS-PIN.json`, digests file vendored.
3. **First run with raw output, before any fix** — `reports/FIRST-RUN.md`, commit `c3686c4`.
4. **Resolution log** — `RESOLUTION.md`.

`git diff 0598d14 c3686c4 -- aee/ tools/ tests/ spec/` is empty: nothing but `reports/`
changed between the harness commit and the first-run commit, so the run is reproducible
from the committed tree.

## Reading notes

`NOTES.md` records places where the text underdetermines a reading, with the
reading taken, the reason, and the alternative left on the table. Entries are
written as they arise and before the first run, so that a divergence traced to
one of them can be told apart from a mistake.

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
