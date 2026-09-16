# aee-e2 — independent E2 validator for Adversarial Execution Evidence v0.7

Second implementation (E2) for [in-toto/attestation#570][pr], written from the specification
text alone, per §e3 of the [ITE draft at `58eee06`][ite]. Seat accepted by the spec author on
2026-09-15; terms and the head-vs-corpus spec drift are declared in [comment 5696811312][c].

Python, standard library only. No third-party dependencies, at any point.

## Evidence order

This repository is committed in the order agreed on the PR before any code was written:

1. **Spec text pinned by digest** — `spec/SPEC-PIN.json`, with both revisions vendored as bytes.
2. **Corpus digest as published at v0.10.1** — `spec/CORPUS-PIN.json`, digests file vendored.
3. **First run with raw output, before any fix** — not yet taken.
4. **Resolution log** — follows the first run.

Steps 1 and 2 are this commit. Step 3 is committed before any directed fix is made, so the first
run is reproducible from this tree whatever the score turns out to be.

## Reading notes

`NOTES.md` records places where the text underdetermines a reading, with the
reading taken, the reason, and the alternative left on the table. Entries are
written as they arise and before the first run, so that a divergence traced to
one of them can be told apart from a mistake.

## Independence

Not consulted, and not to be consulted before step 3 is committed: the Rust `aee-checker`, the
reference Go reader in the corpus repository, `vectors/interpretation-decisions.json`,
`vectors/CHANGES.md`, `crosswalks/`, `DISPOSITIONS.md`. The manifest is read at scoring time,
which is unavoidable; it is not read to tune behaviour beforehand.

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
