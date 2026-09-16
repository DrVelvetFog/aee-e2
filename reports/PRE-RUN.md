# Corpus verified, before any vector was scored

Recorded at 2026-09-16T12:25:37Z, before the first run. Verifying a corpus after seeing a score
is worth nothing, so this is its own artefact with its own commit.

    checkout        astrogilda/agent-evidence-vectors @ v0.10.1
    HEAD            6c2fa6cc75b3e4f20368ba1637f56f52ac77b171
    pinned commit   6c2fa6cc75b3e4f20368ba1637f56f52ac77b171

## The corpus's own recomputation

`scripts/release-digests.py --check` recomputes every digest from the vector
files rather than reading it from a manifest. It needs nothing installed.

    exit status     0
    output          OK: release/CORPUS-DIGESTS.txt is exactly what the corpora on disk produce, and every digest in it was recomputed rather than read.

## Against the pin this repository committed first

`spec/CORPUS-PIN.json` was committed in 069a748, before any validator code existed.

| check | result |
|---|---|
| clone HEAD is the pinned commit | ok |
| `release/CORPUS-DIGESTS.txt` sha256 matches the vendored copy | ok |
| vendored digests file is byte-identical to the checkout's | ok |
| manifest `corpusDigest` | ok |
| manifest `suite` | ok |
| vector count | ok |

    corpusDigest    8b035678def9e5ac00ba761b8c640e4412c57163134afb9d2c1a90f49d573a52
    suite           adversarial-execution-evidence-conformance
    vectors         272 at suiteRevision 28

The harness refuses to score a checkout that fails any of these, so a run that
produced a number at all is a run against this corpus.
