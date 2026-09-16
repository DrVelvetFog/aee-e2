#!/usr/bin/env python3
"""Run the conformance corpus and write the run report.

    python3 tools/run_corpus.py <corpus-checkout> [--out reports/]

The corpus checkout is a clone of ``astrogilda/agent-evidence-vectors`` at the
tag this repository pins in ``spec/CORPUS-PIN.json``. Nothing is fetched here;
the checkout is read.

What is scored, per the corpus manifest's ``comparisonSurface``: ``verdict``,
and on an accepted statement ``result``. Refusal ``codes`` are measured and
reported as their own figure, because they are this rail's vocabulary and not
the specification's.

The tool refuses to run unless the corpus it was handed is the corpus this
repository pinned. Scoring against an unverified corpus produces a number that
means nothing, and verifying afterwards is too late to have meant anything.
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from aee.verify import verify_bytes  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


class CorpusMismatch(RuntimeError):
    """The checkout is not the corpus this repository pinned."""


def check_corpus(corpus_root, pin):
    """Every check that can be made before a single vector is scored."""
    checks = []

    digests_path = corpus_root / "release" / "CORPUS-DIGESTS.txt"
    if not digests_path.exists():
        raise CorpusMismatch("release/CORPUS-DIGESTS.txt is absent from the checkout")
    carried = hashlib.sha256(digests_path.read_bytes()).hexdigest()
    checks.append(
        ("release/CORPUS-DIGESTS.txt sha256", carried, pin["vendoredDigestFileSha256"])
    )

    manifest_path = corpus_root / pin["manifest"]
    manifest = json.loads(manifest_path.read_text())
    checks.append(("manifest corpusDigest", manifest["corpusDigest"], pin["corpusDigest"]))
    checks.append(("manifest suite", manifest["suite"], pin["suite"]))
    checks.append(("vector count", len(manifest["vectors"]), pin["vectors"]))

    failures = [name for name, got, want in checks if got != want]
    if failures:
        detail = "\n".join(
            "  %-34s got %r want %r" % (name, got, want)
            for name, got, want in checks
            if got != want
        )
        raise CorpusMismatch("the checkout does not match the pin:\n" + detail)
    return manifest, checks


def run(corpus_root, manifest):
    """Score every vector. One pass, no retries, no per-vector special casing."""
    vectors_root = corpus_root / pathlib.PurePosixPath(
        "vectors"
    )
    rows = []
    for entry in manifest["vectors"]:
        raw = (vectors_root / entry["file"]).read_bytes()
        verdict = verify_bytes(raw)
        expected = entry["expected"]
        want_verdict = expected["verdict"]
        want_result = expected.get("result")

        verdict_match = verdict.verdict == want_verdict
        # result is scored only on an accepted statement.
        if want_verdict == "valid":
            result_match = verdict.result == want_result
        else:
            result_match = None

        rows.append(
            {
                "id": entry["id"],
                "kind": entry["kind"],
                "file": entry["file"],
                "conditions": entry.get("conditions", []),
                "expected_verdict": want_verdict,
                "expected_result": want_result,
                "got_verdict": verdict.verdict,
                "got_result": verdict.result,
                "verdict_match": verdict_match,
                "result_match": result_match,
                "codes": list(verdict.codes),
                "expected_codes": expected.get("codes"),
            }
        )
    return rows


def summarise(rows):
    scored = len(rows)
    verdict_ok = sum(1 for r in rows if r["verdict_match"])
    accepts = [r for r in rows if r["expected_verdict"] == "valid"]
    result_ok = sum(1 for r in accepts if r["result_match"])
    fully_ok = sum(
        1 for r in rows if r["verdict_match"] and r["result_match"] is not False
    )
    by_condition = {}
    for row in rows:
        if row["verdict_match"] and row["result_match"] is not False:
            continue
        for condition in row["conditions"] or ["(none)"]:
            by_condition.setdefault(condition, []).append(row["id"])
    return {
        "vectors": scored,
        "verdict_matches": verdict_ok,
        "accepts": len(accepts),
        "result_matches": result_ok,
        "fully_matching": fully_ok,
        "divergences": scored - fully_ok,
        "divergent_conditions": by_condition,
    }


def render(rows, summary, checks, pin, spec_pin, when):
    out = []
    w = out.append
    w("# First run")
    w("")
    w("Raw output of the first execution of this implementation against the")
    w("pinned corpus. Written before any fix. Nothing below has been edited in")
    w("response to what it says.")
    w("")
    w("    taken           %s" % when)
    w("    spec            %s" % spec_pin["head"]["commit"])
    w("    spec sha256     %s" % spec_pin["head"]["sha256"])
    w("    corpus          %s @ %s" % (pin["repo"], pin["tag"]))
    w("    corpus digest   %s" % pin["corpusDigest"])
    w("    suite           %s, suiteRevision %s" % (pin["suite"], pin["suiteRevision"]))
    w("    language        Python, standard library only")
    w("")
    w("## Corpus verified before scoring")
    w("")
    for name, got, want in checks:
        w("    %-34s %s" % (name, "ok" if got == want else "MISMATCH"))
    w("")
    w("## Score")
    w("")
    w("Scored surface is `verdict`, and `result` on an accepted statement. Codes")
    w("are measured, not scored, and are reported separately below.")
    w("")
    w("    vectors                 %d" % summary["vectors"])
    w("    verdict matches         %d / %d" % (summary["verdict_matches"], summary["vectors"]))
    w("    result matches          %d / %d (accepted statements only)" % (summary["result_matches"], summary["accepts"]))
    w("    fully matching          %d / %d" % (summary["fully_matching"], summary["vectors"]))
    w("    divergences             %d" % summary["divergences"])
    w("")
    w("## Divergences")
    w("")
    divergent = [
        r for r in rows if not (r["verdict_match"] and r["result_match"] is not False)
    ]
    if not divergent:
        w("None.")
    else:
        w("| id | conditions | expected | got | codes emitted |")
        w("|---|---|---|---|---|")
        for row in divergent:
            expected = row["expected_verdict"]
            if row["expected_result"]:
                expected += " / " + row["expected_result"]
            got = row["got_verdict"]
            if row["got_result"]:
                got += " / " + row["got_result"]
            w(
                "| `%s` | %s | %s | %s | %s |"
                % (
                    row["id"],
                    ", ".join("`%s`" % c for c in row["conditions"]) or "-",
                    expected,
                    got,
                    ", ".join("`%s`" % c for c in row["codes"][:4]) or "-",
                )
            )
        w("")
        w("### Divergences grouped by condition")
        w("")
        for condition, ids in sorted(
            summary["divergent_conditions"].items(), key=lambda kv: (-len(kv[1]), kv[0])
        ):
            w("- `%s` — %d: %s" % (condition, len(ids), ", ".join("`%s`" % i for i in ids[:8])))
    w("")
    w("## Reason parity")
    w("")
    w("Reported as its own figure, per the manifest's comparison surface. This")
    w("rail's codes are declared in `aee/findings.py` and are not intended to")
    w("match the reference verifier's vocabulary.")
    w("")
    counts = {}
    for row in rows:
        for code in row["codes"]:
            counts[code] = counts.get(code, 0) + 1
    w("| code | vectors |")
    w("|---|---|")
    for code, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        w("| `%s` | %d |" % (code, count))
    w("")
    return "\n".join(out) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=pathlib.Path, help="corpus checkout at the pinned tag")
    parser.add_argument("--out", type=pathlib.Path, default=ROOT / "reports")
    args = parser.parse_args(argv)

    pin = json.loads((ROOT / "spec" / "CORPUS-PIN.json").read_text())
    spec_pin = json.loads((ROOT / "spec" / "SPEC-PIN.json").read_text())

    try:
        manifest, checks = check_corpus(args.corpus, pin)
    except CorpusMismatch as exc:
        print("refusing to run: %s" % exc, file=sys.stderr)
        return 2

    rows = run(args.corpus, manifest)
    summary = summarise(rows)
    when = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "FIRST-RUN.md").write_text(
        render(rows, summary, checks, pin, spec_pin, when)
    )
    (args.out / "first-run.json").write_text(
        json.dumps({"taken": when, "summary": summary, "rows": rows}, indent=2, sort_keys=True) + "\n"
    )
    print(
        "%d vectors: %d verdict matches, %d/%d result matches, %d divergences"
        % (
            summary["vectors"],
            summary["verdict_matches"],
            summary["result_matches"],
            summary["accepts"],
            summary["divergences"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
