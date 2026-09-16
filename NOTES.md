# Reading notes

Places where the specification underdetermines a reading, or where a choice was
made that a second reader could reasonably have made differently. Recorded as
they arose, before the first run, so that a divergence traced to one of them can
be told apart from a mistake.

Prerequisites says the standard for these directly:

> Where the text underdetermines a reading and no conformance vector exercises
> it, two implementations agreeing on that reading is evidence the text is
> determinate, not proof of it -- the reading is untested rather than confirmed,
> and a third implementation could differ there in silence.

So each entry below names the reading taken and the alternative left on the
table, rather than asserting the text is clear.

---

## 1. The safe-integer rule and exponent-form numbers

**Text.** "Producers MUST enforce the RFC 7493 (I-JSON) safe-integer profile on
canonicalized content: integers with magnitude at or above 2^53 MUST be
rejected."

**Question.** Is `1e21` an "integer" for this rule? Its value is integral and far
above the bound, but it is not written in integer form.

**Reading taken.** The rule applies to numbers written in integer form. `1e21`
parses.

**Why.** The same Prerequisites section pins RFC 8785, whose number layout gives
`1e+21` an explicit canonical form. A blanket refusal of integral values above
2^53 would make that layout unreachable, so the narrower reading is the one
consistent with the rest of the section.

**Alternative.** Refuse any number whose value is integral and at or above the
bound, regardless of how it is written. A rail taking that reading refuses input
this one accepts.

**Where.** `aee/ijson.py`, `_Scanner.number`.

---

## 2. What the PAE runs over

**Text.** "a consumer verifies each record's signature, DSSE PAE over
`(payloadType, payload)`" -- where `payload` is "base64 of the exact canonical
bytes the substrate signed".

**Question.** Does the PAE body take the base64 text as carried, or the bytes it
decodes to?

**Reading taken.** The decoded bytes.

**Why.** DSSE is referenced normatively and defines PAE over the serialised
body, which the envelope carries base64-encoded. This is a reading of a
referenced document rather than a free choice, but the sentence in isolation
admits both, so it is recorded.

**Where.** `aee/dsse.py`, `pae_for_record`.

---

## 3. Where the safe-integer rule is enforced

**Reading taken.** The canonicaliser refuses a Python `int` of magnitude 2^53 or
above, because no faithful double exists for it. It does not police `float`
magnitudes, which are already doubles, and formats them by the ECMAScript rules
whatever their size.

**Why.** Refusing an out-of-range number on the way *in* is the reader's job and
is done there, against the raw bytes, which is where the text puts it. A
serialiser that also refused would duplicate the check in the wrong place and
could not be used to emit a value the profile permits.

**Where.** `aee/jcs.py`, `_serialize`; `aee/ijson.py`, `_Scanner.number`.

---

## 4. Noncharacters produced by escapes

**Text.** The noncharacters are "rejected wherever a string literal appears, at
any depth and in both member-name and value position."

**Reading taken.** A noncharacter reached through a `\u` escape, including one
assembled from a surrogate pair such as `🿾` for U+1FFFE, is refused
exactly as a literal one is.

**Why.** The rule is about the code point a string denotes, not the bytes that
spell it. The opposite reading would let any noncharacter through by escaping
it, which would leave the rule with no effect.

**Where.** `aee/ijson.py`, `_Scanner.escape`.

---

## 5. The empty observed set

**Reading taken.** A run whose substrate emitted no `interception` or
`examination` record commits to the canonicalisation of the empty array, so
`aeeObservedSet` is `sha256("[]")`.

**Why.** The definition is a total function of the carried records and names no
exception for emptiness. A seal that omitted the member instead would be making
a different claim -- silence rather than "nothing was emitted" -- and the text
requires the member on every `sealed` record.

**Alternative.** Treat the empty case as unreachable, on the grounds that a
statement carrying a `basis: substrate` row needs covering records. That would
make the value undefined rather than computed.

**Where.** `aee/observed_set.py`.

---

## 6. Relying on Python's UTF-8 decoder for the encoding half

**Text.** "A verifier MUST therefore apply this check to the raw bytes, before
any decoded string is read."

**Reading taken.** Decoding with a decoder that *raises* rather than substitutes
satisfies this, and the remaining rules are enforced by the scan.

**Why.** The stated reason for the rule is that "a lenient decoder does not fail
on ill-formed bytes, it substitutes U+FFFD for them, and every check downstream
of the decode then reads a string the producer never wrote". A strict decoder
manufactures no U+FFFD, so no downstream check can read one. Python's strict
UTF-8 decoder also refuses overlong forms and surrogates encoded directly in
UTF-8, which are the two encoding defects the text names.

**Alternative.** Scan the raw bytes without decoding at all. That is stricter in
letter and identical in effect here; it would matter if the decoder were
lenient, which is exactly what is being avoided.

**Where.** `aee/ijson.py`, `loads`.

---

## 7. A missing `containmentObserved` under the first condition

**Text.** The first condition holds when a row "carries a containment-observed
label from the carried caught set ..., a label outside the carried
`observationVocabulary.labels` (fail-closed), or a missing or out-of-vocabulary
`basis`, `method` or `attribution` (fail-closed)".

**Question.** The sentence spells out *missing* for the three axes but not for
`containmentObserved`. What does the recompute do when the member is absent?

**Reading taken.** Absent counts as "outside the carried labels", so the
condition holds and contributes `fail`.

**Why.** A member that is not there is not in the carried set, and the
fail-closed direction is the one the same sentence takes everywhere else. The
recompute is also defined as total, so it must answer rather than decline.

**Alternative.** Treat the omission as a well-formedness fault only, leaving the
recompute to run on the remaining rows. The statement is invalid either way, so
the two readings differ in the refusal given, not in the verdict -- and refusal
codes are measured rather than scored.

**Where.** `aee/result.py`, `_condition_one`.

---

## 8. The recompute on a malformed predicate

**Reading taken.** `recompute_result` never raises. Anything it cannot read
resolves fail-closed: an absent vocabulary yields empty carried sets, which puts
every label outside them and contributes `fail`.

**Why.** "Defined as a total, deterministic, severity-independent function of
the predicate". A function that throws on some predicates is not total, and the
verifier would then depend on the well-formedness gate having run first, which
the two-stage description does not promise.

**Where.** `aee/result.py`, `recompute_result` and `_vocabulary`.
