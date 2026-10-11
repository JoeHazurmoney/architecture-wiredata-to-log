# ADR-0002: Flag opaque content in Enclave 1, and let it cross

**Status:** Proposed
**Date:** 2026-10-04
**Deciders:** System owner and ISSO.

## Context

The question: what happens if encrypted data shows up in the Enclave 1 log stream? Can we tell
that it's encrypted, and what should we do about it?

* Until now wd2l didn't look at log content. `_raw` crossed exactly as received, and the
  [accreditation notes](../accreditation-notes.md) listed content filtering as out of scope.
* Encrypted data in a log can be harmless (a certificate, a compressed debug dump, a token an
  application logs), evidence an analyst needs (malware traffic in a proxy log), or a way to move
  information that shouldn't move.
* The flow's direction relative to each enclave's sensitivity follows the rule in the
  [README](../../README.md). So this is mainly a question of visibility and policy, and nothing
  that crosses is run.
* Constraints: losses are detected and reported, never silent. The link is one-way. Volume is
  under 1,000 events/s. The sender uses only the Python standard library.

## Can encrypted data be recognized?

Partly: reliably enough to flag it, never well enough to prove it.

* A log line is text, so binary data appears in it encoded (base64, base64url, hex) or inside an
  armor block (PGP). Long runs of those can be found and decoded.
* Once decoded, encrypted data, compressed data and random keys look alike: about 8 bits of
  entropy per byte and no readable structure. Markers separate some of them. PGP and age armor,
  OpenSSL's `Salted__` and the age header mean encrypted. gzip, zlib, zip, bzip2, xz and zstd
  headers mean compressed. With no marker, "high-entropy" is as far as anyone can go.
* Short random strings are everywhere in normal logs: hashes, GUIDs, session IDs, signatures.
  They're too short to judge, so only blobs of 256 decoded bytes or more count (armor blocks
  count at any size).
* Encoded readable text, such as a PowerShell `-EncodedCommand`, decodes to text, so it isn't
  opaque.
* What can't be found: data hidden in ordinary-looking text, through word choice, spacing,
  splitting across many events, or timing. Detection is a tripwire for blobs, not proof that
  nothing is hidden.

Checked on 17,624 real log lines (`samples/logs`): no findings. The lab's three planted blobs (a
random blob, a gzip blob, a PGP message) are all flagged.

## Decision

`wd2l-sender` inspects each event's `_raw` (`wd2l/opaque.py`) and flags opaque content with two
indexed fields: `wd2l_opaque` (`encrypted`, `compressed` or `high-entropy`) and
`wd2l_opaque_bytes` (the blob's decoded size).

* Flagged events **cross unchanged**.
* The sender counts them: `opaque_events` in its heartbeat, and `sender_opaque_events` in the
  receiver's health records.
* A SIEM alert lists them by host and source.
* It's on by default. `--no-opaque-check` turns it off.

## Options considered

### Option A: do nothing (the previous state)

| Dimension | Assessment |
|---|---|
| Complexity | None |
| Completeness | Unaffected |
| Visibility | None: encrypted content crosses unnoticed |
| False positives | None |
| Accreditation | Content filtering stays out of scope |

**Pros:** nothing to build or tune.
**Cons:** no one can answer "did anything encrypted cross?"

### Option B: flag and let it cross (chosen)

| Dimension | Assessment |
|---|---|
| Complexity | Low: one standard-library module |
| Cost | A regex scan per event, small at under 1,000 events/s |
| Completeness | Unaffected: nothing is withheld |
| Visibility | Every flagged event, with host, source, kind and size, is searchable and alerted on |
| False positives | Cheap: a tag on an event that crossed anyway |
| Accreditation | Evidence for AC-4(8) and AC-4(15). Doesn't enforce AC-4(4) |

**Pros:** visibility with no loss. Analysts keep the blob.
**Cons:** detects but doesn't stop. Benign sources will trigger the alert until they're reviewed.

### Option C: redact the blob

Replace only the blob in `_raw` with a marker (kind, size, SHA-256) and keep the rest of the line.
The original stays on the Enclave 1 log retention server.

| Dimension | Assessment |
|---|---|
| Complexity | Medium |
| Completeness | The event crosses, but changed. Byte-for-byte file rebuilds break for those lines |
| Visibility | Analysts see that something was removed, not what |
| False positives | Costly: a legitimate payload is cut out |
| Accreditation | Meets AC-4(4) by modifying the content |

### Option D: hold in Enclave 1

The event doesn't cross. A stub (host, source, time, kind, size, SHA-256) crosses instead, so
the numbering stays complete. The original is kept on the log retention server for review and
release.

| Dimension | Assessment |
|---|---|
| Complexity | High: a quarantine store, plus a review and release procedure |
| Completeness | Reported by the stub, but the content is delayed, or lost if never released |
| Visibility | Analysts wait for a review |
| False positives | Costly: a legitimate event is withheld |
| Accreditation | Strongest: blocks or quarantines (AC-4(4), AC-4(8)) |

## Trade-off analysis

* **Direction of the flow.** Under the README's direction rule, the main value is visibility, so
  flagging gives most of the benefit at the least cost.
* **Detect and report.** B keeps every event. D turns some into stubs. A hides the question.
* **The SOC needs the blobs.** Encrypted command-and-control traffic in a proxy log is evidence.
  C and D take it away from analysts.
* **False positives.** With B a wrong flag costs a glance. With C or D it changes or withholds a
  legitimate event.
* **The detection limits apply to every option.** None of them catches data hidden in normal
  text. B is honest about being a tripwire.
* **NIST.** AC-4(4) (Flow Control of Encrypted Information) is in the High baseline, not
  Moderate. Its guidance counts unrecognized encoded data as encryption. B detects but doesn't
  prevent, so if the ISSO tailors AC-4(4) in for this cross-domain flow, C or D is needed.

## Consequences

* **Easier:** answering "did anything encrypted cross, from where?" Search `wd2l_opaque=*`.
* **Harder:** the alert will fire for some benign sources (applications that log compressed or
  encrypted payloads). Each source needs a one-time review and, if it's benign, a note or a
  suppression in the alert.
* **Revisit when:**
  1. the direction rule in the [README](../../README.md) changes;
  2. the ISSO tailors in AC-4(4) or AC-4(15) enforcement (then C or D);
  3. the alerts, or a review, show a real channel.

## Controls

| Control | How this design relates |
|---|---|
| AC-4(4) Flow Control of Encrypted Information | High baseline, not required at Moderate. Flagging detects but doesn't prevent; C or D would meet it |
| AC-4(8) Security and Privacy Policy Filters | The detector is a content filter. Its action on a match is "flag" |
| AC-4(15) Detection of Unsanctioned Information | Detection is in place for opaque blobs. Prohibiting the transfer would need D |
| SI-4 System Monitoring | The alert and the counters |

## Action items

1. [ ] ISSO: confirm flag-and-pass, or require redact or hold.
2. [ ] Review the first weeks of alerts and record the known benign sources.
3. [ ] Optional: also flag executables (MZ and ELF headers) and other encodings (base32, base85).
4. [ ] Once the audit module exists: an `opaque_content` audit record
   ([audit design](../audit-and-health.md), section 4).
