# Hand-off: wd2l (wire data to log)

Summary to start a new conversation. Read this first, then the docs it points to.

## Project
- Repo `JoeHazurmoney/architecture-wiredata-to-log` ("wd2l"). One-way log transfer: Enclave 1
  hosts → log aggregator (Cribl Stream in practice) → `wd2l-sender` (numbers events, UDP to a
  black-hole IP with static ARP) → inline **network tap** → **one fiber strand, TX only** →
  Enclave 2 capture NIC → `wd2l-receiver` (rebuild, verify, report gaps) → SIEM (Splunk in
  practice, HEC format) + tcpdump pcap archive for replay.
- Python stdlib only, ≥3.9. Lab = Linux network namespaces (`lab/run-lab.sh`).

## User and environment facts (decisions already made)
- Terminology: **Enclave 1 / Enclave 2** (never low/high side). Product-neutral docs: "log
  aggregator", "SIEM", "network tap"; products only as examples. Code identifiers keep product
  names (`CriblHandler`, `fake_cribl.py`, `--hec-*`, `deploy/receiver/splunk/`).
- Docs: RHEL-family commands first, Ubuntu as notes. Plain language, direct, minimal jargon,
  push back when needed. Mermaid diagrams, not ASCII.
- Cross-domain: the one-strand TX-only fiber method is already accredited in another enclave.
- Compliance: **NIST SP 800-53 Rev 5, Moderate** baseline; audit retention **1 year**.
- Time: GPS SAASM receiver in each enclave → switch at stratum 2 → hosts via chrony (stratum 3).
- **No SIEM in Enclave 1** (only a central log server); Splunk in Enclave 2.
- Volume < 1,000 events/s. Loss handling: detect and report (no retransmission).
- Real pipeline: Splunk UF tails continuously written logs → Cribl Stream → wd2l-sender.

## Repo state (as of 2026-10-04)
- `main` @ `0d28c83`: PR #1 (POC), #2 (user's fixes: durable delivery, sender drain, stream
  linking, CI workflow), #3 (real sample logs + `--files` byte-for-byte lab, audit/health plan doc).
  All squash-merged by the user.
- Branch **`architecture-wd2l` @ `5d5467f`, not merged, no PR yet, CI green**: interleaved
  multi-file reconstruction —
  - `wd2l-sender --source-seq` (opt-in): per-(host, source) counter → indexed field `wd2l_src_seq`.
  - `lab/files_to_events.py --interleave`: merge files by each line's timestamp (syslog/auditd).
  - `lab/rebuild_files.py`: rebuild by (host, source) ordered by `wd2l_src_seq`; names missing
    lines; statuses MATCH / INCOMPLETE / NO-LINE-NUMBERS / MULTIPLE-RUNS / DIFFERENT.
  - `run-lab.sh --interleave`, `verify.py --source-seq`, CI step, `docs/multiple-files.md`.
  - Results: 17,624 interleaved lines (501 source switches), all three files SHA-256 MATCH; with
    `--loss 1` the 182 missing (file, line) pairs equal the receiver's 182 stream gaps.
- Tests: 105 pass (`python3 -m pytest`). Lab runs: default, `--loss 1`, `--receiver-outage`,
  `--receiver-crash`, `--files …`, `--interleave --files …` (all in CI).
- Sample logs: `samples/logs/{messages,secure,audit.log}` (real, from a disposable VM; sanitized:
  `sample-host`, loopback only, throwaway users) + `SHA256SUMS` + `samples/generate-sample-logs.sh`.

## Key docs
`docs/architecture.md`, `wire-format.md`, `deployment/{network,log-server,receiver}.md`,
`operations.md`, `accreditation-notes.md`, `running-the-lab.md` (§8 real files, interleaved),
`audit-and-health-plan.md` (proposal), `multiple-files.md` (on the branch).

## Open work / next steps
1. Decide on a PR for `architecture-wd2l` (interleave work).
2. **Audit & health plan** (`docs/audit-and-health-plan.md`) — proposal only, not built. Phases:
   1 audit module + catalog + JSON op logs; 2 per-segment health signals + in-band Enclave 1
   records; 3 running-hash reconciliation + `wd2l-audit-report`; 4 Splunk fault-segment
   dashboard, alerts, auditd rules. ISSO decisions pending (§17): AU-2 event list, AU-5 behavior
   (proposed: keep transferring), time thresholds, auditor role, Enclave 1 retention copy.
   Recommended first for MTTR: phase 2 + dashboard.
3. User will supply logs from their own Linux box as more seed data (don't commit real logs
   without review).
4. Production caveats for byte-exact files (in `multiple-files.md`): one event per line,
   newline stripped by event breaking, UF re-sends, rotation, sender restarts reset `wd2l_src_seq`.
5. Minor: unused `typing.Set` import in `wd2l/receiver.py` (from PR #2).

## Session mechanics learned
- This environment's git proxy and `gh api` **cannot delete branches** (HTTP 403); the user
  deletes them on GitHub. Creating PRs and merging via `gh api` works.
- The user deletes `architecture-wd2l` after merges; recreate it from `origin/main` for new work.
- PRs: squash-merge; the user usually reviews/merges, sometimes asks me to merge.
- Commit trailer lines: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and
  `Claude-Session: <session URL>`.
