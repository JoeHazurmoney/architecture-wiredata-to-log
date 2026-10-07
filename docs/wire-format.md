# Wire format (WD2L version 1)

One UDP datagram carries one frame, from `10.255.255.1:5514` to `10.255.255.2:5514`. All
integers are big-endian. The implementation is `wd2l/wire.py`.

This page is the developer reference for the frame and the receiver's rules. For the whole packet
(Ethernet, IPv4 and UDP headers included), every field's type, size and range, rates, and
annotated captures, written for the interface control document, see
[interface-description.md](interface-description.md).

## Frame

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `WD2L` |
| 4 | 1 | `version` | `1` |
| 5 | 1 | `type` | `1` = DATA, `2` = HEARTBEAT |
| 6 | 2 | `flags` | bit 0 = records stream (below); other bits `0` |
| 8 | 8 | `stream_id` | random, new every time the sender starts |
| 16 | 8 | `seq` | DATA: event number in this stream, starting at 1. HEARTBEAT: last event number sent |
| 24 | 2 | `chunk_idx` | 0-based piece number |
| 26 | 2 | `chunk_count` | pieces in this event (1 = fits in one packet) |
| 28 | 4 | `event_len` | length of the whole event in bytes |
| 32 | 32 | `digest` | SHA-256 of the whole event |
| 64 | n | `payload` | this piece's bytes |
| 64+n | 4 | `crc32` | CRC-32 (zlib) of bytes 0 … 64+n-1 |

Overhead is 68 bytes. With `max_datagram` = 1472 (MTU 1500 − 20 IP − 8 UDP), each packet holds
1,404 bytes of event. With 8972 (MTU 9000) it holds 8,904.

All pieces of one event are sent back to back and in order. Nothing is ever resent.

## DATA event body

The pieces joined together are UTF-8 JSON, exactly one object:

```json
{"_time":1727265600.123,"host":"fw01","source":"udp:514","sourcetype":"pan:traffic",
 "index":"enclave1","_raw":"<14>Sep 25 12:00:00 fw01 1,2026/09/25 ...",
 "fields":{"wd2l_truncated":300000,"wd2l_tx_time":1727265600.912}}
```

`_raw` (string) is required. `_time` (number), `host`/`source`/`sourcetype`/`index` (strings ≤ 1024
characters) are optional. `fields` is optional: a flat object of string or number values, sent to
the SIEM as indexed fields. The receiver ignores anything else.

The sender stamps `wd2l_tx_time` (its clock when it sent the event, epoch seconds, rounded to the
millisecond) in `fields` unless started with `--no-tx-time`. It counts toward `--max-event`. The
receiver adds `wd2l_rx_time` (its own clock when the event arrived) before sending the event on,
replacing any `wd2l_rx_time` that came over the wire. Neither changes the frame format.

When `_raw` carries a long blob that can't be inspected, the sender also sets `wd2l_opaque`
(`encrypted`, `compressed` or `high-entropy`) and `wd2l_opaque_bytes` (the blob's decoded size),
unless started with `--no-opaque-check`. It removes those two fields from anything the
aggregator sent, so only the sender can set them. See
[ADR-0002](decisions/0002-opaque-content.md).

## HEARTBEAT body

One piece, JSON, sent every second and once more on clean shutdown:

```json
{"audit_n":412,"audit_ok":true,"bad_input":0,"boot":42,"clients":1,"cpu_pct":1.4,
 "datagrams_sent":8673,"events_hash":"3f9a0c51d27be4468a1d90c7e25b6f83b04c7d19e8a2f5603d1b94ce7a08f26d",
 "events_in":5001,"events_sent":5001,"final":true,
 "heartbeat_trimmed":0,
 "input_backlog_bytes":0,"nic_carrier":true,"nic_tx_dropped":0,"nic_tx_errors":0,
 "nic_tx_packets":8673,"opaque_events":0,"prev_last_seq":1837204,
 "prev_stream":9140175346201236511,"rss_mb":31.2,"send_errors":0,"sender_drops":0,
 "sender_time":1790360018.66,"shutdown_unread_bytes":0,"stall_s":0.0,"time_offset_ms":0.021,
 "time_stratum":1,"time_synced":true,"truncated":1,"uptime":12.3}
```

Keys are sent in sorted order, as shown. Since wd2l 0.2.0 the heartbeat also carries a snapshot of
Enclave 1 (input, sender process, egress NIC, time, audit); see the ICD §8 for every key. When the
sender can't read chrony, `time_offset_ms`, `time_stratum` and `time_synced` are left out and
`"time_unavailable":true` is sent instead.

`seq` in the header is the last event number sent. That's what lets the receiver notice events
lost at the very end of a burst, when nothing newer arrives to reveal the hole. `final` is present
only on the shutdown heartbeat, and is always the last frame of a stream.

`events_hash` is the set hash of this run's events 1 … `seq` (the heartbeat's `seq` is the cut): the
sum modulo 2²⁵⁶ of SHA-256(`seq` as 8 bytes big-endian ‖ the event's SHA-256 `digest`). It is 64
lowercase hex digits, all zeros before the first event. Enclave 2 computes the same sum over what
it received and compares, which proves it delivered exactly these events. It is always present and
is never dropped from a trimmed heartbeat.

`shutdown_unread_bytes` is input the log aggregator had already handed over (TCP acknowledged)
that the sender could not read before it stopped. It is normally 0.

`sender_time` is the sender's clock when it sent the heartbeat. The receiver subtracts it from its
own clock at arrival and reports the result as `clock_offset_s` in its health records: the clock
difference between the two enclaves plus the one-way delay, which is well under 1 ms on a direct
fiber.

`boot`, `prev_stream` and `prev_last_seq` are present only when the sender runs with `--state`:

* `boot` counts sender runs (1, 2, 3, …). It lives in the sender's state file.
* `prev_stream` / `prev_last_seq` name the run before this one and the last event number it
  recorded (saved at every heartbeat, so after a crash it can be up to one heartbeat behind).

## Records stream

With `--audit-dir`, the sender runs a second stream beside the data stream. It carries the
sender's own audit and health records. It has its own random `stream_id`, its own `seq` from 1 and
its own heartbeat, and every frame has `flags` bit 0 set. Its DATA bodies use the same event
layout, but they are records, not logs: `host` is the log server, `source` is `wd2l-sender`,
`sourcetype` is `wd2l:sender:audit` or `wd2l:sender:health`, and `_raw` is the record as canonical
JSON. There is no `index`.

The heartbeat has `events_sent`, `records_too_big`, `outbox_dropped`, `sender_time`, `uptime` and
`final`. It has no `boot` or `prev_*`: records streams aren't linked across runs. Receivers older
than wd2l 0.2.0 ignore `flags`, so **update the receiver first**.

Receiver rule: frames with `flags` bit 0 set are tracked as their own stream, delivered to the
audit or health index, and never linked to the run chain.

## Why the sequence number never resets

`seq` is 64 bits and restarts at 1 only with a new `stream_id`, i.e. when the sender restarts. At
1,000 events/s it would take about 584 million years to run out, so there is no wraparound
handling. The pair (`stream_id`, `seq`) identifies an event. Streams are linked into a chain by
`boot` / `prev_stream`, which lets the receiver notice a run it never saw at all.

## Receiver rules

* Drop a datagram if it is shorter than 68 bytes, or if CRC, magic, version, type or chunk fields
  are wrong. Count it as `bad_frames`.
* Drop a piece whose `event_len` exceeds the receiver's `--max-event`.
* Hold pieces of an event for up to `--reasm-timeout` seconds. Cap the total held bytes at
  `--max-buffer`, evicting the oldest part-built event first.
* After joining the pieces, the length and SHA-256 must match `event_len` and `digest`.
* Per stream: a missing number becomes a gap `--gap-window` seconds after something newer (an
  event, or a heartbeat's `seq`) shows it should exist.
* A number already delivered is a duplicate and is dropped. A number inside a reported gap fills
  that gap (this is how archive replay works).
* An event counts as delivered in the saved state only once the output has made it durable (the
  SIEM accepted it, it is in the on-disk spool, or it is fsync'd to a file). After a crash, events
  handed over but not yet durable are reported as gaps (`reason=receiver_restart`) and can be
  filled by replay.
* Stream links (when present): the previous stream's known last number is raised to
  `prev_last_seq`, so a lost tail becomes a gap. A `prev_stream` the receiver has never seen is
  reported as `stream_missing` and its events 1..`prev_last_seq` as a gap. A jump in `boot` of
  more than one reports the runs in between as `stream_missing`; a lower `boot` is reported as
  `sender_boot_reset`. A brand-new receiver (no state) does not report history from before it
  started.
