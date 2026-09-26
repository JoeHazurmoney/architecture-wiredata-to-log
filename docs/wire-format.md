# Wire format (WD2L version 1)

One UDP datagram carries one frame. Default destination `10.255.255.2:5514`. All integers are
big-endian. The implementation is `wd2l/wire.py`.

## Frame

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `WD2L` |
| 4 | 1 | `version` | `1` |
| 5 | 1 | `type` | `1` = DATA, `2` = HEARTBEAT |
| 6 | 2 | `flags` | reserved, `0` |
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
 "fields":{"wd2l_truncated":300000}}
```

`_raw` (string) is required. `_time` (number), `host`/`source`/`sourcetype`/`index` (strings ≤ 1024
characters) are optional. `fields` is optional: a flat object of string or number values, sent to
the SIEM as indexed fields. The receiver ignores anything else.

## HEARTBEAT body

One piece, JSON, sent every second and once more on clean shutdown:

```json
{"events_sent":5001,"datagrams_sent":8673,"sender_drops":0,"truncated":1,"bad_input":0,
 "send_errors":0,"shutdown_unread_bytes":0,"sender_time":1790360018.66,"uptime":12.3,
 "boot":42,"prev_stream":9140175346201236511,"prev_last_seq":1837204,"final":true}
```

`seq` in the header is the last event number sent. That's what lets the receiver notice events
lost at the very end of a burst, when nothing newer arrives to reveal the hole. `final` is present
only on the shutdown heartbeat, and is always the last frame of a stream.

`shutdown_unread_bytes` is input the log aggregator had already handed over (TCP acknowledged)
that the sender could not read before it stopped. It is normally 0.

`boot`, `prev_stream` and `prev_last_seq` are present only when the sender runs with `--state`:

* `boot` counts sender runs (1, 2, 3, …). It lives in the sender's state file.
* `prev_stream` / `prev_last_seq` name the run before this one and the last event number it
  recorded (saved at every heartbeat, so after a crash it can be up to one heartbeat behind).

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
