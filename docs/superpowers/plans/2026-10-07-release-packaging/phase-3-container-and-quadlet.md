# Phase 3: container image, lab image mode, options in env files, Quadlet units

Part of the [release packaging plan](README.md). Read its **Global constraints** first. Spec:
[spec.md](spec.md) "Phase 3", and the "Unit change" bullet of "Phase 5". It is done here
because the Quadlet units read the same env files.

**Delivers:**

* the receiver says when the kernel gave its capture socket less buffer than asked, and a
  sysctl file fixes it;
* the image builds from the wheel on the FIPS Hardened Images, with labels of its own;
* the lab runs the sender and receiver **from the image** (`--image`), in CI on every push;
* the units take their site options from `/etc/wd2l/*.env`;
* the Quadlet units;
* the containers guide.

**Depends on Phase 0:**

* Task 3.3 uses the runner's `rmem_max` (Phase 0 log);
* Task 3.5 uses P0-2 (env expansion in `Exec=`), P0-3 (SELinux mounts), P0-4 (user name) and
  P0-1 (the capability for a non-root user).

Run tests with `T` from the plan README.

---

### Task 3.1: The capture buffer the kernel actually gave

**Files:**
- Modify: `wd2l/packets.py`, `wd2l/receiver.py`, `docs/deployment/receiver.md`,
  `docs/operations.md`
- Create: `deploy/receiver/90-wd2l.conf`, `tests/test_capture_buffer.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  * `packets.SO_RCVBUFFORCE = 33`;
  * `packets.set_rcvbuf(sock, wanted: int) -> int` (what `getsockopt(SO_RCVBUF)` reports);
  * `LiveCapture.rcvbuf: int`;
  * `receiver.rcvbuf_warning(got: int, wanted: int) -> Optional[str]`;
  * `deploy/receiver/90-wd2l.conf`, which Task 5.2 installs in `/usr/lib/sysctl.d/`.

Background: `LiveCapture` asks for 64 MiB with `SO_RCVBUFFORCE`, which needs `CAP_NET_ADMIN`.
The receiver runs with only `CAP_NET_RAW`, both as a native unit and in the container. So the
call falls back to `SO_RCVBUF`, which the kernel caps at `net.core.rmem_max` (212992 bytes by
default). The kernel reports double what it set.

- [ ] **Step 1: Write the failing tests**

`tests/test_capture_buffer.py`:

```python
import os

from wd2l import packets, receiver

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class BufSock:
    """setsockopt/getsockopt like the kernel: SO_RCVBUFFORCE needs CAP_NET_ADMIN, SO_RCVBUF is
    capped at rmem_max, and getsockopt reports double what was set."""

    def __init__(self, admin, rmem_max):
        self.admin, self.rmem_max, self.size = admin, rmem_max, 0

    def setsockopt(self, level, opt, value):
        if opt == packets.SO_RCVBUFFORCE:
            if not self.admin:
                raise PermissionError(1, "Operation not permitted")
            self.size = value
        else:
            self.size = min(value, self.rmem_max)

    def getsockopt(self, level, opt):
        return 2 * self.size


def test_rcvbuf_is_forced_with_net_admin():
    assert packets.set_rcvbuf(BufSock(True, 212992), 64 << 20) == 128 << 20


def test_rcvbuf_falls_back_and_reports_the_cap():
    assert packets.set_rcvbuf(BufSock(False, 212992), 64 << 20) == 425984


def test_rcvbuf_with_rmem_max_raised_is_enough():
    got = packets.set_rcvbuf(BufSock(False, 67108864), 64 << 20)
    assert receiver.rcvbuf_warning(got, 64 << 20) is None


def test_rcvbuf_warning():
    assert receiver.rcvbuf_warning(128 << 20, 64 << 20) is None
    w = receiver.rcvbuf_warning(425984, 64 << 20)
    for part in ("208 KiB", "65536 KiB", "net.core.rmem_max", "67108864", "90-wd2l.conf"):
        assert part in w, part


def test_sysctl_file_matches_the_default_buffer():
    with open(os.path.join(REPO, "deploy", "receiver", "90-wd2l.conf")) as f:
        lines = [x for x in f.read().splitlines() if x.strip() and not x.startswith("#")]
    assert lines == ["net.core.rmem_max = 67108864"]
    assert receiver.build_parser().get_default("capture_rcvbuf") == 67108864
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_capture_buffer.py -v`
Expected: FAIL (`AttributeError: module 'wd2l.packets' has no attribute 'SO_RCVBUFFORCE'`).

- [ ] **Step 3: Write the implementation**

`wd2l/packets.py`, add above `class LiveCapture`:

```python
SO_RCVBUFFORCE = 33


def set_rcvbuf(sock: Any, wanted: int) -> int:
    """Ask for a `wanted`-byte receive buffer and return what the kernel gave (getsockopt
    reports double the size set). SO_RCVBUFFORCE needs CAP_NET_ADMIN, which the receiver
    doesn't have (native unit or container), so the size is normally capped at
    net.core.rmem_max: deploy/receiver/90-wd2l.conf raises it."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, wanted)
    except OSError:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, wanted)
    return sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
```

In `LiveCapture.__init__`, replace the `try`/`except` around the two `setsockopt` calls with
`self.rcvbuf = set_rcvbuf(self.sock, rcvbuf)`. Add `Any` to the `typing` import if it isn't
there.

`wd2l/receiver.py`, add a module-level function near `steady_clock()`:

```python
def rcvbuf_warning(got: int, wanted: int) -> Optional[str]:
    """A warning when the kernel gave the capture socket less than --capture-rcvbuf. It
    reports double what it set, so anything under 2 x wanted is less."""
    if got >= 2 * wanted:
        return None
    return ("capture receive buffer is %d KiB, not the %d KiB asked for (--capture-rcvbuf): "
            "bursts can be dropped by the kernel. Raise net.core.rmem_max to at least %d "
            "(deploy/receiver/90-wd2l.conf)" % (got // 2048, wanted // 1024, wanted))
```

In `main()`, right after `cap = packets.LiveCapture(a.live, rcvbuf=a.capture_rcvbuf)`:

```python
        warning = rcvbuf_warning(cap.rcvbuf, a.capture_rcvbuf)
        if warning:
            log.warning(warning)
```

`deploy/receiver/90-wd2l.conf`:

```text
# wd2l receiver: let the capture socket have the 64 MiB receive buffer it asks for
# (--capture-rcvbuf, default 67108864). The receiver runs without CAP_NET_ADMIN (native unit
# and container alike), so the kernel caps its buffer at net.core.rmem_max.
# The wd2l-receiver RPM installs this in /usr/lib/sysctl.d/. By hand:
#   sudo cp deploy/receiver/90-wd2l.conf /etc/sysctl.d/ && sudo sysctl --system
net.core.rmem_max = 67108864
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `T -q`
Expected: PASS (the whole suite).

- [ ] **Step 5: Docs**

* **`docs/deployment/receiver.md`:** add a step between "2. Capture NIC" and "3. Capture
  archive":

  ````markdown
  ### Kernel receive buffer

  ```bash
  sudo cp deploy/receiver/90-wd2l.conf /etc/sysctl.d/ && sudo sysctl --system
  sysctl net.core.rmem_max        # 67108864
  ```

  The receiver asks for a 64 MiB capture buffer, but it runs without `CAP_NET_ADMIN`, so the
  kernel caps the buffer at `net.core.rmem_max` (about 208 KiB by default). Without this file,
  bursts are dropped by the kernel (`kernel_drops`), and the receiver logs a warning at start.
  ````

* **The same file:** in the options table's `--capture-rcvbuf` row, add "Needs
  `net.core.rmem_max` at least this big (above); the receiver warns at start when it got less".
* **`docs/operations.md`,** under the fault-segment alert where `kernel_drops` / `e2-capture`
  is discussed: "If the receiver's log has a `capture receive buffer is … KiB` warning, apply
  `90-wd2l.conf` ([receiver guide](deployment/receiver.md#kernel-receive-buffer)) and restart
  the receiver."

- [ ] **Step 6: Commit**

```bash
git add wd2l/packets.py wd2l/receiver.py deploy/receiver/90-wd2l.conf tests/test_capture_buffer.py \
  docs/deployment/receiver.md docs/operations.md
git commit -m "Receiver: say when the capture buffer is capped; sysctl file to raise rmem_max"
```

---

### Task 3.2: The Containerfile, its checker, and one build script

**Files:**
- Create: `packaging/container/Containerfile`, `packaging/container/check_containerfile.py`,
  `packaging/container/build.sh`, `tests/test_container_checks.py`

**Interfaces:**
- Consumes: the `dist` wheel (Task 1.1), `packaging/ci/pin-images.sh` (Task 1.2) and ADR-0004.
- Produces:
  * `check_containerfile.froms(text) -> List[dict]` (keys `ref`, `stage`, `name`, `tag`,
    `digest`), `check_containerfile.problems(text) -> List[str]` and
    `check_containerfile.base(text) -> str`;
  * the CLI flags `--base` and `--json`;
  * `packaging/container/build.sh DIST TAG`, which runs `podman build` with the version, the
    revision, `SOURCE_DATE_EPOCH`, the base labels and the label removals. `PODMAN=cmd`
    overrides (tests).
  * Labels on the image:
    * `name=wd2l` and `vendor=wd2l project`;
    * `org.opencontainers.image.{title,description,version,revision,source,url,vendor,licenses}`;
    * `org.opencontainers.image.base.{name,digest}`;
    * the base's Red Hat and Hummingbird product labels removed (`build.sh`'s `UNSET`).

- [ ] **Step 1: Write the failing tests**

`tests/test_container_checks.py`:

```python
import json
import os
import subprocess

from helpers import load_script

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
cc = load_script("packaging/container/check_containerfile.py")
D1, D2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64
B = "registry.access.redhat.com/hi/python"
GOOD = ("FROM %s:3.12-fips-builder@%s AS build\nRUN true\nFROM %s:3.12-fips@%s\n"
        "COPY --from=build /out/ /\n") % (B, D1, B, D2)


def real():
    with open(os.path.join(REPO, "packaging", "container", "Containerfile")) as f:
        return f.read()


def test_the_real_containerfile_passes():
    assert cc.problems(real()) == []
    assert cc.base(real()).startswith(B + ":3.12-fips@sha256:")


def test_good():
    assert cc.problems(GOOD) == []
    assert cc.base(GOOD) == "%s:3.12-fips@%s" % (B, D2)
    assert [f["stage"] for f in cc.froms(GOOD)] == ["build", None]


def test_unpinned_base_is_refused():
    assert any("not pinned" in p for p in cc.problems(GOOD.replace("@" + D2, "")))


def test_other_registry_is_refused():
    bad = GOOD.replace(B + ":3.12-fips@", "docker.io/library/python:3.12-fips@")
    assert any("not a Red Hat Hardened Image" in p for p in cc.problems(bad))


def test_non_fips_variant_is_refused():
    assert any("not a FIPS variant" in p for p in cc.problems(GOOD.replace(":3.12-fips@", ":3.12@")))


def test_builder_as_the_last_stage_is_refused():
    bad = "FROM %s:3.12-fips-builder@%s\n" % (B, D1)
    assert any("last stage" in p for p in cc.problems(bad))


def test_copy_from_an_image_instead_of_a_stage_is_refused():
    bad = GOOD + "COPY --from=quay.io/someone/tools:1 /bin/x /bin/x\n"
    assert any("copies from" in p for p in cc.problems(bad))


def test_json_lists_every_from(tmp_path):
    f = tmp_path / "Containerfile"
    f.write_text(GOOD)
    r = subprocess.run(["python3", os.path.join(REPO, "packaging", "container",
                                                "check_containerfile.py"), str(f), "--json"],
                       stdout=subprocess.PIPE)
    got = json.loads(r.stdout)
    assert [x["tag"] for x in got] == ["3.12-fips-builder", "3.12-fips"] and got[1]["digest"] == D2


def test_build_script_passes_labels_and_removes_the_base_product_labels(tmp_path):
    log = tmp_path / "args"
    fake = tmp_path / "podman"
    fake.write_text('#!/bin/sh\nfor a in "$@"; do echo "$a"; done > "%s"\n' % log)
    fake.chmod(0o755)
    dist = tmp_path / "dist"
    dist.mkdir()
    sha = "c" * 40
    r = subprocess.run(["bash", os.path.join(REPO, "packaging", "container", "build.sh"),
                        str(dist), "localhost/wd2l:test"],
                       env=dict(os.environ, PODMAN=str(fake), REVISION=sha, EPOCH="1791209000"),
                       stderr=subprocess.PIPE)
    assert r.returncode == 0, r.stderr
    args = log.read_text().splitlines()
    assert args[0] == "build" and args[-1] == str(dist)
    assert args[args.index("--timestamp") + 1] == "1791209000"
    build_args = [args[i + 1] for i, a in enumerate(args) if a == "--build-arg"]
    base = cc.base(real())
    assert "BASE_NAME=" + base.split("@")[0] in build_args
    assert "BASE_DIGEST=" + base.split("@")[1] in build_args
    assert "REVISION=" + sha in build_args
    assert "VERSION=" + __import__("wd2l").__version__ in build_args
    unset = [args[i + 1] for i, a in enumerate(args) if a == "--unsetlabel"]
    for label in ("cpe", "com.redhat.component", "io.hummingbird-project.variant"):
        assert label in unset
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_container_checks.py -v`
Expected: FAIL (`FileNotFoundError` for `check_containerfile.py`).

- [ ] **Step 3: Write `packaging/container/check_containerfile.py`**

```python
#!/usr/bin/env python3
"""Checks packaging/container/Containerfile before anything is built
(docs/decisions/0004-container-base-image.md):

* every FROM is a Red Hat Hardened Image, a FIPS variant, pinned as NAME:TAG@sha256:DIGEST;
* the last stage is a runtime image, not a builder;
* COPY --from names a stage, never an image.

    check_containerfile.py [FILE]           check; exit 1 with one line per problem
    check_containerfile.py [FILE] --base    print the runtime base (NAME:TAG@DIGEST)
    check_containerfile.py [FILE] --json    print every FROM as JSON"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(HERE, "Containerfile")
REGISTRY = "registry.access.redhat.com/hi/"
FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", re.I)
COPY_FROM = re.compile(r"^\s*COPY\s+.*--from=(\S+)", re.I)
PINNED = re.compile(r"^(?P<name>[^@\s]+):(?P<tag>[^@\s:/]+)@(?P<digest>sha256:[0-9a-f]{64})$")


def froms(text: str) -> List[Dict[str, Optional[str]]]:
    out = []
    for line in text.splitlines():
        m = FROM.match(line)
        if m:
            p = PINNED.match(m.group(1))
            out.append({"ref": m.group(1), "stage": m.group(2),
                        "name": p.group("name") if p else None,
                        "tag": p.group("tag") if p else None,
                        "digest": p.group("digest") if p else None})
    return out


def problems(text: str) -> List[str]:
    refs = froms(text)
    if not refs:
        return ["no FROM line"]
    out = []
    for r in refs:
        if not r["digest"]:
            out.append("%s: not pinned as NAME:TAG@sha256:DIGEST" % r["ref"])
            continue
        if not str(r["name"]).startswith(REGISTRY):
            out.append("%s: not a Red Hat Hardened Image (%s...)" % (r["ref"], REGISTRY))
        if not re.search(r"-fips(-builder)?$", str(r["tag"])):
            out.append("%s: not a FIPS variant" % r["ref"])
    last = refs[-1]
    if last["tag"] and str(last["tag"]).endswith("-builder"):
        out.append("%s: the last stage must be a runtime image, not a builder" % last["ref"])
    stages = {r["stage"] for r in refs if r["stage"]}
    for line in text.splitlines():
        m = COPY_FROM.match(line)
        if m and m.group(1) not in stages:
            out.append("COPY --from=%s: copies from an image, not a stage" % m.group(1))
    return out


def base(text: str) -> str:
    return str(froms(text)[-1]["ref"])


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Check the wd2l Containerfile.")
    p.add_argument("file", nargs="?", default=DEFAULT)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--base", action="store_true", help="print the runtime base image")
    g.add_argument("--json", action="store_true", help="print every FROM as JSON")
    a = p.parse_args(argv)
    with open(a.file) as f:
        text = f.read()
    probs = problems(text)
    for x in probs:
        print("containerfile: " + x, file=sys.stderr)
    if probs:
        return 1
    if a.base:
        print(base(text))
    elif a.json:
        print(json.dumps(froms(text), indent=1))
    else:
        print("containerfile: ok (%s)" % base(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Write the Containerfile (without digests), then pin it**

`packaging/container/Containerfile`:

```dockerfile
# wd2l on Red Hat Hardened Images, FIPS variant (docs/decisions/0004-container-base-image.md).
# Build with packaging/container/build.sh DIST TAG: the context is dist/ (the wheel), and the
# script passes the labels. Both bases are pinned by digest. Dependabot proposes new ones, and
# .github/workflows/image.yml verifies their signatures and provenance before every build.
FROM registry.access.redhat.com/hi/python:3.12-fips-builder AS build
USER 0
COPY wd2l-*-py3-none-any.whl /tmp/
# Compiled with checked hashes so the .pyc files don't depend on file times (reproducible), and
# with their real path (/usr/lib/...), not /out.
RUN python3 -m pip install --no-deps --no-index --no-cache-dir --no-compile \
      --root /out --prefix /usr /tmp/wd2l-*-py3-none-any.whl \
 && python3 -m compileall -q --invalidation-mode checked-hash -s /out -p / \
      /out/usr/lib/python3.12/site-packages/wd2l

FROM registry.access.redhat.com/hi/python:3.12-fips
ARG VERSION=dev
ARG REVISION=unknown
ARG BASE_NAME=unknown
ARG BASE_DIGEST=unknown
LABEL name="wd2l" \
      vendor="wd2l project" \
      maintainer="wd2l project" \
      version="${VERSION}" \
      summary="One-way log transfer: wd2l-sender and wd2l-receiver" \
      description="Frames logs into UDP in Enclave 1 and rebuilds them from tapped packets in Enclave 2" \
      io.k8s.description="Frames logs into UDP in Enclave 1 and rebuilds them from tapped packets in Enclave 2" \
      url="https://github.com/JoeHazurmoney/architecture-wiredata-to-log" \
      org.opencontainers.image.title="wd2l" \
      org.opencontainers.image.description="One-way log transfer: wd2l-sender and wd2l-receiver" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="https://github.com/JoeHazurmoney/architecture-wiredata-to-log" \
      org.opencontainers.image.url="https://github.com/JoeHazurmoney/architecture-wiredata-to-log" \
      org.opencontainers.image.vendor="wd2l project" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="${BASE_NAME}" \
      org.opencontainers.image.base.digest="${BASE_DIGEST}"
COPY --from=build /out/ /
USER 65532
CMD ["wd2l-receiver", "--help"]
```

Run: `bash packaging/ci/pin-images.sh packaging/container/Containerfile && git diff packaging/container/Containerfile`
Expected: both FROM lines gain `@sha256:<64 hex>`.

- [ ] **Step 5: Write `packaging/container/build.sh`**

```bash
#!/usr/bin/env bash
# Builds the wd2l image the same way everywhere (CI, release, by hand):
#   packaging/container/build.sh DIST TAG        DIST holds the wheel (python -m build)
# It sets the version, the commit and the base image as labels, and SOURCE_DATE_EPOCH (the
# commit time) as the image time, so the same commit builds the same image. It removes the
# base's Red Hat and Hummingbird product labels: this image is wd2l, not hi/python, and the
# base is named in org.opencontainers.image.base.*. Environment: PODMAN=cmd overrides podman;
# REVISION and EPOCH override the commit and its time (tests, and checkouts without git).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DIST="${1:?usage: build.sh DIST TAG}"
TAG="${2:?usage: build.sh DIST TAG}"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$REPO/wd2l/__init__.py")"
REVISION="${REVISION:-$(git -C "$REPO" rev-parse HEAD)}"
EPOCH="${EPOCH:-$(git -C "$REPO" log -1 --format=%ct)}"
BASE="$(python3 "$HERE/check_containerfile.py" "$HERE/Containerfile" --base)"
UNSET=(cpe com.redhat.component distribution-scope build-date release vcs-ref vcs-type
       io.hummingbird-project.containerfile io.hummingbird-project.major-minor-version
       io.hummingbird-project.major-version io.hummingbird-project.repository
       io.hummingbird-project.stream io.hummingbird-project.application-category
       io.hummingbird-project.variant io.hummingbird-project.variant.base
       io.hummingbird-project.variant.description io.hummingbird-project.variant.fips)
args=(build --timestamp "$EPOCH" -f "$HERE/Containerfile" -t "$TAG"
      --build-arg "VERSION=$VERSION" --build-arg "REVISION=$REVISION"
      --build-arg "BASE_NAME=${BASE%@*}" --build-arg "BASE_DIGEST=${BASE#*@}")
for l in "${UNSET[@]}"; do args+=(--unsetlabel "$l"); done
exec ${PODMAN:-podman} "${args[@]}" "$DIST"
```

- [ ] **Step 6: Run the tests, then build and look at it**

Run: `T tests/test_container_checks.py -v`
Expected: PASS.

Docker has no `--unsetlabel` and no `--timestamp`, so this local build is a smoke test only.
CI builds with `build.sh` and podman:

```bash
B && MSYS_NO_PATHCONV=1 docker build -f packaging/container/Containerfile -t wd2l:dev dist/
docker run --rm wd2l:dev wd2l-receiver --help | head -3
docker run --rm wd2l:dev python3 -c "import os, wd2l.hostinfo as h; print(os.getuid(), h.build_id(), h.code_sha256()[:12])"
docker run --rm wd2l:dev python3 -c "import _hashlib, hashlib; print(_hashlib.get_fips_mode()); hashlib.md5()" ; echo "exit $?"
```

Expected:

* the receiver's usage line;
* `65532 <commit> <12 hex>`;
* `1`, then a `ValueError` traceback and a non-zero exit (MD5 refused).

- [ ] **Step 7: Commit**

```bash
chmod +x packaging/container/build.sh packaging/container/check_containerfile.py
git add --chmod=+x packaging/container/build.sh
git add packaging/container/Containerfile packaging/container/check_containerfile.py \
  tests/test_container_checks.py
git commit -m "Container image on Hardened Images (FIPS): Containerfile, checker, build script"
```

---

### Task 3.3: The lab runs the image (`--image`)

**Files:**
- Modify: `lab/run-lab.sh`, `.github/workflows/tests.yml`, `docs/running-the-lab.md`

**Interfaces:**
- Consumes: `TIME_ARGS` and `--chrony-udp` (Task 2.3), `build.sh` (Task 3.2), and
  `90-wd2l.conf`'s value (Task 3.1).
- Produces: `lab/run-lab.sh --image IMAGE`.
  * The sender and receiver run from the image as UID 65532: `--cap-drop all`, `NET_RAW` for
    the receiver only, read-only, no new privileges.
  * It implies `--chrony-udp`.
  * It is allowed with the plain run, `--loss`, `--files`, `--interleave`, `--maintenance` and
    `--receiver-outage`, which all stop wd2l with SIGTERM; podman passes that on.
  * It refuses `--receiver-crash` and `--fault`, because their SIGKILL and SIGSTOP would hit
    the podman client, not wd2l.
  * The CI job `lab-image` runs it; Task 4.1 moves it into `image.yml`.

- [ ] **Step 1: Change `lab/run-lab.sh`**

* **Usage block:** add `[--image IMAGE]`:

  ```text
  #   --image IMAGE       run wd2l-sender and wd2l-receiver from this container image (podman, as
  #                       root): UID 65532, no capabilities but NET_RAW for the receiver, read-only,
  #                       like the Quadlet units. Implies --chrony-udp. Not with --fault or
  #                       --receiver-crash (SIGSTOP and SIGKILL would reach the podman client,
  #                       not wd2l); --receiver-outage works (SIGTERM is passed on)
  ```

* **Defaults:** `IMAGE=""`. **Parsing:** `--image) IMAGE="$2"; CHRONY_UDP=1; shift 2 ;;`.
* **Validation**, after the `--fault` check:

```bash
if [ -n "$IMAGE" ] && { [ -n "$FAULT" ] || [ "$KILLSIG" = KILL ]; }; then
  echo "--image doesn't run with --fault or --receiver-crash (their signals would reach podman, not wd2l)" >&2; exit 2
fi
```

* **Tool check:** after the existing `for c in ip tc nft tcpdump python3` loop:

  ```bash
  [ -z "$IMAGE" ] || command -v podman >/dev/null || { echo "missing podman" >&2; exit 1; }
  ```

* **`cleanup()`:** before the teardown line:

```bash
  [ -z "$IMAGE" ] || podman rm -f wd2l-lab-tx wd2l-lab-rx >/dev/null 2>&1
  [ -z "${RMEM_OLD:-}" ] || sysctl -qw net.core.rmem_max="$RMEM_OLD"
```

* **After `mkdir -p "$OUT/pcap" "$OUT/received"`:**

```bash
if [ -n "$IMAGE" ]; then
  chown -R 65532:65532 "$OUT"        # the image's user writes the state, audit and output files
  # Like a production receiver, the container has no CAP_NET_ADMIN, so its capture buffer is
  # capped at rmem_max: raise it as deploy/receiver/90-wd2l.conf does; put it back at the end.
  RMEM_OLD=$(cat /proc/sys/net/core/rmem_max)
  sysctl -qw net.core.rmem_max=67108864
fi
```

* **Above `start_capture()`, add the launcher:**

```bash
# Runs a wd2l module in a namespace: from this checkout, or (--image) from the image as its
# unprivileged user, read-only, with only the receiver's one capability, as the Quadlet units do.
wd2l_run() {   # wd2l_run NAMESPACE CONTAINER-NAME MODULE [ARGS...]
  local ns="$1" name="$2" module="$3"; shift 3
  if [ -z "$IMAGE" ]; then
    ip netns exec "$ns" python3 -m "$module" "$@"
    return
  fi
  local caps=(--cap-drop all)
  [ "$module" != wd2l.receiver ] || caps+=(--cap-add NET_RAW)
  podman run --rm --name "$name" --network "ns:/run/netns/$ns" --user 65532:65532 \
    "${caps[@]}" --security-opt no-new-privileges --read-only -v "$OUT:$OUT" \
    "$IMAGE" python3 -m "$module" "$@"
}
```

* **`start_receiver`:** `wd2l_run wd2l-enc2 wd2l-lab-rx wd2l.receiver "${RX_ARGS[@]}" >>"$OUT/receiver.log" 2>&1 &`
* **`start_sender`:** replace `$ENC1 python3 -m wd2l.sender` with
  `wd2l_run wd2l-enc1 wd2l-lab-tx wd2l.sender`, and keep the rest of the line.

The `kill -TERM "$TX_PID"` and `wait` lines are unchanged. `podman run` passes SIGTERM on to
the container and exits when wd2l does.

- [ ] **Step 2: CI.** Add a job to `.github/workflows/tests.yml`:

```yaml
  lab-image:
    # The same one-way path, with wd2l-sender and wd2l-receiver running from the container image.
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: sudo apt-get update -q && sudo apt-get install -y -q iproute2 nftables tcpdump
      - run: python -m pip install build && git rev-parse HEAD > wd2l/BUILD && python -m build
      - run: packaging/container/build.sh dist localhost/wd2l:ci
      - run: podman save localhost/wd2l:ci | sudo podman load
      - run: sudo lab/run-lab.sh --image localhost/wd2l:ci
      - run: sudo lab/run-lab.sh --image localhost/wd2l:ci --loss 1
      - run: sudo lab/run-lab.sh --image localhost/wd2l:ci --files samples/logs/messages samples/logs/secure samples/logs/audit.log
```

- [ ] **Step 3: Docs.** In `docs/running-the-lab.md`, add a section after §9, "## 10. Run the
  container image through the lab":

````markdown
The same runs, with `wd2l-sender` and `wd2l-receiver` running from the container image, as the
Quadlet units run them: user 65532, no capabilities except `NET_RAW` for the receiver, a
read-only image. It needs Podman.

```bash
python3 -m pip install --user build && git rev-parse HEAD > wd2l/BUILD && python3 -m build
packaging/container/build.sh dist localhost/wd2l:dev
podman save localhost/wd2l:dev | sudo podman load
sudo lab/run-lab.sh --image localhost/wd2l:dev
sudo lab/run-lab.sh --image localhost/wd2l:dev --files samples/logs/messages samples/logs/secure samples/logs/audit.log
```

Both sides ask a chronyd stand-in over UDP (`--chrony-addr`), as the containers do. The run
raises `net.core.rmem_max` for its duration, as
[the receiver guide](deployment/receiver.md#kernel-receive-buffer) has production do.
`--receiver-outage` works with `--image`. The fault runs and `--receiver-crash` don't: they
freeze or kill the process, and with `--image` that would be the podman client.
````

- [ ] **Step 4: Check it in CI.** Ask your partner before pushing, then push and watch the
  `lab-image` job:

```bash
git add lab/run-lab.sh .github/workflows/tests.yml docs/running-the-lab.md
git commit -m "Lab: --image runs the sender and receiver from the container image"
git push
gh run watch "$(gh run list --branch release-packaging --workflow tests --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Expected: `lab-image` is green, and each run ends in `PASS`. The `--files` run says "every file
rebuilt byte for byte". If the receiver log in the run's output shows
`capture receive buffer is … KiB`, the sysctl step didn't apply, so check that the job runs the
lab as root.

---

### Task 3.4: Site options move into env files

**Files:**
- Create: `deploy/log-server/sender.env`, `deploy/receiver/receiver.env`,
  `deploy/receiver/capture.env`
- Modify: `deploy/log-server/wd2l-sender.service`, `deploy/receiver/wd2l-receiver.service`,
  `deploy/receiver/wd2l-capture.service`, `tests/test_deploy.py`,
  `docs/deployment/log-server.md`, `docs/deployment/receiver.md`

**Interfaces:**
- Consumes: Phase 0 row P0-2. It confirmed that systemd's `EnvironmentFile=` joins a value's
  backslash-newline lines and splits `$VAR` into separate arguments.
- Produces:
  * `/etc/wd2l/sender.env` (`WD2L_SENDER_ARGS`), `/etc/wd2l/receiver.env`
    (`WD2L_RECEIVER_ARGS`) and `/etc/wd2l/capture.env` (`IFACE`);
  * the units that read them;
  * the test helpers `test_deploy.env_file(path) -> Dict[str, str]` and
    `test_deploy.args(unit, env, var, module) -> List[str]`, which Task 3.5 and Task 5.2 use.

- [ ] **Step 1: Write the failing tests.** Replace `tests/test_deploy.py`'s `args()` and the two
  unit tests. Keep `unit()`, the seal test and the auditd test.

```python
SENDER_ENV = os.path.join(REPO, "deploy", "log-server", "sender.env")
RECEIVER_ENV = os.path.join(REPO, "deploy", "receiver", "receiver.env")
CAPTURE_UNIT = os.path.join(REPO, "deploy", "receiver", "wd2l-capture.service")
CAPTURE_ENV = os.path.join(REPO, "deploy", "receiver", "capture.env")

# What the units passed before the options moved into env files (they must not change).
SENDER_ARGS_BEFORE = [
    "--listen", "127.0.0.1:10070", "--bind", "10.255.255.1:5514", "--dst", "10.255.255.2:5514",
    "--max-datagram", "1472", "--auth-token-file", "/etc/wd2l/aggregator.token",
    "--state", "/var/lib/wd2l/sender.json", "--audit-dir", "/var/log/wd2l",
    "--egress-iface", "ens224", "--log-format", "json"]
RECEIVER_ARGS_BEFORE = [
    "--live", "ens256", "--dst-ip", "10.255.255.2", "--dst-port", "5514",
    "--src-ip", "10.255.255.1", "--src-port", "5514", "--state", "/var/lib/wd2l/state.json",
    "--spool-dir", "/var/lib/wd2l/spool", "--hec-url", "https://siem.enclave2.example:8088",
    "--hec-token-file", "/etc/wd2l/hec.token", "--hec-ca", "/etc/wd2l/siem-ca.pem",
    "--default-index", "enclave1", "--health-index", "wd2l",
    "--hec-audit-token-file", "/etc/wd2l/hec-audit.token", "--audit-index", "wd2l_audit",
    "--audit-dir", "/var/log/wd2l", "--pcap-dir", "/var/lib/wd2l/pcap", "--log-format", "json"]


def env_file(path):
    """KEY=VALUE lines as systemd's EnvironmentFile= reads them: a backslash at the end of a
    line joins the next one, and double quotes around a value are removed."""
    with open(path) as f:
        text = f.read().replace("\r\n", "\n").replace("\\\n", "")
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k, v = line.split("=", 1)
        if len(v) >= 2 and v[0] == v[-1] == '"':
            v = v[1:-1]
        out[k.strip()] = v
    return out


def args(unit_path, env_path, var, module):
    u = unit(unit_path)
    assert u["EnvironmentFile"] == ["/etc/wd2l/" + os.path.basename(env_path)]
    argv = shlex.split(u["ExecStart"][0])
    assert argv == ["/usr/bin/python3", "-m", module, "$" + var]
    return shlex.split(env_file(env_path)[var])


def test_moving_the_options_into_env_files_changed_none_of_them():
    assert args(SENDER_UNIT, SENDER_ENV, "WD2L_SENDER_ARGS", "wd2l.sender") == SENDER_ARGS_BEFORE
    assert args(RECEIVER_UNIT, RECEIVER_ENV, "WD2L_RECEIVER_ARGS", "wd2l.receiver") \
        == RECEIVER_ARGS_BEFORE


def test_sender_unit_turns_audit_and_health_on():
    a = sender.build_parser().parse_args(
        args(SENDER_UNIT, SENDER_ENV, "WD2L_SENDER_ARGS", "wd2l.sender"))
    assert (a.audit_dir, a.log_format, a.egress_iface) == ("/var/log/wd2l", "json", "ens224")
    u = unit(SENDER_UNIT)
    assert "/var/log/wd2l" in " ".join(u["ReadWritePaths"]) and u["UMask"] == ["0027"]
    assert u["StateDirectoryMode"] == ["0750"]


def test_receiver_unit_turns_audit_and_health_on():
    a = receiver.build_parser().parse_args(
        args(RECEIVER_UNIT, RECEIVER_ENV, "WD2L_RECEIVER_ARGS", "wd2l.receiver"))
    assert (a.audit_dir, a.log_format, a.pcap_dir) == ("/var/log/wd2l", "json", "/var/lib/wd2l/pcap")
    assert a.hec_audit_token_file == "/etc/wd2l/hec-audit.token" and a.audit_index == "wd2l_audit"
    paths = " ".join(unit(RECEIVER_UNIT)["ReadWritePaths"])
    assert "/var/lib/wd2l" in paths and "/var/log/wd2l" in paths


def test_capture_unit_reads_the_interface_from_capture_env():
    u = unit(CAPTURE_UNIT)
    assert u["EnvironmentFile"] == ["/etc/wd2l/capture.env"]
    assert shlex.split(u["ExecStart"][0])[:3] == ["/usr/sbin/tcpdump", "-i", "${IFACE}"]
    assert env_file(CAPTURE_ENV)["IFACE"] == "ens256"
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_deploy.py -v`
Expected: FAIL (`FileNotFoundError` for `sender.env`, then `KeyError: 'EnvironmentFile'`).

- [ ] **Step 3: Write the env files and change the units**

`deploy/log-server/sender.env`:

```text
# wd2l-sender options. wd2l-sender.service and wd2l-sender.container both read this file;
# change options here, not in the units. One option per line: systemd joins lines ending in a
# backslash. All options: python3 -m wd2l.sender --help, and docs/deployment/log-server.md.
# Installed as /etc/wd2l/sender.env (the RPM keeps your edits on upgrade).
WD2L_SENDER_ARGS="--listen 127.0.0.1:10070 \
--bind 10.255.255.1:5514 \
--dst 10.255.255.2:5514 \
--max-datagram 1472 \
--auth-token-file /etc/wd2l/aggregator.token \
--state /var/lib/wd2l/sender.json \
--audit-dir /var/log/wd2l \
--egress-iface ens224 \
--log-format json"
```

`deploy/receiver/receiver.env`: the same header (wd2l-receiver,
`docs/deployment/receiver.md`), with
`WD2L_RECEIVER_ARGS="--live ens256 \` and then one line per option, in
`RECEIVER_ARGS_BEFORE`'s order, each as `--option value \`. The last line ends with `"`.

`deploy/receiver/capture.env`:

```text
# The capture NIC. capture-nic.sh and wd2l-capture.service (tcpdump) read this file.
# Installed as /etc/wd2l/capture.env.
IFACE=ens256
# MTU=1500     match Enclave 1 (9000 with jumbo frames end to end)
```

`deploy/log-server/wd2l-sender.service`. Replace the whole `ExecStart=… \` block (the
`ExecStart` line and its continuation lines) with:

```ini
# Site options (addresses, NIC, token, paths): /etc/wd2l/sender.env.
EnvironmentFile=/etc/wd2l/sender.env
ExecStart=/usr/bin/python3 -m wd2l.sender $WD2L_SENDER_ARGS
```

Then add `StateDirectoryMode=0750` right after `StateDirectory=wd2l`.

`deploy/receiver/wd2l-receiver.service`: the same, with
`EnvironmentFile=/etc/wd2l/receiver.env` and
`ExecStart=/usr/bin/python3 -m wd2l.receiver $WD2L_RECEIVER_ARGS`.

`deploy/receiver/wd2l-capture.service`. Add `EnvironmentFile=/etc/wd2l/capture.env` above
`ExecStart`, and change `-i ens256` to `-i ${IFACE}`. Drop the comment line about editing the
interface name.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `T -q`
Expected: PASS.

- [ ] **Step 5: Docs**

* **`docs/deployment/log-server.md` §1 Install:** after the `egress.env` line, add
  `sudo cp deploy/log-server/sender.env /etc/wd2l/                     # edit the options here`.
* **The same file, §4:** before the `cp` of the unit, add the sentence: "The options are in
  `/etc/wd2l/sender.env`; the unit reads them from there."
* **The same file, the "Upgrading an install from before the fixed source port" paragraph:**
  change "add `--src-port 5514` to the receiver unit" to "add `--src-port 5514` to
  `/etc/wd2l/receiver.env`".
* **The same file, the options table:** "The unit uses" becomes "`sender.env` uses".
* **`docs/deployment/receiver.md` §2:** replace
  `echo 'IFACE=ens256' | sudo tee /etc/wd2l/capture.env` with
  `sudo cp deploy/receiver/capture.env /etc/wd2l/        # edit IFACE if it isn't ens256`.
* **The same file, §3:** delete the "edit the interface name in wd2l-capture.service" comment.
* **The same file, §4:** "Edit the SIEM URL and index names in
  `deploy/receiver/wd2l-receiver.service`" becomes "Copy the options file and edit the SIEM URL
  and index names in it: `sudo cp deploy/receiver/receiver.env /etc/wd2l/`".
* **The same file, the options table:** "The unit uses/sets" becomes "`receiver.env` uses/sets".
* **Search the rest:**

  ```bash
  grep -rn "ExecStart\|in the unit\|unit uses\|receiver unit\|sender unit" docs --include=*.md | grep -v superpowers
  ```

  Fix any remaining instruction to edit options inside a unit, so that it names the env file.

- [ ] **Step 6: Commit**

```bash
git add deploy/log-server/sender.env deploy/receiver/receiver.env deploy/receiver/capture.env \
  deploy/log-server/wd2l-sender.service deploy/receiver/wd2l-receiver.service \
  deploy/receiver/wd2l-capture.service tests/test_deploy.py docs
git commit -m "Units read their site options from /etc/wd2l/*.env (same options as before)"
```

---

### Task 3.5: Quadlet units and the containers guide

**Files:**
- Create: `deploy/log-server/wd2l-sender.container`, `deploy/receiver/wd2l-receiver.container`,
  `docs/deployment/containers.md`. Also `packaging/selinux/wd2l.te`, **only if** P0-3 failed.
- Modify: `tests/test_deploy.py`, `README.md` (Deploying list), `docs/planned-downtime.md`

**Interfaces:**
- Consumes:
  * the env files (Task 3.4) and the image name;
  * P0-1 (ambient `NET_RAW`), P0-2 (`Exec=$VAR`), P0-3 (mounts) and P0-4 (user).
- Produces:
  * the two `.container` files, which Task 5.2 installs in `/usr/share/wd2l/quadlet/`;
  * `test_deploy.quadlet(path) -> Dict[section, Dict[key, List[str]]]`;
  * `docs/deployment/containers.md`, which `docs/releasing.md` links to.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_deploy.py`, and add `import pytest`
  to its imports)

```python
import wd2l


def quadlet(path):
    """A Quadlet/systemd unit as {section: {key: [values]}}; continuation lines joined."""
    with open(path) as f:
        text = f.read().replace("\r\n", "\n").replace("\\\n", " ")
    out, sec = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            sec = out.setdefault(line[1:-1], {})
            continue
        k, v = line.split("=", 1)
        sec.setdefault(k.strip(), []).append(v.strip())
    return out


QUADLETS = [
    ("log-server", "wd2l-sender", "WD2L_SENDER_ARGS", SENDER_UNIT, 30, []),
    ("receiver", "wd2l-receiver", "WD2L_RECEIVER_ARGS", RECEIVER_UNIT, 60, ["NET_RAW"]),
]


@pytest.mark.parametrize("side, name, var, native_path, stop, caps", QUADLETS)
def test_quadlet_unit_matches_the_native_one(side, name, var, native_path, stop, caps):
    q = quadlet(os.path.join(REPO, "deploy", side, name + ".container"))
    native, c = unit(native_path), q["Container"]
    assert c["Image"] == ["ghcr.io/joehazurmoney/wd2l:" + wd2l.__version__]
    assert c["Pull"] == ["never"] and c["Network"] == ["host"]
    assert c["DropCapability"] == ["all"] and c.get("AddCapability", []) == caps
    assert c["NoNewPrivileges"] == ["true"] and c["ReadOnly"] == ["true"]
    assert c["StopTimeout"] == [str(stop)] and native["TimeoutStopSec"] == [str(stop)]
    assert int(q["Service"]["TimeoutStopSec"][0]) > stop
    assert q["Service"]["EnvironmentFile"] == native["EnvironmentFile"]
    assert shlex.split(c["Exec"][0]) == [name, "$" + var, "--chrony-addr", "127.0.0.1:323"]
    for k in ("After", "Requires", "Wants"):
        assert q["Unit"].get(k) == native.get(k), k
    assert "--umask=0027" in " ".join(c.get("PodmanArgs", []))
```

If P0-2 failed (Quadlet doesn't expand `$VAR`), the `Exec` assertion becomes:

```python
    assert shlex.split(c["Exec"][0]) == [name] + args(native_path, ENVS[name], var, MODULES[name]) \
        + ["--chrony-addr", "127.0.0.1:323"]
```

Define `ENVS = {"wd2l-sender": SENDER_ENV, "wd2l-receiver": RECEIVER_ENV}` and
`MODULES = {"wd2l-sender": "wd2l.sender", "wd2l-receiver": "wd2l.receiver"}` above it. Then
the `Exec=` line carries the options directly, and the test keeps it equal to the env file. Add
the As-built row.

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_deploy.py -k quadlet -v`
Expected: FAIL (`FileNotFoundError` for `wd2l-sender.container`).

- [ ] **Step 3: Write the Quadlet units**

`deploy/log-server/wd2l-sender.container`. The user lines follow P0-4: option (a) shown;
for (b), the `User=`/`Group=` lines hold numbers and the install step writes them (see the
guide); for (c), add the `--passwd-entry` to `PodmanArgs`. The mount options follow P0-3:
`:z` shown.

```ini
# wd2l-sender as a container under systemd (Quadlet): docs/deployment/containers.md,
# docs/decisions/0005-quadlet.md. Copy to /etc/containers/systemd/, then:
#   sudo systemctl daemon-reload && sudo systemctl start wd2l-sender
# Use this or wd2l-sender.service on a host, never both. Options: /etc/wd2l/sender.env.
[Unit]
Description=wd2l sender (container): log aggregator JSON lines in, one-way UDP frames out
After=network-online.target wd2l-egress-nic.service
Wants=network-online.target
Requires=wd2l-egress-nic.service

[Container]
ContainerName=wd2l-sender
# The release's image, verified and loaded beforehand (docs/releasing.md). For strict change
# control, name it by the digest in the release notes: ghcr.io/joehazurmoney/wd2l@sha256:...
Image=ghcr.io/joehazurmoney/wd2l:0.3.0
Pull=never
Network=host
User=wd2l
Group=wd2l
Volume=/etc/passwd:/etc/passwd:ro
Volume=/etc/group:/etc/group:ro
Volume=/etc/wd2l:/etc/wd2l:ro,z
Volume=/var/lib/wd2l:/var/lib/wd2l:z
Volume=/var/log/wd2l:/var/log/wd2l:z
DropCapability=all
NoNewPrivileges=true
ReadOnly=true
PodmanArgs=--umask=0027
# On SIGTERM the sender drains its input, then sends the final heartbeat (planned-downtime.md).
StopTimeout=30
Exec=wd2l-sender $WD2L_SENDER_ARGS --chrony-addr 127.0.0.1:323

[Service]
EnvironmentFile=/etc/wd2l/sender.env
Restart=always
RestartSec=2
TimeoutStopSec=40

[Install]
WantedBy=multi-user.target
```

`deploy/receiver/wd2l-receiver.container` differs in these places:

* the description says "wd2l receiver (container): rebuild logs from the tapped stream";
* `[Unit]` has `After=wd2l-capture-nic.service network-online.target`,
  `Requires=wd2l-capture-nic.service` and `Wants=network-online.target`, as the native unit
  does;
* `ContainerName=wd2l-receiver`;
* `AddCapability=NET_RAW` after `DropCapability=all`, with the comment
  `# Raw socket for capture, nothing else.`;
* `StopTimeout=60`, with the comment
  `# Final health record, up to 15 s for the SIEM, then the state file.`;
* `Exec=wd2l-receiver $WD2L_RECEIVER_ARGS --chrony-addr 127.0.0.1:323`;
* `EnvironmentFile=/etc/wd2l/receiver.env` and `TimeoutStopSec=70`.

**If P0-3 failed:** commit the reviewed `wd2l.te` from Task 0.2 step 3 as
`packaging/selinux/wd2l.te`, with a header comment naming the denials it allows. The guide's
SELinux section installs it:
`checkmodule -M -m -o wd2l.mod wd2l.te && semodule_package -o wd2l.pp -m wd2l.mod && sudo semodule -i wd2l.pp`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `T -q`
Expected: PASS.

- [ ] **Step 5: Write `docs/deployment/containers.md`.** Plain, short sentences, like the other
  deployment guides. Sections and their content:

  1. **"Containers instead of native services."** A table: what runs where.
     * **In a container:** `wd2l-sender` and `wd2l-receiver`.
     * **On the host:** the NIC scripts, nftables, the tcpdump archive and its prune timer, the
       audit seal timer, the auditd rules and chrony.
     * One paragraph on why: [ADR-0004](../decisions/0004-container-base-image.md) and
       [ADR-0005](../decisions/0005-quadlet.md).
     * "Use the container or the native unit on a host, never both."
  2. **"What the host needs."**
     * RHEL 9.2+ or RHEL 10 with Podman 4.4 or later.
     * The host pieces: install the `wd2l-sender` or `wd2l-receiver` RPM (it brings the units,
       env files and scripts; leave the native wd2l service disabled), or follow the native
       guide's host steps.
     * Receiver: the sysctl file.
     * chronyd answering on 127.0.0.1:323, which is the default. Check it with
       `chronyc -h 127.0.0.1 tracking` as a normal user.
  3. **"Bring the image in (offline)."** The release's verify-and-import commands from
     [releasing.md](../releasing.md#bringing-a-release-into-an-enclave). Then show that the
     loaded digest equals the release notes: `sudo podman image inspect --format '{{.Digest}}'
     ghcr.io/joehazurmoney/wd2l:<version>`.
  4. **"Or pull it (online)."** A `/etc/containers/policy.json` entry, so that Podman refuses
     unsigned images from this repository:

     ```json
     "ghcr.io/joehazurmoney/wd2l": [{"type": "sigstoreSigned", "keyPath": "/etc/pki/containers/wd2l-cosign.pub", "signedIdentity": {"type": "matchRepository"}}]
     ```

     And `/etc/containers/registries.d/wd2l.yaml` with `docker: {ghcr.io/joehazurmoney/wd2l:
     {use-sigstore-attachments: true}}`. Copy `cosign.pub` to the key path.
  5. **"Install the unit."**

     ```bash
     sudo systemctl disable --now wd2l-receiver.service 2>/dev/null   # the native unit, if it was on
     sudo cp /usr/share/wd2l/quadlet/wd2l-receiver.container /etc/containers/systemd/
     # strict change control: name the release's digest
     sudo sed -i 's|^Image=.*|Image=ghcr.io/joehazurmoney/wd2l@sha256:<digest from the release notes>|' \
       /etc/containers/systemd/wd2l-receiver.container
     sudo systemctl daemon-reload && sudo systemctl start wd2l-receiver
     journalctl -u wd2l-receiver -f
     ```

     Generated units can't be "enabled": the `[Install]` section takes effect at
     `daemon-reload`.
  6. **"User, SELinux and FIPS."** These come from the Phase 0 results:
     * how the user is set (P0-4), and what audit records show for `actor`;
     * the mount options (P0-3), and the policy module if needed;
     * FIPS: the image always uses the FIPS provider. It is validated only when the host is
       RHEL installed in FIPS mode. The image has no CA bundle, so `receiver.env` must keep
       `--hec-ca`.
  7. **"Signals and audit."** `sudo podman kill --signal USR1 wd2l-receiver` toggles debug
     logging. Inside the container, the audit record names pid 0 as the sender. The host's
     auditd records who ran `podman`. Optional rule:
     `-w /usr/bin/podman -p x -k wd2l-podman`.
  8. **"Replay from the archive."** Stop the live receiver first, then:

     ```bash
     sudo podman run --rm --network none --user wd2l -v /etc/passwd:/etc/passwd:ro \
       -v /var/lib/wd2l:/var/lib/wd2l:z -v /var/log/wd2l:/var/log/wd2l:z -v /etc/wd2l:/etc/wd2l:ro,z \
       ghcr.io/joehazurmoney/wd2l:<version> wd2l-receiver --pcap /var/lib/wd2l/pcap/cap-....pcap \
       <the replay options from operations.md> --chrony-addr 127.0.0.1:323
     ```

     `--network none` blocks the SIEM. For a replay that sends to the SIEM, use
     `--network host`, as the unit does.
  9. **"Upgrade and roll back."** Load and verify the new image, change `Image=`,
     `daemon-reload`, then stop and start as in [planned-downtime.md](../planned-downtime.md).
     To roll back, name the previous image.

  Then:

  * add the guide to the README's "Deploying" list, after Receiver:
    "[Containers](docs/deployment/containers.md): the sender and receiver as containers under
    systemd (Quadlet)";
  * add one line to `docs/planned-downtime.md`'s commands section: "With the container units
    the commands are the same: `systemctl stop wd2l-sender` stops the container cleanly (it
    waits `StopTimeout`)."

- [ ] **Step 6: Commit**

```bash
git add deploy/log-server/wd2l-sender.container deploy/receiver/wd2l-receiver.container \
  tests/test_deploy.py docs/deployment/containers.md README.md docs/planned-downtime.md
git add packaging/selinux/wd2l.te 2>/dev/null || true
git commit -m "Quadlet units for the sender and receiver; containers deployment guide"
```
