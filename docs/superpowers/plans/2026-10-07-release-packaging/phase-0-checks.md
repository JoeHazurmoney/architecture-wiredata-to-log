# Phase 0: checks that could change the design

Part of the [release packaging plan](README.md). Read its **Global constraints** first. Spec:
[spec.md](spec.md) "Phase 0".

**Delivers:** the answer to each of the spec's eight checks, recorded in the README's As-built
log as rows `P0-1` … `P0-8`, with the fallback chosen wherever a check fails. Later tasks name the
check they depend on.

* **Where the checks run.** Two places: a throwaway workflow on a GitHub runner (Task 0.1), and
  a RHEL 10 VM that your partner provides (Task 0.2). Nothing from this phase is merged except
  the log rows.
* **Base image names used below:**

```bash
PY=registry.access.redhat.com/hi/python:3.12-fips
PYB=registry.access.redhat.com/hi/python:3.12-fips-builder
COSIGN=registry.access.redhat.com/hi/cosign:latest
ORAS=registry.access.redhat.com/hi/oras:1.3
```

---

### Task 0.1: Runner checks (1, 5, 6a, 7, 8) in a throwaway workflow

**Files:**
- Create (on branch `phase0-checks` only, never merged): `.github/workflows/phase0-checks.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: the workflow log, whose lines are copied into rows P0-1, P0-5, P0-6, P0-7 and P0-8
  (Task 0.3).

- [ ] **Step 1: Get your partner's OK.** Pushing a branch, running a workflow and pushing test
  images to `ghcr.io/joehazurmoney/wd2l-phase0*` are outward actions. Ask:
  "Phase 0 needs a throwaway branch `phase0-checks` with one workflow, run once by hand. It
  pushes test images to `ghcr.io/joehazurmoney/wd2l-phase0` and `wd2l-phase0-base/python`, which
  you can delete afterwards. OK to push and run it?" Stop here until the answer is yes.

- [ ] **Step 2: Write the workflow**

Resolve the checkout action's commit for its current major version first, and pin it the way
every workflow in this plan does:

```bash
gh api repos/actions/checkout/git/ref/tags/v4 --jq .object.sha     # if it's an annotated tag:
gh api repos/actions/checkout/git/tags/<that sha> --jq .object.sha
```

`.github/workflows/phase0-checks.yml` (on a branch made from `release-packaging`):

```yaml
name: phase0-checks
# Throwaway: answers the spec's Phase 0 checks on a GitHub runner. Never merged.
on: workflow_dispatch
permissions:
  contents: read
  packages: write
jobs:
  runner:
    runs-on: ubuntu-24.04
    env:
      PY: registry.access.redhat.com/hi/python:3.12-fips
      PYB: registry.access.redhat.com/hi/python:3.12-fips-builder
      COSIGN: registry.access.redhat.com/hi/cosign:latest
      ORAS: registry.access.redhat.com/hi/oras:1.3
    steps:
      - uses: actions/checkout@<sha from step 2> # v4
      - name: Versions
        run: |
          podman version; skopeo --version; uname -r
          echo "rmem_max=$(cat /proc/sys/net/core/rmem_max)"
          echo "T=ghcr.io/$(echo '${{ github.repository_owner }}' | tr A-Z a-z)/wd2l-phase0" >> "$GITHUB_ENV"
      - name: "Check 1: non-root user with only NET_RAW opens AF_PACKET"
        run: |
          sudo podman run --rm --network host --user 65532 --cap-drop all --cap-add NET_RAW "$PY" \
            python3 -c "import socket; s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)); s.bind(('lo', 0)); print('AF_PACKET ok')"
          if sudo podman run --rm --network host --user 65532 --cap-drop all "$PY" \
               python3 -c "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)"; then
            echo "UNEXPECTED: AF_PACKET without NET_RAW"; exit 1
          fi
          echo "without NET_RAW: refused, as expected"
          sudo podman run --rm --network host --user 65532 --cap-drop all --cap-add NET_RAW "$PY" \
            python3 -c "print(open('/proc/self/status').read())" | grep -E '^Cap(Prm|Eff|Bnd|Amb)'
      - name: "Check 5: NIC counters with the host network"
        run: |
          sudo podman run --rm --network host --user 65532 "$PY" python3 -c \
            "import os; print(sorted(os.listdir('/sys/class/net'))); print('lo rx_packets', open('/sys/class/net/lo/statistics/rx_packets').read().strip())"
      - name: "Check 6a: FIPS provider in force, md5 refused, the test suite under FIPS"
        run: |
          podman run --rm "$PY" python3 -c "
          import _hashlib, hashlib, ssl
          print('fips_mode', _hashlib.get_fips_mode(), ssl.OPENSSL_VERSION)
          try:
              hashlib.md5(b'x'); print('md5 ALLOWED')
          except ValueError as e:
              print('md5 refused:', e)
          print('sha256', hashlib.sha256(b'x').hexdigest()[:16])"
          podman run --rm --userns=keep-id -v "$PWD:/src" -w /src "$PYB" \
            bash -c 'python3 -m pip install -q --user pytest && python3 -m pytest -q -p no:cacheprovider'
      - name: "Check 7: cosign key pair, no transparency log, offline verify; the Red Hat signature"
        env:
          COSIGN_PASSWORD: phase0
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | podman login ghcr.io -u "${{ github.actor }}" --password-stdin
          AUTH="$XDG_RUNTIME_DIR/containers/auth.json"
          C() { podman run --rm --userns=keep-id -e COSIGN_PASSWORD -e HOME=/tmp -v "$PWD:/work" -w /work \
                  -v "$AUTH:/auth/config.json:ro" -e DOCKER_CONFIG=/auth "$COSIGN" "$@"; }
          Coff() { podman run --rm --network none --userns=keep-id -e HOME=/tmp -v "$PWD:/work" -w /work "$COSIGN" "$@"; }
          C version
          curl -s https://security.access.redhat.com/data/63405576.txt \
            | sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' > rh.pub
          echo "== Red Hat signature on $PY"
          C verify --key rh.pub --insecure-ignore-tlog "$PY" | head -c 800; echo
          C generate-key-pair
          printf 'FROM %s\n' "$PY" > Cf
          podman build -q -t "$T:check" -f Cf .
          podman push --digestfile d.txt "$T:check"; D=$(cat d.txt); echo "digest $D"
          C sign --key cosign.key --tlog-upload=false --yes "$T@$D"
          C verify --key cosign.pub --insecure-ignore-tlog "$T@$D" > /dev/null && echo "verify: ok"
          echo '{"hello": "phase0"}' > pred.json
          C attest --key cosign.key --tlog-upload=false --yes \
            --type https://example.invalid/phase0/v1 --predicate pred.json "$T@$D"
          C verify-attestation --key cosign.pub --insecure-ignore-tlog \
            --type https://example.invalid/phase0/v1 "$T@$D" > /dev/null && echo "verify-attestation: ok"
          C tree "$T@$D"
          C save --dir oci "$T@$D"
          Coff verify --key cosign.pub --insecure-ignore-tlog --local-image oci > /dev/null \
            && echo "offline verify of the saved layout: ok"
          Coff verify-attestation --key cosign.pub --insecure-ignore-tlog \
            --type https://example.invalid/phase0/v1 --local-image oci > /dev/null \
            && echo "offline verify-attestation of the saved layout: ok"
          echo blob > b.txt
          C sign-blob --key cosign.key --tlog-upload=false --yes --bundle b.sigstore.json b.txt
          Coff verify-blob --key cosign.pub --insecure-ignore-tlog --bundle b.sigstore.json b.txt \
            && echo "offline verify-blob: ok"
          echo "== offline import, then run by digest with no pull"
          sudo skopeo copy oci:oci containers-storage:"$T:imported"
          sudo podman image inspect --format 'stored digest {{.Digest}}' "$T:imported"
          sudo podman run --rm --pull=never "$T@$D" python3 -c 'print("run by digest after offline import: ok")'
      - name: "Check 8: copy the base and its records into ghcr"
        run: |
          AUTH="$XDG_RUNTIME_DIR/containers/auth.json"
          O() { podman run --rm --userns=keep-id -e HOME=/tmp -v "$AUTH:/auth/config.json:ro" "$ORAS" "$@"; }
          C() { podman run --rm --userns=keep-id -e HOME=/tmp -v "$AUTH:/auth/config.json:ro" -e DOCKER_CONFIG=/auth "$COSIGN" "$@"; }
          IDX="sha256:$(skopeo inspect --raw "docker://$PY" | sha256sum | cut -d' ' -f1)"
          echo "index digest $IDX"
          O copy --registry-config /auth/config.json -r "registry.access.redhat.com/hi/python@$IDX" "$T-base/python:check"
          O discover --registry-config /auth/config.json "$T-base/python@$IDX"
          C copy "quay.io/hummingbird/python@$IDX" "$T-base/python"
          skopeo list-tags --creds "${{ github.actor }}:${{ secrets.GITHUB_TOKEN }}" "docker://$T-base/python"
          REL=$(skopeo inspect --config "docker://$PY" | jq -r '.config.Labels.release')
          echo "source image tag ${REL}-source"
          O copy --registry-config /auth/config.json "registry.access.redhat.com/hi/python:${REL}-source" "$T-base/python:${REL}-source"
```

- [ ] **Step 3: Push the branch and run it** (with your partner's OK from step 1)

```bash
git switch -c phase0-checks
git add .github/workflows/phase0-checks.yml
git commit -m "Phase 0: throwaway checks workflow (not for merge)"
git push -u origin phase0-checks
gh workflow run phase0-checks.yml --ref phase0-checks
gh run watch "$(gh run list --workflow phase0-checks.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run view --log > /tmp/phase0-runner.log   # keep it for Task 0.3
git switch release-packaging
```

Expected, step by step:

* **Check 1:** `AF_PACKET ok`, then "refused, as expected". `CapEff` and `CapAmb` show
  `0000000000002000` (NET_RAW only).
* **Check 5:** the runner's NIC names and a number for `lo`.
* **Check 6a:**
  * `fips_mode 1`;
  * `md5 refused: …`;
  * pytest ends in `passed` with no failures.
* **Check 7:**
  * the Red Hat verification prints JSON that contains the index digest;
  * every "ok" line appears;
  * `cosign tree` lists the signature and the attestation;
  * `run by digest after offline import: ok`.
* **Check 8:** `oras discover` lists at least one `application/vnd.dev.sigstore.bundle.v0.3+json`
  referrer; `list-tags` shows `sha256-<hex>.att`, `.sbom` and `.sig`; the source copy completes.

If a line differs, don't fix anything yet; Task 0.3 records it and picks the fallback.

- [ ] **Step 4: Clean up.** Ask your partner to delete the packages `wd2l-phase0` and
  `wd2l-phase0-base/python` (GitHub → Packages → Package settings → Delete). Delete the branch
  once the log is saved: `git push origin --delete phase0-checks`, with their OK.

---

### Task 0.2: RHEL 10 VM checks (1, 2, 3, 4, 5, 6b)

**Files:** none in the repo.

**Interfaces:**
- Consumes: a RHEL 10 VM from your partner. It needs SELinux enforcing (`getenforce` →
  `Enforcing`), a clone of this branch at `~/wd2l`, and Podman. For check 6b it needs either a
  second VM installed in FIPS mode or a reinstall with `fips=1` (RHEL 10 sets FIPS mode at
  install time).
- Produces: the outputs for rows P0-1 (RHEL), P0-2, P0-3, P0-4, P0-5 (RHEL) and P0-6 (FIPS
  host).

Your partner runs these; you give them the block and collect the output. As root
(`sudo -i`), with `PY` set as at the top of this file:

- [ ] **Step 1: Check 1 on RHEL** (SELinux enforcing): run the three commands from Task 0.1's
  check 1 step, as root. Expected: the same results, and no AVC from
  `ausearch -m AVC -ts recent`.

- [ ] **Step 2: Check 2: does an env file's value reach the program as separate arguments?**

```bash
install -d /etc/wd2l
cat > /etc/wd2l/p0.env <<'EOF'
P0_ARGS="--one 1 \
--two 2 \
--three 3"
EOF
cat > /etc/systemd/system/p0-native.service <<'EOF'
[Service]
Type=oneshot
EnvironmentFile=/etc/wd2l/p0.env
ExecStart=/usr/bin/python3 -c "import sys; print('native', sys.argv[1:])" $P0_ARGS
EOF
mkdir -p /etc/containers/systemd
cat > /etc/containers/systemd/p0.container <<EOF
[Service]
Type=oneshot
EnvironmentFile=/etc/wd2l/p0.env
[Container]
Image=$PY
Exec=python3 -c "import sys; print('quadlet', sys.argv[1:])" \$P0_ARGS
EOF
systemctl daemon-reload
systemctl start p0-native p0
journalctl -u p0-native -u p0 -o cat --since -2min | grep -E "native|quadlet"
/usr/lib/systemd/system-generators/podman-system-generator --dryrun 2>/dev/null | grep ExecStart
```

Expected: both lines end in `['--one', '1', '--two', '2', '--three', '3']`. The generator's
`ExecStart` should show `$P0_ARGS` unescaped. If the Quadlet line shows `['$P0_ARGS']` or one
joined string, check 2 fails: the fallback is options written directly in `Exec=` (Task 3.5).

- [ ] **Step 3: Check 3: SELinux with shared bind mounts**

```bash
useradd -r -s /sbin/nologin wd2l 2>/dev/null || true
install -d -o wd2l -g wd2l -m 0750 /var/lib/wd2l /var/lib/wd2l/pcap
install -d -o wd2l -g wd2l -m 2750 /var/log/wd2l
sed 's/ens256/lo/' ~/wd2l/deploy/receiver/wd2l-capture.service > /etc/systemd/system/p0-capture.service
sed -i 's/-G 3600/-G 60/; /Requires=/d; /After=/d' /etc/systemd/system/p0-capture.service
systemctl daemon-reload && systemctl start p0-capture && sleep 3
ls -lZ /var/lib/wd2l/pcap
U=$(id -u wd2l); G=$(id -g wd2l)
podman run --rm --network host --user "$U:$G" \
  -v /var/lib/wd2l:/var/lib/wd2l:z -v /var/log/wd2l:/var/log/wd2l:z "$PY" python3 -c "
import glob, os
print('pcap files seen:', glob.glob('/var/lib/wd2l/pcap/cap-*.pcap'))
open('/var/lib/wd2l/state.json', 'w').write('{}')
open('/var/log/wd2l/audit-p0.jsonl', 'a').write('x\n')
print('state and audit written')"
sleep 70                                  # tcpdump starts a new file after the relabel
ls -lZ /var/lib/wd2l/pcap /var/lib/wd2l /var/log/wd2l
systemctl status p0-capture --no-pager | head -5
chattr +a /var/log/wd2l/audit-p0.jsonl && lsattr /var/log/wd2l/audit-p0.jsonl
ausearch -m AVC -ts recent
systemctl stop p0-capture
```

Expected (pass):

* the container sees the pcap files, and writes the state and audit files;
* after the relabel, tcpdump keeps writing new files (a second `cap-*` file appears and the
  unit stays active);
* `chattr +a` works;
* `ausearch` shows no AVC.

If tcpdump stops or AVCs appear, check 3 fails: Task 3.5 uses the fallback, a policy module
built from these denials:

```bash
ausearch -m AVC -ts recent | audit2allow -M wd2l
cat wd2l.te        # copy this into the P0-3 row; Task 3.5 commits it as packaging/selinux/wd2l.te
```

- [ ] **Step 4: Check 4: does the container show the user's name?** Try (a), then (b), then
  (c), and stop at the first one that prints `wd2l`:

```bash
U=$(id -u wd2l); G=$(id -g wd2l)
echo "(a)"; podman run --rm --user wd2l -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro "$PY" \
  python3 -c "import os, pwd; print(os.getuid(), pwd.getpwuid(os.getuid()).pw_name)"
echo "(b)"; podman run --rm --user "$U:$G" "$PY" \
  python3 -c "import os, pwd; print(os.getuid(), pwd.getpwuid(os.getuid()).pw_name)"
echo "(c)"; podman run --rm --user "$U:$G" --passwd-entry "wd2l:*:$U:$G::/tmp:/sbin/nologin" "$PY" \
  python3 -c "import os, pwd; print(os.getuid(), pwd.getpwuid(os.getuid()).pw_name)"
ausearch -m AVC -ts recent
```

Record which option printed `<uid> wd2l` with no AVC. Task 3.5 uses it:

* (a): `User=wd2l` plus the two read-only mounts;
* (b): `User=`/`Group=` numbers written by the install step;
* (c): (b) plus `PodmanArgs=--passwd-entry=…`.

If none prints the name, record that. Audit records then show `uid=N(?)`, and the containers
guide says so.

- [ ] **Step 5: Check 5 on RHEL:**

```bash
NIC=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')
podman run --rm --network host --user 65532 "$PY" python3 -c "print(open('/sys/class/net/$NIC/statistics/rx_packets').read())"
```

Expected: a number.

- [ ] **Step 6: Check 6b, on the VM installed in FIPS mode**

```bash
cat /proc/sys/crypto/fips_enabled            # 1
podman run --rm "$PY" python3 -c "import _hashlib, hashlib; print('fips_mode', _hashlib.get_fips_mode())
try:
    hashlib.md5(b'x'); print('md5 ALLOWED')
except ValueError as e:
    print('md5 refused:', e)"
openssl req -x509 -newkey rsa:3072 -nodes -keyout /tmp/k.pem -out /tmp/c.pem -days 2 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost
openssl s_server -accept 8443 -cert /tmp/c.pem -key /tmp/k.pem -www >/dev/null 2>&1 & S=$!
sleep 1
podman run --rm --network host -v /tmp/c.pem:/ca.pem:ro,Z "$PY" python3 -c "
import socket, ssl
c = ssl.create_default_context(cafile='/ca.pem')
s = c.wrap_socket(socket.create_connection(('localhost', 8443)), server_hostname='localhost')
print('TLS ok:', s.version(), s.cipher()[0])"
podman run --rm --network host "$PY" python3 -c "
import socket, ssl
try:
    ssl.create_default_context().wrap_socket(socket.create_connection(('localhost', 8443)), server_hostname='localhost')
    print('UNEXPECTED: verified without a CA file')
except ssl.SSLError as e:
    print('without --hec-ca: refused, as expected:', e.reason)"
kill $S
```

Expected:

* `fips_mode 1` and `md5 refused`;
* `TLS ok: TLSv1.3 TLS_AES_256_GCM_SHA384` (or another AES-GCM suite);
* "refused, as expected" without the CA file.

- [ ] **Step 7: Clean up the VM**

```bash
systemctl disable --now p0-capture 2>/dev/null; rm -f /etc/systemd/system/p0-*.service \
  /etc/containers/systemd/p0.container /etc/wd2l/p0.env /var/log/wd2l/audit-p0.jsonl 2>/dev/null
chattr -a /var/log/wd2l/audit-p0.jsonl 2>/dev/null; systemctl daemon-reload
```

---

### Task 0.3: Record the results and the fallbacks

**Files:**
- Modify: `docs/superpowers/plans/2026-10-07-release-packaging/README.md` (As-built log)

**Interfaces:**
- Consumes: the outputs of Tasks 0.1 and 0.2.
- Produces: rows `P0-1` … `P0-8`. **Later tasks read them:**
  * Task 3.5 reads P0-2, P0-3 and P0-4;
  * Task 4.2 reads P0-7;
  * Tasks 4.7 and 6.3 read P0-7 and P0-8;
  * Task 1.3 reads P0-6.

- [ ] **Step 1: Add one row per check** to the As-built log. Use this shape (the example is
  check 4 when (a) failed and (b) worked):

```markdown
| P0-4 | Phase 0 check 4 | Option (b): numeric `User=`/`Group=`, written at install (`id -u wd2l`); no /etc/passwd mount | (a) failed: "unable to find user wd2l" — podman looks up names before mounts are applied |
```

Every row says, in the "Built" column, what later tasks must do. Also record:

* **P0-7:** the exact cosign version and flags that worked; whether `--bundle` or
  `--output-signature` was needed for `sign-blob`; whether `cosign save` carried the
  attestation.
* **P0-8:** whether the `.att`/`.sbom` tags came across.
* The runner's `rmem_max` (for Task 3.3).

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/2026-10-07-release-packaging/README.md
git commit -m "Release plan: Phase 0 check results and the fallbacks chosen"
```
