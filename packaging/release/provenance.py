#!/usr/bin/env python3
"""The SLSA v1 provenance predicate for a published image. `cosign attest --type slsaprovenance1`
wraps it in an in-toto statement whose subject is the image digest. It names the commit, the
workflow, the wheel and the exact base images, with their mirrored copies
(docs/decisions/0006-release-artifacts-and-signing.md). It is self-asserted: made in the build
workflow and signed with the release key. The SLSA Build L3 provenance is GitHub's attestation,
made by attest.yml (docs/decisions/0007-slsa-build-l3.md).

    provenance.py --wheel WHL --froms froms.json --mirror REPO --started ISO > provenance.json"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence


def predicate(env: Mapping[str, str], wheel_name: str, wheel_sha256: str,
              froms: List[Dict[str, Any]], mirror: str, started: str,
              finished: str) -> Dict[str, Any]:
    server, repo = env["GITHUB_SERVER_URL"], env["GITHUB_REPOSITORY"]
    workflow = env.get("GITHUB_WORKFLOW_REF", "")
    deps: List[Dict[str, Any]] = [
        {"uri": "git+%s/%s@%s" % (server, repo, env["GITHUB_REF"]),
         "digest": {"gitCommit": env["GITHUB_SHA"]}},
        {"uri": wheel_name, "digest": {"sha256": wheel_sha256}}]
    for f in froms:
        deps.append({"uri": "%s:%s" % (f["name"], f["tag"]),
                     "digest": {"sha256": f["digest"].split(":", 1)[1]},
                     "annotations": {"stage": f["stage"] or "runtime",
                                     "mirror": "%s@%s" % (mirror, f["digest"])}})
    return {
        "buildDefinition": {
            "buildType": "%s/%s/blob/main/docs/releasing.md#how-a-release-is-built" % (server, repo),
            "externalParameters": {
                "workflow": {"ref": env["GITHUB_REF"], "repository": "%s/%s" % (server, repo),
                             "path": workflow.split("@")[0].split("/", 2)[-1] if workflow else ""},
                "containerfile": "packaging/container/Containerfile"},
            "internalParameters": {"github": {
                "event_name": env.get("GITHUB_EVENT_NAME"),
                "runner_environment": env.get("RUNNER_ENVIRONMENT"),
                "repository_id": env.get("GITHUB_REPOSITORY_ID")}},
            "resolvedDependencies": deps},
        "runDetails": {
            "builder": {"id": "%s/%s" % (server, workflow) if workflow else server},
            "metadata": {
                "invocationId": "%s/%s/actions/runs/%s/attempts/%s" % (
                    server, repo, env["GITHUB_RUN_ID"], env.get("GITHUB_RUN_ATTEMPT", "1")),
                "startedOn": started, "finishedOn": finished}}}


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="SLSA v1 predicate for the image.")
    p.add_argument("--wheel", required=True)
    p.add_argument("--froms", required=True, help="check_containerfile.py --json output")
    p.add_argument("--mirror", required=True, help="where the base images are mirrored")
    p.add_argument("--started", required=True)
    a = p.parse_args(argv)
    with open(a.wheel, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    with open(a.froms) as f:
        froms = json.load(f)
    finished = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    json.dump(predicate(os.environ, os.path.basename(a.wheel), sha, froms, a.mirror, a.started,
                        finished), sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
