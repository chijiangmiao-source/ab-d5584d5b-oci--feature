"""HTTP smoke client for the verify container.

Submits an audit that exercises opaque directories, whiteout deletion,
file/dir replacement, path rebuild in a later layer and hard links, then
reads the frozen result back and compares it exactly.  A second audit
exercises the full per-path evolution entry point (``GET
/audits/{id}/history``) across opaque clear, ancestor directory
replacement and later rebuild.  Also probes the negative paths (too many
layers, dangling hard link, traversal, frozen id re-use, unknown id,
illegal/untracked history paths).  Exits 0 only if every check passes.

Run: ``APP_ADDR=http://app:8080 python -m app.smoke``
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

from .tarbuild import d, f, layer_b64, ln, opq, wh


def build_smoke_layers() -> list[str]:
    layer0 = layer_b64([
        d("payload"), d("payload/calib"), d("payload/logs"), d("payload/scratch"),
        f("payload/calib/gain.txt", "gain-v1"),
        f("payload/calib/offset.txt", "offset-v1"),
        f("payload/logs/old.log", "stale"),
        f("payload/scratch/tmp.txt", "tmp"),
        f("payload/manifest.txt", "manifest-v1"),
    ])
    layer1 = layer_b64([
        wh("payload/calib", "gain.txt"),        # revoke calibration file
        opq("payload/logs"),                    # opaque: clear lower logs
        f("payload/logs/fresh.log", "fresh"),   # survives the opaque marker
        f("payload/manifest.txt", "manifest-v2"),  # file superseded
    ])
    layer2 = layer_b64([
        f("payload/calib/gain.txt", "gain-v3"),  # rebuild after whiteout
        ln("payload/calib/gain.link", "payload/calib/gain.txt"),
        f("payload/scratch", "now-a-file"),      # dir -> file replacement
    ])
    return [layer0, layer1, layer2]


EXPECTED_PATHS = [
    {"path": "payload", "type": "dir", "layer": 0},
    {"path": "payload/calib", "type": "dir", "layer": 0},
    {"path": "payload/calib/gain.link", "type": "file", "layer": 2,
     "link": "payload/calib/gain.txt"},
    {"path": "payload/calib/gain.txt", "type": "file", "layer": 2},
    {"path": "payload/calib/offset.txt", "type": "file", "layer": 0},
    {"path": "payload/logs", "type": "dir", "layer": 0},
    {"path": "payload/logs/fresh.log", "type": "file", "layer": 1},
    {"path": "payload/manifest.txt", "type": "file", "layer": 1},
    {"path": "payload/scratch", "type": "file", "layer": 2},
]

EXPECTED_DELETIONS = [
    {"path": "payload/calib/gain.txt", "layer": 0, "kind": "whiteout",
     "byLayer": 1, "via": "payload/calib/.wh.gain.txt"},
    {"path": "payload/logs/old.log", "layer": 0, "kind": "opaque",
     "byLayer": 1, "via": "payload/logs/.wh..wh..opq"},
    {"path": "payload/manifest.txt", "layer": 0, "kind": "replaced",
     "byLayer": 1, "via": "payload/manifest.txt"},
    {"path": "payload/scratch", "layer": 0, "kind": "replaced",
     "byLayer": 2, "via": "payload/scratch"},
    {"path": "payload/scratch/tmp.txt", "layer": 0, "kind": "replaced",
     "byLayer": 2, "via": "payload/scratch"},
]


def build_evolution_layers() -> list[str]:
    """Audit whose 'ev/seq/sample.txt' path sees every evolution action."""
    layer0 = layer_b64([
        d("ev"), d("ev/seq"),
        f("ev/seq/sample.txt", "v0"),
        f("ev/cal.txt", "v0"),
    ])
    layer1 = layer_b64([
        opq("ev"),                           # opaque-clear lower children
        f("ev/new.txt", "fresh"),            # same-layer addition survives
    ])
    layer2 = layer_b64([
        d("ev/seq"),                         # rebuild after opaque
        f("ev/seq/sample.txt", "v2"),
    ])
    layer3 = layer_b64([
        f("ev/seq", "now-a-file"),           # directory -> file replacement
    ])
    layer4 = layer_b64([
        wh("ev", "seq"),                     # whiteout the replacement file
        d("ev/seq"),                         # rebuild the directory
        f("ev/seq/sample.txt", "v4"),        # rebuild the descendant
    ])
    return [layer0, layer1, layer2, layer3, layer4]


# Complete, ordered evolution of ev/seq/sample.txt: creation, opaque clear,
# rebuild, ancestor-driven disappearance (dir replaced by file) and a final
# rebuild -- the story the archive engineers need in one read.
EXPECTED_SAMPLE_HISTORY = [
    {"action": "create", "layer": 0, "via": "ev/seq/sample.txt",
     "beforeType": None, "afterType": "file"},
    {"action": "opaque", "layer": 1, "via": "ev/.wh..wh..opq",
     "beforeType": "file", "afterType": None},
    {"action": "recreate", "layer": 2, "via": "ev/seq/sample.txt",
     "beforeType": None, "afterType": "file"},
    {"action": "overwrite", "layer": 3, "via": "ev/seq",
     "beforeType": "file", "afterType": None},
    {"action": "recreate", "layer": 4, "via": "ev/seq/sample.txt",
     "beforeType": None, "afterType": "file"},
]

EXPECTED_EVOLUTION_PATHS = [
    {"path": "ev", "type": "dir", "layer": 0},
    {"path": "ev/new.txt", "type": "file", "layer": 1},
    {"path": "ev/seq", "type": "dir", "layer": 4},
    {"path": "ev/seq/sample.txt", "type": "file", "layer": 4},
]


def _request(method: str, url: str, payload: dict | None = None,
             timeout: int = 10) -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read())
        except Exception:
            body = {}
        return exc.code, body


def main() -> int:
    addr = os.environ.get("APP_ADDR", "http://127.0.0.1:8080").rstrip("/")
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}"
              + (f"  -- {detail}" if detail and not ok else ""), flush=True)
        if not ok:
            failures.append(name)

    print(f"[smoke] waiting for {addr}/healthz ...", flush=True)
    deadline = time.time() + float(os.environ.get("SMOKE_WAIT_SECONDS", "60"))
    while True:
        try:
            status, _ = _request("GET", addr + "/healthz", timeout=3)
            if status == 200:
                break
        except Exception:
            pass
        if time.time() > deadline:
            print("[smoke] FAIL: service did not become healthy", flush=True)
            return 1
        time.sleep(1)

    print("[smoke] submitting opaque/rebuild audit", flush=True)
    audit_id = f"smoke-{int(time.time())}-{os.getpid()}"
    status, created = _request("POST", addr + "/audits",
                               {"id": audit_id, "layers": build_smoke_layers()})
    check("POST /audits -> 201", status == 201, f"got {status}: {created}")
    if status == 201:
        check("POST response paths match",
              created.get("paths") == EXPECTED_PATHS, json.dumps(created.get("paths")))
        check("POST response deletions match",
              created.get("deletions") == EXPECTED_DELETIONS,
              json.dumps(created.get("deletions")))

    status, got = _request("GET", f"{addr}/audits/{audit_id}")
    check("GET /audits/{id} -> 200", status == 200, f"got {status}")
    if status == 200:
        check("GET frozen paths match", got.get("paths") == EXPECTED_PATHS,
              json.dumps(got.get("paths")))
        check("GET frozen deletions match",
              got.get("deletions") == EXPECTED_DELETIONS,
              json.dumps(got.get("deletions")))
        check("GET frozen layerCount", got.get("layerCount") == 3)

    status, _ = _request("POST", addr + "/audits",
                         {"id": audit_id, "layers": build_smoke_layers()})
    check("re-POST frozen id -> 409", status == 409, f"got {status}")

    status, _ = _request("POST", addr + "/audits",
                         {"id": audit_id + "-many", "layers": build_smoke_layers() * 3})
    check("more than 6 layers -> 400", status == 400, f"got {status}")

    dangling = layer_b64([ln("payload/link", "payload/missing-target")])
    status, _ = _request("POST", addr + "/audits",
                         {"id": audit_id + "-dangling", "layers": [dangling]})
    check("dangling hard link -> 400", status == 400, f"got {status}")
    status, _ = _request("GET", f"{addr}/audits/{audit_id}-dangling")
    check("failed audit left no state -> 404", status == 404, f"got {status}")

    traversal = layer_b64([f("../escape.txt", "x")])
    status, _ = _request("POST", addr + "/audits",
                         {"id": audit_id + "-trav", "layers": [traversal]})
    check("path traversal -> 400", status == 400, f"got {status}")

    status, _ = _request("GET", addr + "/audits/never-submitted")
    check("GET unknown id -> 404", status == 404, f"got {status}")

    print("[smoke] submitting opaque/replacement/rebuild evolution audit",
          flush=True)
    ev_id = f"{audit_id}-evolution"
    status, ev_created = _request(
        "POST", addr + "/audits",
        {"id": ev_id, "layers": build_evolution_layers()})
    check("POST evolution audit -> 201", status == 201,
          f"got {status}: {ev_created}")
    if status == 201:
        check("evolution frozen paths match",
              ev_created.get("paths") == EXPECTED_EVOLUTION_PATHS,
              json.dumps(ev_created.get("paths")))

    status, hist = _request(
        "GET", f"{addr}/audits/{ev_id}/history?path=ev/seq/sample.txt")
    check("GET history -> 200", status == 200, f"got {status}: {hist}")
    if status == 200:
        check("history status present", hist.get("status") == "present")
        check("complete evolution (create/opaque/recreate/overwrite/"
              "recreate)",
              hist.get("history") == EXPECTED_SAMPLE_HISTORY,
              json.dumps(hist.get("history")))
        final = next((p for p in ev_created.get("paths", [])
                      if p["path"] == "ev/seq/sample.txt"), None)
        check("history final source matches frozen verdict",
              final is not None
              and hist.get("final", {}).get("layer") == final["layer"]
              and hist.get("final", {}).get("type") == final["type"],
              f"{hist.get('final')} != {final}")

    # The wiped calibration file explains its own opaque disappearance.
    status, gone = _request(
        "GET", f"{addr}/audits/{ev_id}/history?path=ev/cal.txt")
    check("deleted path history -> status deleted",
          status == 200 and gone.get("status") == "deleted"
          and gone.get("final") is None
          and [e["action"] for e in gone.get("history", [])]
          == ["create", "opaque"],
          json.dumps(gone))

    # A legal path that never appeared in any layer is explicitly untracked.
    status, untracked = _request(
        "GET", f"{addr}/audits/{ev_id}/history?path=ev/not-here.bin")
    check("untracked legal path -> 200 status untracked",
          status == 200 and untracked.get("status") == "untracked"
          and untracked.get("history") == [],
          json.dumps(untracked))

    # Illegal paths, missing parameter and unknown audits must not leak any
    # partial record.
    for bad in ("..%2Fescape", "%2Fabs", "ev%2F", "ev%2F.%2Fx"):
        status, body = _request(
            "GET", f"{addr}/audits/{ev_id}/history?path={bad}")
        check(f"illegal path {bad} -> 400 with no record",
              status == 400 and "history" not in body and "final" not in body,
              f"got {status}: {body}")
    status, body = _request("GET", f"{addr}/audits/{ev_id}/history")
    check("missing path parameter -> 400", status == 400, f"got {status}")
    status, body = _request(
        "GET", f"{addr}/audits/no-such-audit/history?path=ev/new.txt")
    check("history for unknown audit -> 404 with no record",
          status == 404 and "history" not in body, f"got {status}: {body}")

    if failures:
        print(f"[smoke] FAILED ({len(failures)} check(s))", flush=True)
        return 1
    print("[smoke] OK: all checks passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
