"""HTTP API tests: frozen audits, atomicity, validation errors."""

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from app import server
from app.tarbuild import d, f, layer_b64, ln, opq, wh


def request(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), server.make_handler(server.AuditStore()))
        cls.httpd.daemon_threads = True
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def url(self, path):
        return self.base + path

    def test_healthz(self):
        status, body = request("GET", self.url("/healthz"))
        self.assertEqual((status, body["status"]), (200, "ok"))

    def test_post_then_get_frozen_result(self):
        layers = [
            layer_b64([d("app"), f("app/a.txt", "1"), f("app/b.txt", "2")]),
            layer_b64([wh("app", "a.txt"), f("app/c.txt", "3")]),
        ]
        status, created = request("POST", self.url("/audits"),
                                  {"id": "t-post", "layers": layers})
        self.assertEqual(status, 201)
        self.assertEqual(created["layerCount"], 2)
        self.assertEqual(
            [p["path"] for p in created["paths"]],
            ["app", "app/b.txt", "app/c.txt"])
        self.assertEqual(created["deletions"], [{
            "path": "app/a.txt", "layer": 0, "kind": "whiteout",
            "byLayer": 1, "via": "app/.wh.a.txt",
        }])
        status, got = request("GET", self.url("/audits/t-post"))
        self.assertEqual(status, 200)
        self.assertEqual(got, created)

    def test_frozen_id_conflict(self):
        payload = {"id": "t-frozen", "layers": [layer_b64([f("a", "x")])]}
        status, _ = request("POST", self.url("/audits"), payload)
        self.assertEqual(status, 201)
        status, body = request("POST", self.url("/audits"), payload)
        self.assertEqual(status, 409)
        self.assertIn("frozen", body["error"])
        # Original result untouched.
        _, got = request("GET", self.url("/audits/t-frozen"))
        self.assertEqual([p["path"] for p in got["paths"]], ["a"])

    def test_get_unknown_id(self):
        status, _ = request("GET", self.url("/audits/nope"))
        self.assertEqual(status, 404)

    def test_list_audits(self):
        request("POST", self.url("/audits"),
                {"id": "t-list", "layers": [layer_b64([f("a")])]})
        status, body = request("GET", self.url("/audits"))
        self.assertEqual(status, 200)
        self.assertIn("t-list", body["audits"])

    def test_too_many_layers(self):
        status, body = request(
            "POST", self.url("/audits"),
            {"id": "t-many", "layers": [layer_b64([])] * 7})
        self.assertEqual(status, 400)
        self.assertIn("1..6", body["error"])

    def test_zero_layers(self):
        status, _ = request("POST", self.url("/audits"), {"id": "t-zero", "layers": []})
        self.assertEqual(status, 400)

    def test_invalid_base64(self):
        status, body = request("POST", self.url("/audits"),
                               {"id": "t-b64", "layers": ["!!!not-base64!!!"]})
        self.assertEqual(status, 400)
        self.assertIn("base64", body["error"])

    def test_invalid_gzip(self):
        import base64
        blob = base64.b64encode(b"not a gzip stream at all").decode()
        status, body = request("POST", self.url("/audits"),
                               {"id": "t-gz", "layers": [blob]})
        self.assertEqual(status, 400)
        self.assertIn("layer 0", body["error"])

    def test_invalid_id(self):
        status, _ = request("POST", self.url("/audits"),
                            {"id": "bad/id", "layers": [layer_b64([])]})
        self.assertEqual(status, 400)

    def test_failed_audit_is_atomic(self):
        # Layer 1 (index 1) contains a dangling hard link: the whole audit
        # must be rejected and no partial state may be retrievable.
        layers = [
            layer_b64([d("ok"), f("ok/a.txt", "1")]),
            layer_b64([ln("ok/b.txt", "ok/missing.txt")]),
        ]
        status, body = request("POST", self.url("/audits"),
                               {"id": "t-atomic", "layers": layers})
        self.assertEqual(status, 400)
        self.assertIn("layer 1", body["error"])
        status, _ = request("GET", self.url("/audits/t-atomic"))
        self.assertEqual(status, 404)

    def test_malformed_json(self):
        req = urllib.request.Request(self.url("/audits"), data=b"{not json",
                                     method="POST",
                                     headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)


class HistoryEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), server.make_handler(server.AuditStore()))
        cls.httpd.daemon_threads = True
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.audit_id = "t-history"
        # Layer 0: dir with descendants; layer 1: opaque clear + same-layer
        # fresh file + file overwrite; layer 2: dir -> file replacement;
        # layer 3: rebuild of the wiped descendant in a later layer.
        layers = [
            layer_b64([
                d("d"), d("d/sub"), f("d/sub/gone.txt", "old"),
                f("d/keep.txt", "k"), f("d/f.txt", "v1"),
            ]),
            layer_b64([
                opq("d"), f("d/fresh.txt", "new"), f("d/f.txt", "v2"),
            ]),
            layer_b64([f("d/sub", "now-a-file")]),
            layer_b64([wh("d", "sub"), d("d/sub"), f("d/sub/gone.txt", "new")]),
        ]
        status, cls.created = request("POST", f"{cls.base}/audits",
                                      {"id": cls.audit_id, "layers": layers})
        assert status == 201, cls.created

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def history(self, raw_path, **extra):
        import urllib.parse
        query = urllib.parse.urlencode({"path": raw_path, **extra})
        return request("GET", f"{self.base}/audits/{self.audit_id}/history?{query}")

    def test_full_evolution_of_rebuilt_descendant(self):
        status, body = self.history("d/sub/gone.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], self.audit_id)
        self.assertEqual(body["path"], "d/sub/gone.txt")
        self.assertEqual(body["status"], "present")
        actions = [(e["action"], e["layer"], e["via"],
                    e["beforeType"], e["afterType"]) for e in body["history"]]
        self.assertEqual(actions, [
            ("create", 0, "d/sub/gone.txt", None, "file"),
            ("opaque", 1, "d/.wh..wh..opq", "file", None),
            ("recreate", 3, "d/sub/gone.txt", None, "file"),
        ])
        self.assertEqual(body["final"], {"type": "file", "layer": 3})
        # Final source must agree with the frozen full-audit verdict.
        final = next(p for p in self.created["paths"]
                     if p["path"] == "d/sub/gone.txt")
        self.assertEqual(body["final"]["layer"], final["layer"])

    def test_replaced_directory_descendant_explains_disappearance(self):
        # Separate audit: a directory is replaced by a file in a higher
        # layer; its descendant never gets a direct deletion entry but must
        # still report the ancestor overwrite as the cause of vanishing.
        layers = [
            layer_b64([d("p"), d("p/c"), f("p/c/child.txt", "x")]),
            layer_b64([f("p", "now-a-file")]),
        ]
        status, _ = request("POST", f"{self.base}/audits",
                            {"id": "t-history-replace", "layers": layers})
        self.assertEqual(status, 201)
        status, body = request(
            "GET", f"{self.base}/audits/t-history-replace/history"
                   "?path=p/c/child.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "deleted")
        self.assertEqual(
            [(e["action"], e["via"], e["afterType"]) for e in body["history"]],
            [("create", "p/c/child.txt", "file"),
             ("overwrite", "p", None)])

    def test_replaced_descendant_rebuilt_later_stays_consistent(self):
        # Ancestor dir -> file wipes the child; a later layer recreates the
        # subtree.  The evolution stays continuous and the final source
        # matches the frozen verdict.
        layers = [
            layer_b64([d("p"), d("p/c"), f("p/c/child.txt", "x")]),
            layer_b64([f("p", "now-a-file")]),
            layer_b64([wh("", "p"), d("p"), d("p/c"),
                       f("p/c/child.txt", "y")]),
        ]
        status, created = request(
            "POST", f"{self.base}/audits",
            {"id": "t-history-rebuild", "layers": layers})
        self.assertEqual(status, 201)
        status, body = request(
            "GET", f"{self.base}/audits/t-history-rebuild/history"
                   "?path=p/c/child.txt")
        self.assertEqual(status, 200)
        self.assertEqual([e["action"] for e in body["history"]],
                         ["create", "overwrite", "recreate"])
        final = next(p for p in created["paths"]
                     if p["path"] == "p/c/child.txt")
        self.assertEqual(body["final"]["layer"], final["layer"])

    def test_opaque_rebuild_whiteout_recreate_chain(self):
        # d/sub: dir (0), opaque-cleared (1), rebuilt as a file (2),
        # whited out (3) and recreated as a dir (3).
        status, body = self.history("d/sub")
        self.assertEqual(status, 200)
        self.assertEqual([e["action"] for e in body["history"]],
                         ["create", "opaque", "recreate", "whiteout",
                          "recreate"])
        self.assertEqual(body["history"][2]["beforeType"], None)
        self.assertEqual(body["history"][2]["afterType"], "file")
        self.assertEqual(body["history"][2]["via"], "d/sub")
        self.assertEqual(body["final"]["type"], "dir")

    def test_same_layer_file_after_opaque_is_recreated(self):
        # Opaque clears the lower f.txt first; the same-layer v2 entry is a
        # recreate carrying the new layer, not an overwrite.
        status, body = self.history("d/f.txt")
        self.assertEqual(status, 200)
        self.assertEqual([e["action"] for e in body["history"]],
                         ["create", "opaque", "recreate"])
        self.assertEqual(body["history"][2]["via"], "d/f.txt")
        self.assertEqual(body["final"]["layer"], 1)

    def test_plain_file_overwrite(self):
        layers = [
            layer_b64([f("m.txt", "v1")]),
            layer_b64([f("m.txt", "v2")]),
        ]
        request("POST", f"{self.base}/audits",
                {"id": "t-history-overwrite", "layers": layers})
        status, body = request(
            "GET", f"{self.base}/audits/t-history-overwrite/history?path=m.txt")
        self.assertEqual(status, 200)
        self.assertEqual([e["action"] for e in body["history"]],
                         ["create", "overwrite"])
        event = body["history"][1]
        self.assertEqual((event["beforeType"], event["afterType"]),
                         ("file", "file"))

    def test_deleted_path_status(self):
        # d/keep.txt survives the opaque? No: opaque clears ALL lower
        # children; only same-layer additions survive.  keep.txt is gone.
        status, body = self.history("d/keep.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "deleted")
        self.assertIsNone(body["final"])
        self.assertEqual([e["action"] for e in body["history"]],
                         ["create", "opaque"])

    def test_untracked_legal_path(self):
        status, body = self.history("d/never-existed.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "untracked")
        self.assertEqual(body["history"], [])
        self.assertEqual(body["path"], "d/never-existed.txt")

    def test_illegal_paths_are_rejected_without_records(self):
        for bad in ("../escape", "/abs/path", "a//b", "a/./b", "a/", ""):
            status, body = self.history(bad)
            self.assertEqual(status, 400, f"expected 400 for {bad!r}")
            self.assertNotIn("history", body)
            self.assertNotIn("final", body)

    def test_missing_path_parameter(self):
        status, body = request(
            "GET", f"{self.base}/audits/{self.audit_id}/history")
        self.assertEqual(status, 400)
        self.assertNotIn("history", body)

    def test_unknown_audit_leaks_nothing(self):
        status, body = request(
            "GET", f"{self.base}/audits/unknown-id/history?path=d/f.txt")
        self.assertEqual(status, 404)
        self.assertNotIn("history", body)
        self.assertNotIn("status", body)

    def test_unknown_audit_with_illegal_path_still_404(self):
        status, _ = request(
            "GET", f"{self.base}/audits/unknown-id/history?path=../x")
        self.assertEqual(status, 404)

    def test_history_does_not_change_frozen_result(self):
        status, got = request("GET", f"{self.base}/audits/{self.audit_id}")
        self.assertEqual(status, 200)
        self.assertEqual(got, self.created)


if __name__ == "__main__":
    unittest.main()
