"""HTTP API tests: frozen audits, atomicity, validation errors."""

import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

from app import server
from app.tarbuild import d, f, layer_b64, ln, wh


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
    """GET /audits/{id}/history?path=... on frozen audits."""

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), server.make_handler(server.AuditStore()))
        cls.httpd.daemon_threads = True
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        # One frozen audit shared by the read-only history tests:
        #   layer 0: p/ + p/sub/a.txt + p/keep.txt
        #   layer 1: whiteout of p/sub, p/manifest.txt created
        #   layer 2: p/sub/a.txt rebuilt, p/manifest.txt superseded
        layers = [
            layer_b64([d("p"), d("p/sub"), f("p/sub/a.txt", "1"),
                       f("p/keep.txt", "k")]),
            layer_b64([wh("p", "sub"), f("p/manifest.txt", "m1")]),
            layer_b64([f("p/sub/a.txt", "2"), f("p/manifest.txt", "m2")]),
        ]
        status, cls.frozen = request("POST", cls.base + "/audits",
                                     {"id": "h-main", "layers": layers})
        assert status == 201, cls.frozen

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def history(self, audit_id, raw_path=None):
        url = f"{self.base}/audits/{audit_id}/history"
        if raw_path is not None:
            url += "?" + urllib.parse.urlencode({"path": raw_path})
        return request("GET", url)

    def test_frozen_result_has_no_history_key(self):
        self.assertNotIn("history", self.frozen)
        status, got = request("GET", self.base + "/audits/h-main")
        self.assertEqual(status, 200)
        self.assertEqual(got, self.frozen)
        self.assertNotIn("history", got)

    def test_rebuilt_path_full_evolution(self):
        status, body = self.history("h-main", "p/sub/a.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], "h-main")
        self.assertEqual(body["path"], "p/sub/a.txt")
        self.assertTrue(body["tracked"])
        # Final state consistent with the frozen path list.
        final = next(p for p in self.frozen["paths"]
                     if p["path"] == "p/sub/a.txt")
        self.assertTrue(body["present"])
        self.assertEqual(body["type"], final["type"])
        self.assertEqual(body["layer"], final["layer"])
        self.assertEqual(body["actions"], [
            {"action": "created", "layer": 0, "via": "p/sub/a.txt",
             "fromType": None, "toType": "file"},
            {"action": "whiteout", "layer": 1, "via": "p/.wh.sub",
             "fromType": "file", "toType": None},
            {"action": "created", "layer": 2, "via": "p/sub/a.txt",
             "fromType": None, "toType": "file"},
        ])

    def test_ancestor_dir_history_shows_removal_and_rebuild(self):
        status, body = self.history("h-main", "p/sub")
        self.assertEqual(status, 200)
        self.assertEqual(body["actions"], [
            {"action": "created", "layer": 0, "via": "p/sub",
             "fromType": None, "toType": "dir"},
            {"action": "whiteout", "layer": 1, "via": "p/.wh.sub",
             "fromType": "dir", "toType": None},
            {"action": "created", "layer": 2, "via": "p/sub/a.txt",
             "fromType": None, "toType": "dir"},
        ])
        self.assertTrue(body["present"])
        self.assertEqual(body["layer"], 2)

    def test_superseded_file_history(self):
        status, body = self.history("h-main", "p/manifest.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body["actions"], [
            {"action": "created", "layer": 1, "via": "p/manifest.txt",
             "fromType": None, "toType": "file"},
            {"action": "replaced", "layer": 2, "via": "p/manifest.txt",
             "fromType": "file", "toType": "file"},
        ])
        self.assertTrue(body["present"])
        self.assertEqual(body["layer"], 2)

    def test_untouched_path_has_single_creation_event(self):
        status, body = self.history("h-main", "p/keep.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body["actions"], [
            {"action": "created", "layer": 0, "via": "p/keep.txt",
             "fromType": None, "toType": "file"},
        ])

    def test_untracked_canonical_path(self):
        status, body = self.history("h-main", "p/never.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body["tracked"], False)
        self.assertEqual(body["present"], False)
        self.assertEqual(body["actions"], [])
        # Whiteout entries never entered the tree: also untracked.
        status, body = self.history("h-main", "p/.wh.sub")
        self.assertEqual(status, 200)
        self.assertEqual(body["tracked"], False)

    def test_illegal_paths_rejected(self):
        for raw in ("../escape.txt", "/abs.txt", "p/", "p//a.txt", "p/./a.txt"):
            status, body = self.history("h-main", raw)
            self.assertEqual(status, 400, raw)
            self.assertIn("error", body)

    def test_missing_path_param(self):
        status, _ = request("GET", self.base + "/audits/h-main/history")
        self.assertEqual(status, 400)

    def test_unknown_audit(self):
        status, _ = self.history("no-such-audit", "p")
        self.assertEqual(status, 404)

    def test_never_frozen_audit_leaks_nothing(self):
        layers = [layer_b64([ln("x/y", "x/missing")])]
        status, _ = request("POST", self.base + "/audits",
                            {"id": "h-failed", "layers": layers})
        self.assertEqual(status, 400)
        status, _ = self.history("h-failed", "x/y")
        self.assertEqual(status, 404)

    def test_unknown_subresource(self):
        status, _ = request("GET", self.base + "/audits/h-main/bogus")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
