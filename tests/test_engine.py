"""Whiteout-rule tests for the union engine."""

import unittest

from app.engine import EngineError, apply_layers
from app.tarparse import TYPE_DIR, TYPE_FILE, TYPE_LINK, Entry


def F(path):
    return Entry(path, TYPE_FILE, 1)


def D(path):
    return Entry(path, TYPE_DIR)


def L(path, target):
    return Entry(path, TYPE_LINK, 0, target)


def paths_of(result):
    return {item["path"]: item for item in result["paths"]}


class WhiteoutTests(unittest.TestCase):
    def test_whiteout_deletes_lower_file_and_leaves_no_trace(self):
        result = apply_layers([
            [D("etc"), F("etc/cal.txt"), F("etc/keep.txt")],
            [F("etc/.wh.cal.txt")],
        ])
        paths = paths_of(result)
        self.assertEqual(sorted(paths), ["etc", "etc/keep.txt"])
        self.assertEqual(paths["etc/keep.txt"]["layer"], 0)
        self.assertEqual(result["deletions"], [{
            "path": "etc/cal.txt", "layer": 0, "kind": "whiteout",
            "byLayer": 1, "via": "etc/.wh.cal.txt",
        }])

    def test_whiteout_removes_whole_subtree(self):
        result = apply_layers([
            [D("a"), D("a/b"), F("a/b/c.txt"), F("a/top.txt")],
            [F("a/.wh.b")],
        ])
        self.assertEqual(sorted(paths_of(result)), ["a", "a/top.txt"])
        self.assertEqual(
            [d["path"] for d in result["deletions"]], ["a/b", "a/b/c.txt"])

    def test_whiteout_of_missing_path_is_tolerated(self):
        result = apply_layers([[F("x.txt")], [F(".wh.never-existed")]])
        self.assertEqual(sorted(paths_of(result)), ["x.txt"])
        self.assertEqual(result["deletions"], [])

    def test_opaque_clears_lower_children_but_keeps_same_layer_entries(self):
        result = apply_layers([
            [D("d"), F("d/old1.txt"), F("d/old2.txt"), D("d/sub"),
             F("d/sub/deep.txt"), F("top.txt")],
            [F("d/.wh..wh..opq"), F("d/new.txt")],
        ])
        paths = paths_of(result)
        self.assertEqual(sorted(paths), ["d", "d/new.txt", "top.txt"])
        self.assertEqual(paths["d"]["layer"], 0)  # dir itself survives
        self.assertEqual(paths["d/new.txt"]["layer"], 1)
        kinds = {d["path"]: d["kind"] for d in result["deletions"]}
        self.assertEqual(kinds, {
            "d/old1.txt": "opaque",
            "d/old2.txt": "opaque",
            "d/sub": "opaque",
            "d/sub/deep.txt": "opaque",
        })

    def test_opaque_marker_added_after_new_entries_still_preserves_them(self):
        result = apply_layers([
            [D("d"), F("d/old.txt")],
            [F("d/fresh.txt"), F("d/.wh..wh..opq")],
        ])
        self.assertEqual(sorted(paths_of(result)), ["d", "d/fresh.txt"])

    def test_opaque_at_root_clears_all_lower_layers(self):
        result = apply_layers([
            [F("a.txt"), D("d"), F("d/b.txt")],
            [F(".wh..wh..opq"), F("c.txt")],
        ])
        self.assertEqual(sorted(paths_of(result)), ["c.txt"])

    def test_rebuild_after_whiteout(self):
        result = apply_layers([
            [F("cfg.txt")],
            [F(".wh.cfg.txt")],
            [F("cfg.txt")],
        ])
        paths = paths_of(result)
        self.assertEqual(paths["cfg.txt"]["layer"], 2)
        self.assertEqual(len(result["deletions"]), 1)
        self.assertEqual(result["deletions"][0]["kind"], "whiteout")

    def test_file_replaces_dir_and_drops_descendants(self):
        result = apply_layers([
            [D("p"), F("p/child.txt")],
            [F("p")],
        ])
        paths = paths_of(result)
        self.assertEqual(paths["p"]["type"], "file")
        self.assertEqual(paths["p"]["layer"], 1)
        self.assertEqual(
            {d["path"] for d in result["deletions"]}, {"p", "p/child.txt"})
        self.assertTrue(all(d["kind"] == "replaced" for d in result["deletions"]))

    def test_dir_replaces_file(self):
        result = apply_layers([
            [F("p")],
            [D("p"), F("p/child.txt")],
        ])
        paths = paths_of(result)
        self.assertEqual(paths["p"]["type"], "dir")
        self.assertEqual(paths["p"]["layer"], 1)
        self.assertEqual(paths["p/child.txt"]["layer"], 1)
        self.assertEqual([d["path"] for d in result["deletions"]], ["p"])

    def test_dir_restatement_keeps_lower_source_layer(self):
        result = apply_layers([
            [D("d"), F("d/a.txt")],
            [D("d"), F("d/b.txt")],
        ])
        paths = paths_of(result)
        self.assertEqual(paths["d"]["layer"], 0)
        self.assertEqual(paths["d/b.txt"]["layer"], 1)
        self.assertEqual(result["deletions"], [])

    def test_file_superseded_by_later_file_records_evidence(self):
        result = apply_layers([[F("m.txt")], [F("m.txt")]])
        self.assertEqual(paths_of(result)["m.txt"]["layer"], 1)
        self.assertEqual(result["deletions"], [{
            "path": "m.txt", "layer": 0, "kind": "replaced",
            "byLayer": 1, "via": "m.txt",
        }])

    def test_hardlink_within_layer(self):
        result = apply_layers([[F("a.txt"), L("b.txt", "a.txt")]])
        paths = paths_of(result)
        self.assertEqual(paths["b.txt"]["type"], "file")
        self.assertEqual(paths["b.txt"]["link"], "a.txt")

    def test_hardlink_to_lower_layer_is_dangling(self):
        with self.assertRaises(EngineError):
            apply_layers([[F("a.txt")], [L("b.txt", "a.txt")]])

    def test_hardlink_to_missing_target_is_dangling(self):
        with self.assertRaises(EngineError):
            apply_layers([[L("b.txt", "missing.txt")]])

    def test_hardlink_to_directory_rejected(self):
        with self.assertRaises(EngineError):
            apply_layers([[D("dir"), L("b.txt", "dir")]])

    def test_hardlink_to_whiteout_deleted_file_is_dangling(self):
        with self.assertRaises(EngineError):
            apply_layers([[F("a.txt"), F(".wh.a.txt"), L("b.txt", "a.txt")]])

    def test_duplicate_entry_rejected(self):
        with self.assertRaises(EngineError):
            apply_layers([[F("a.txt"), F("a.txt")]])

    def test_delete_and_recreate_in_same_layer_is_duplicate(self):
        with self.assertRaises(EngineError):
            apply_layers([[F("a.txt"), F(".wh.a.txt"), F("a.txt")]])

    def test_parent_file_conflict_rejected(self):
        with self.assertRaises(EngineError):
            apply_layers([[F("a"), F("a/b.txt")]])

    def test_failed_layer_aborts_whole_audit(self):
        # Second layer is invalid; apply_layers must raise and hand back
        # nothing (the caller discards the private tree).
        with self.assertRaises(EngineError) as ctx:
            apply_layers([[F("ok.txt")], [F("x"), F("x/y.txt")]])
        self.assertIn("layer 1", str(ctx.exception))

    def test_implicit_parent_dirs_get_current_layer(self):
        result = apply_layers([[F("a/b/c.txt")]])
        paths = paths_of(result)
        self.assertEqual(paths["a"]["type"], "dir")
        self.assertEqual(paths["a"]["layer"], 0)
        self.assertEqual(paths["a/b"]["layer"], 0)


class HistoryTests(unittest.TestCase):
    """Per-path evolution records produced alongside the adjudication."""

    def test_create_whiteout_rebuild_is_continuous(self):
        result = apply_layers([
            [F("cfg.txt")],
            [F(".wh.cfg.txt")],
            [F("cfg.txt")],
        ])
        self.assertEqual(result["history"]["cfg.txt"], [
            {"action": "created", "layer": 0, "via": "cfg.txt",
             "fromType": None, "toType": "file"},
            {"action": "whiteout", "layer": 1, "via": ".wh.cfg.txt",
             "fromType": "file", "toType": None},
            {"action": "created", "layer": 2, "via": "cfg.txt",
             "fromType": None, "toType": "file"},
        ])
        # Final source layer agrees with the frozen path list.
        self.assertEqual(paths_of(result)["cfg.txt"]["layer"], 2)

    def test_file_superseded_records_single_replace_event(self):
        result = apply_layers([[F("m.txt")], [F("m.txt")]])
        self.assertEqual(result["history"]["m.txt"], [
            {"action": "created", "layer": 0, "via": "m.txt",
             "fromType": None, "toType": "file"},
            {"action": "replaced", "layer": 1, "via": "m.txt",
             "fromType": "file", "toType": "file"},
        ])

    def test_dir_replaced_by_file_explains_descendant_disappearance(self):
        result = apply_layers([[D("p"), F("p/child.txt")], [F("p")]])
        self.assertEqual(result["history"]["p"], [
            {"action": "created", "layer": 0, "via": "p",
             "fromType": None, "toType": "dir"},
            {"action": "replaced", "layer": 1, "via": "p",
             "fromType": "dir", "toType": "file"},
        ])
        # The descendant's log carries the ancestor action (via = "p").
        self.assertEqual(result["history"]["p/child.txt"], [
            {"action": "created", "layer": 0, "via": "p/child.txt",
             "fromType": None, "toType": "file"},
            {"action": "replaced", "layer": 1, "via": "p",
             "fromType": "file", "toType": None},
        ])

    def test_opaque_clearing_recorded_per_removed_child(self):
        result = apply_layers([
            [D("d"), F("d/old.txt")],
            [F("d/.wh..wh..opq"), F("d/new.txt")],
        ])
        self.assertEqual(result["history"]["d/old.txt"], [
            {"action": "created", "layer": 0, "via": "d/old.txt",
             "fromType": None, "toType": "file"},
            {"action": "opaque", "layer": 1, "via": "d/.wh..wh..opq",
             "fromType": "file", "toType": None},
        ])
        self.assertEqual(result["history"]["d/new.txt"], [
            {"action": "created", "layer": 1, "via": "d/new.txt",
             "fromType": None, "toType": "file"},
        ])
        # The opaque dir itself survives untouched: no extra events.
        self.assertEqual(result["history"]["d"], [
            {"action": "created", "layer": 0, "via": "d",
             "fromType": None, "toType": "dir"},
        ])

    def test_rebuild_under_whited_out_dir_keeps_history_continuous(self):
        result = apply_layers([
            [D("a"), D("a/b"), F("a/b/c.txt")],
            [F("a/.wh.b")],
            [F("a/b/c.txt")],
        ])
        self.assertEqual(result["history"]["a/b/c.txt"], [
            {"action": "created", "layer": 0, "via": "a/b/c.txt",
             "fromType": None, "toType": "file"},
            {"action": "whiteout", "layer": 1, "via": "a/.wh.b",
             "fromType": "file", "toType": None},
            {"action": "created", "layer": 2, "via": "a/b/c.txt",
             "fromType": None, "toType": "file"},
        ])
        # The ancestor dir was implicitly re-materialized by the rebuild.
        self.assertEqual(result["history"]["a/b"], [
            {"action": "created", "layer": 0, "via": "a/b",
             "fromType": None, "toType": "dir"},
            {"action": "whiteout", "layer": 1, "via": "a/.wh.b",
             "fromType": "dir", "toType": None},
            {"action": "created", "layer": 2, "via": "a/b/c.txt",
             "fromType": None, "toType": "dir"},
        ])
        self.assertEqual(paths_of(result)["a/b/c.txt"]["layer"], 2)

    def test_implicit_parent_dirs_record_creation_events(self):
        result = apply_layers([[F("a/b/c.txt")]])
        self.assertEqual(result["history"]["a"], [
            {"action": "created", "layer": 0, "via": "a/b/c.txt",
             "fromType": None, "toType": "dir"},
        ])
        self.assertEqual(result["history"]["a/b"], [
            {"action": "created", "layer": 0, "via": "a/b/c.txt",
             "fromType": None, "toType": "dir"},
        ])

    def test_dir_restatement_adds_no_events(self):
        result = apply_layers([[D("d"), F("d/a.txt")], [D("d"), F("d/b.txt")]])
        self.assertEqual(result["history"]["d"], [
            {"action": "created", "layer": 0, "via": "d",
             "fromType": None, "toType": "dir"},
        ])

    def test_hardlink_creation_keeps_link_target(self):
        result = apply_layers([[F("a.txt"), L("b.txt", "a.txt")]])
        self.assertEqual(result["history"]["b.txt"], [
            {"action": "created", "layer": 0, "via": "b.txt",
             "fromType": None, "toType": "file", "link": "a.txt"},
        ])

    def test_whiteout_no_op_records_nothing(self):
        result = apply_layers([[F("x.txt")], [F(".wh.never-existed")]])
        self.assertNotIn("never-existed", result["history"])
        self.assertNotIn(".wh.never-existed", result["history"])

    def test_failed_layer_leaves_history_unreachable(self):
        # apply_layers raises; the caller discards everything, history
        # included, so a rejected audit has no partial record at all.
        with self.assertRaises(EngineError):
            apply_layers([[F("ok.txt")], [F("x"), F("x/y.txt")]])


if __name__ == "__main__":
    unittest.main()
