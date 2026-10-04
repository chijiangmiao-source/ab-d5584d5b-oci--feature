"""Whiteout-rule tests for the union engine."""

import unittest

from app.engine import EngineError, apply_layers, history_for
from app.tarparse import TYPE_DIR, TYPE_FILE, TYPE_LINK, Entry


def F(path):
    return Entry(path, TYPE_FILE, 1)


def D(path):
    return Entry(path, TYPE_DIR)


def L(path, target):
    return Entry(path, TYPE_LINK, 0, target)


def W(path):
    """Whiteout/opaque marker entry (a regular file by TAR type)."""
    return Entry(path, TYPE_FILE, 0)


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


EVENT_KEYS = {"action", "layer", "via", "beforeType", "afterType"}


def actions(record):
    return [(e["action"], e["layer"], e["via"],
             e["beforeType"], e["afterType"]) for e in record["history"]]


class HistoryTests(unittest.TestCase):
    def test_create_event_for_files_and_implicit_dirs(self):
        result = apply_layers([[F("a/b.txt")]])
        record = history_for(result, "a")
        self.assertEqual(record["status"], "present")
        self.assertEqual(record["final"], {"type": "dir", "layer": 0})
        self.assertEqual(actions(record), [
            ("create", 0, "a/b.txt", None, "dir"),
        ])

    def test_overwrite_file_records_before_and_after_types(self):
        result = apply_layers([[F("m.txt")], [F("m.txt")]])
        record = history_for(result, "m.txt")
        self.assertEqual(actions(record), [
            ("create", 0, "m.txt", None, "file"),
            ("overwrite", 1, "m.txt", "file", "file"),
        ])
        self.assertEqual(record["final"]["layer"], 1)

    def test_whiteout_then_recreate_is_continuous(self):
        result = apply_layers([
            [F("cfg.txt")],
            [F(".wh.cfg.txt")],
            [F("cfg.txt")],
        ])
        record = history_for(result, "cfg.txt")
        self.assertEqual([e[0] for e in actions(record)],
                         ["create", "whiteout", "recreate"])
        whiteout = record["history"][1]
        self.assertEqual(whiteout["beforeType"], "file")
        self.assertEqual(whiteout["afterType"], None)
        self.assertEqual(whiteout["via"], ".wh.cfg.txt")
        self.assertEqual(whiteout["layer"], 1)
        self.assertEqual(record["status"], "present")
        self.assertEqual(record["final"]["layer"], 2)

    def test_opaque_clear_then_recreate(self):
        result = apply_layers([
            [D("d"), F("d/x.txt")],
            [F("d/.wh..wh..opq")],
            [F("d/x.txt")],
        ])
        record = history_for(result, "d/x.txt")
        self.assertEqual([e[0] for e in actions(record)],
                         ["create", "opaque", "recreate"])
        self.assertEqual(record["history"][1]["via"], "d/.wh..wh..opq")
        self.assertEqual(record["final"]["layer"], 2)

    def test_descendant_sees_ancestor_whiteout(self):
        result = apply_layers([
            [D("a"), D("a/b"), F("a/b/c.txt")],
            [F("a/.wh.b")],
        ])
        record = history_for(result, "a/b/c.txt")
        self.assertEqual(record["status"], "deleted")
        self.assertIsNone(record["final"])
        self.assertEqual([e[0] for e in actions(record)],
                         ["create", "whiteout"])
        event = record["history"][1]
        self.assertEqual(event["via"], "a/.wh.b")
        self.assertEqual(event["beforeType"], "file")
        self.assertIsNone(event["afterType"])

    def test_descendant_sees_ancestor_dir_replacement_then_rebuild(self):
        result = apply_layers([
            [D("p"), D("p/c"), F("p/c/child.txt")],
            [F("p")],
            [W(".wh.p")],
            [D("p"), D("p/c"), F("p/c/child.txt")],
        ])
        record = history_for(result, "p/c/child.txt")
        self.assertEqual([e[0] for e in actions(record)],
                         ["create", "overwrite", "recreate"])
        replace = record["history"][1]
        self.assertEqual(replace["via"], "p")
        self.assertIsNone(replace["afterType"])
        # Rebuilt history ends at the same source layer as the frozen verdict.
        final = next(p for p in result["paths"]
                     if p["path"] == "p/c/child.txt")
        self.assertEqual(record["final"]["layer"], final["layer"])
        self.assertEqual(record["final"]["layer"], 3)

    def test_dir_replaced_by_file_then_back_to_dir(self):
        result = apply_layers([
            [D("p"), F("p/a.txt")],
            [F("p")],
            [F(".wh.p")],
            [D("p"), F("p/b.txt")],
        ])
        record = history_for(result, "p")
        self.assertEqual([e[0] for e in actions(record)],
                         ["create", "overwrite", "whiteout", "recreate"])
        self.assertEqual(
            [e[4] for e in actions(record)], ["dir", "file", None, "dir"])
        self.assertEqual(record["final"], {"type": "dir", "layer": 3})

    def test_deleted_but_never_rebuilt_is_deleted(self):
        result = apply_layers([[F("gone.txt")], [F(".wh.gone.txt")]])
        record = history_for(result, "gone.txt")
        self.assertEqual(record["status"], "deleted")
        self.assertIsNone(record["final"])

    def test_untracked_legal_path_returns_none(self):
        result = apply_layers([[F("a.txt")]])
        self.assertIsNone(history_for(result, "never/mentioned.txt"))

    def test_events_carry_only_evolution_fields(self):
        result = apply_layers([[F("a.txt")], [F(".wh.a.txt")]])
        record = history_for(result, "a.txt")
        for event in record["history"]:
            self.assertEqual(set(event), EVENT_KEYS)

    def test_hardlink_history_keeps_final_link(self):
        result = apply_layers([
            [F("a.txt"), L("b.txt", "a.txt")],
        ])
        record = history_for(result, "b.txt")
        self.assertEqual(record["final"],
                         {"type": "file", "layer": 0, "link": "a.txt"})


if __name__ == "__main__":
    unittest.main()
