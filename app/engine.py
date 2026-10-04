"""Union file tree with OCI whiteout (".wh.") semantics.

Layers are applied bottom-to-top onto a per-audit tree.  Any failure aborts
the whole audit: the tree is built privately and only handed back on full
success, so a failed layer can never leave a partial adjudication behind.

Rules implemented:

* ``.wh.<name>`` removes ``<name>`` (and its subtree) from lower layers;
  the whiteout entry itself never appears in the result.
* ``.wh..wh..opq`` marks the containing directory opaque: every descendant
  coming from lower layers is removed, while entries added by the current
  layer survive.
* A regular entry replaces a lower entry of a different type (file vs dir);
  replacing a directory drops its whole subtree.  Re-stating a directory
  keeps its original (lower) source layer.
* Hard links must resolve to a regular file that appeared earlier in the
  same layer and still exists in the tree (no dangling links).
* Duplicate canonical paths within one layer are rejected.

Besides the frozen path list and deletion evidence, the adjudication keeps
a per-path evolution history (``result["history"]``).  Every event records
the acting layer, the TAR entry that triggered the action and the node type
before/after it.  Actions:

* ``create``    -- the path appears in the union for the first time;
* ``recreate``  -- the path appears again after an earlier deletion;
* ``overwrite`` -- a regular entry supersedes the node (file over file, or
                   a file/dir type change); descendants of a replaced
                   directory inherit the event with ``afterType: null`` so
                   querying them explains the ancestor-driven disappearance;
* ``whiteout``  -- a ``.wh.<name>`` entry removes the node (and subtree);
* ``opaque``    -- an ``.wh..wh..opq`` marker clears a lower-layer node.
"""

from __future__ import annotations

from dataclasses import dataclass

from .tarparse import Entry, TYPE_DIR, TYPE_LINK

OPAQUE_MARKER = ".wh..wh..opq"
WHITEOUT_PREFIX = ".wh."

ACTION_CREATE = "create"
ACTION_RECREATE = "recreate"
ACTION_OVERWRITE = "overwrite"
ACTION_WHITEOUT = "whiteout"
ACTION_OPAQUE = "opaque"


class EngineError(ValueError):
    """Raised when a layer cannot be applied to the union tree."""


@dataclass
class Node:
    type: str  # "file" | "dir"
    layer: int  # source layer index (0 = bottom layer)
    link: str | None = None  # hard-link target, if created by a link entry


def _parent(path: str) -> str:
    idx = path.rfind("/")
    return path[:idx] if idx != -1 else ""


def _record(seen: set[str], history: list[dict], path: str, action: str,
            layer: int, via: str, before_type: str | None,
            after_type: str | None) -> None:
    """Append one evolution event and remember the path as tracked."""
    history.append({
        "path": path,
        "action": action,
        "layer": layer,
        "via": via,
        "beforeType": before_type,
        "afterType": after_type,
    })
    seen.add(path)


def _ensure_dir(tree: dict[str, Node], path: str, layer: int, via: str,
                seen: set[str], history: list[dict]) -> None:
    """Materialize ``path`` (and missing ancestors) as directories."""
    if not path:
        return
    parts = path.split("/")
    for k in range(1, len(parts) + 1):
        prefix = "/".join(parts[:k])
        node = tree.get(prefix)
        if node is None:
            tree[prefix] = Node("dir", layer)
            _record(seen, history, prefix, ACTION_CREATE, layer, via,
                    None, "dir")
        elif node.type != "dir":
            raise EngineError(f"parent {prefix!r} is not a directory")


def _drop_subtree(tree: dict[str, Node], root: str, kind: str, action: str,
                  by_layer: int, via: str, deletions: list[dict],
                  seen: set[str], history: list[dict]) -> None:
    """Remove ``root`` and its descendants, recording evidence + history."""
    victims = sorted(p for p in tree if p == root or p.startswith(root + "/"))
    for path in victims:
        node = tree.pop(path)
        deletions.append({
            "path": path,
            "layer": node.layer,
            "kind": kind,
            "byLayer": by_layer,
            "via": via,
        })
        _record(seen, history, path, action, by_layer, via, node.type, None)


def _apply_one(tree: dict[str, Node], deletions: list[dict],
               seen: set[str], history: list[dict],
               index: int, entries: list[Entry]) -> None:
    layer_seen: set[str] = set()
    linkables: set[str] = set()  # file/link entries earlier in this layer
    for entry in entries:
        if entry.path in layer_seen:
            raise EngineError(f"duplicate entry {entry.path!r} in layer")
        layer_seen.add(entry.path)
        base = entry.path.rsplit("/", 1)[-1]
        parent = _parent(entry.path)

        if base == OPAQUE_MARKER:
            _ensure_dir(tree, parent, index, entry.path, seen, history)
            prefix = parent + "/" if parent else ""
            for path in sorted(list(tree)):
                node = tree[path]
                if path != parent and path.startswith(prefix) and node.layer < index:
                    del tree[path]
                    deletions.append({
                        "path": path,
                        "layer": node.layer,
                        "kind": "opaque",
                        "byLayer": index,
                        "via": entry.path,
                    })
                    _record(seen, history, path, ACTION_OPAQUE, index,
                            entry.path, node.type, None)
            continue

        if base.startswith(WHITEOUT_PREFIX):
            name = base[len(WHITEOUT_PREFIX):]
            if not name:
                raise EngineError(f"invalid whiteout entry {entry.path!r}")
            _ensure_dir(tree, parent, index, entry.path, seen, history)
            target = parent + "/" + name if parent else name
            # Deleting a path absent from the union is a tolerated no-op.
            _drop_subtree(tree, target, "whiteout", ACTION_WHITEOUT, index,
                          entry.path, deletions, seen, history)
            continue

        _ensure_dir(tree, parent, index, entry.path, seen, history)
        ntype = "dir" if entry.type == TYPE_DIR else "file"
        existing = tree.get(entry.path)
        replaced = False
        if existing is not None and not (existing.type == "dir" and ntype == "dir"):
            # File/dir replacement (either direction) or file superseded:
            # the lower content is removed and recorded as evidence.  The
            # root gets one overwrite event carrying its new type; removed
            # descendants inherit the ancestor action with afterType=null.
            victims = sorted(
                p for p in tree
                if p == entry.path or p.startswith(entry.path + "/"))
            for path in victims:
                node = tree.pop(path)
                deletions.append({
                    "path": path,
                    "layer": node.layer,
                    "kind": "replaced",
                    "byLayer": index,
                    "via": entry.path,
                })
                after_type = ntype if path == entry.path else None
                _record(seen, history, path, ACTION_OVERWRITE, index,
                        entry.path, node.type, after_type)
            existing = None
            replaced = True
        if existing is None:
            tree[entry.path] = Node(
                ntype, index, entry.link if entry.type == TYPE_LINK else None)
            if not replaced:
                # An overwrite event already covers the replacement itself;
                # otherwise the node is born here (first time or a rebuild
                # after a prior whiteout/opaque/ancestor replacement).
                if entry.path in seen:
                    _record(seen, history, entry.path, ACTION_RECREATE, index,
                            entry.path, None, ntype)
                else:
                    _record(seen, history, entry.path, ACTION_CREATE, index,
                            entry.path, None, ntype)

        if entry.type == TYPE_LINK:
            if entry.link not in linkables:
                raise EngineError(
                    f"hard link {entry.path!r} target {entry.link!r} "
                    "not present earlier in the same layer")
            target = tree.get(entry.link)
            if target is None or target.type != "file":
                raise EngineError(
                    f"hard link {entry.path!r} has dangling target {entry.link!r}")
        if ntype == "file":
            linkables.add(entry.path)


def apply_layers(layers: list[list[Entry]]) -> dict:
    """Apply validated layers bottom-to-top; return the frozen adjudication."""
    tree: dict[str, Node] = {}
    deletions: list[dict] = []
    history: list[dict] = []
    seen: set[str] = set()
    for index, entries in enumerate(layers):
        try:
            _apply_one(tree, deletions, seen, history, index, entries)
        except EngineError as exc:
            raise EngineError(f"layer {index}: {exc}") from exc
    paths = []
    for path in sorted(tree):
        node = tree[path]
        item = {"path": path, "type": node.type, "layer": node.layer}
        if node.link is not None:
            item["link"] = node.link
        paths.append(item)
    deletions.sort(key=lambda d: (d["byLayer"], d["path"]))
    return {"paths": paths, "deletions": deletions, "history": history}


def history_for(result: dict, path: str) -> dict | None:
    """Extract one canonical path's ordered evolution from a frozen result.

    Returns ``None`` when the path never appeared in any layer (untracked).
    Otherwise ``status`` is ``"present"`` (with the final node) or
    ``"deleted"`` (the path vanished and was never recreated).  Events stay
    in layer/application order; each carries ``layer`` (acting layer),
    ``via`` (triggering entry), ``beforeType`` and ``afterType``.
    """
    events = [
        {
            "action": e["action"],
            "layer": e["layer"],
            "via": e["via"],
            "beforeType": e["beforeType"],
            "afterType": e["afterType"],
        }
        for e in result["history"] if e["path"] == path
    ]
    if not events:
        return None
    final = next((p for p in result["paths"] if p["path"] == path), None)
    final_node = None
    if final is not None:
        final_node = {"type": final["type"], "layer": final["layer"]}
        if final.get("link") is not None:
            final_node["link"] = final["link"]
    return {
        "path": path,
        "status": "present" if final is not None else "deleted",
        "final": final_node,
        "history": events,
    }
