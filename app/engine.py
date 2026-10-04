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

Besides the frozen path list and the deletion evidence, the engine records
a per-path evolution log (``history``): every action that touches a path —
creation, replacement, whiteout deletion, opaque clearing, re-creation —
is appended in layer order with the acting layer, the triggering entry and
the path's type before/after the action.  When a directory is replaced or
whited-out, each removed descendant gets its own event whose ``via`` names
the ancestor-level entry that explains the disappearance, so the history of
any path is self-contained and continuous across re-creation.
"""

from __future__ import annotations

from dataclasses import dataclass

from .tarparse import Entry, TYPE_DIR, TYPE_LINK

OPAQUE_MARKER = ".wh..wh..opq"
WHITEOUT_PREFIX = ".wh."


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


def _record(history: dict[str, list[dict]], path: str, action: str,
            layer: int, via: str, from_type: str | None,
            to_type: str | None, link: str | None = None) -> None:
    """Append one evolution event to ``path``'s history log."""
    event = {
        "action": action,      # created | replaced | whiteout | opaque
        "layer": layer,        # layer that performed the action
        "via": via,            # entry path that triggered the action
        "fromType": from_type, # type before the action (None = absent)
        "toType": to_type,     # type after the action (None = removed)
    }
    if link is not None:
        event["link"] = link
    history.setdefault(path, []).append(event)


def _ensure_dir(tree: dict[str, Node], path: str, layer: int, via: str,
                history: dict[str, list[dict]]) -> None:
    """Materialize ``path`` (and missing ancestors) as directories."""
    if not path:
        return
    parts = path.split("/")
    for k in range(1, len(parts) + 1):
        prefix = "/".join(parts[:k])
        node = tree.get(prefix)
        if node is None:
            tree[prefix] = Node("dir", layer)
            _record(history, prefix, "created", layer, via, None, "dir")
        elif node.type != "dir":
            raise EngineError(f"parent {prefix!r} is not a directory")


def _drop_subtree(tree: dict[str, Node], root: str, kind: str,
                  by_layer: int, via: str, deletions: list[dict],
                  history: dict[str, list[dict]],
                  root_to_type: str | None = None) -> None:
    """Remove ``root`` and its descendants, recording deletion evidence.

    Every removed path also gets a history event.  When the action replaces
    ``root`` with a new entry (``root_to_type`` set), the root's event keeps
    the type it becomes; descendants always end up absent (``toType`` None).
    """
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
        _record(history, path, kind, by_layer, via, node.type,
                root_to_type if path == root else None)


def _apply_one(tree: dict[str, Node], deletions: list[dict],
               history: dict[str, list[dict]],
               index: int, entries: list[Entry]) -> None:
    seen: set[str] = set()
    linkables: set[str] = set()  # file/link entries earlier in this layer
    for entry in entries:
        if entry.path in seen:
            raise EngineError(f"duplicate entry {entry.path!r} in layer")
        seen.add(entry.path)
        base = entry.path.rsplit("/", 1)[-1]
        parent = _parent(entry.path)

        if base == OPAQUE_MARKER:
            _ensure_dir(tree, parent, index, entry.path, history)
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
                    _record(history, path, "opaque", index, entry.path,
                            node.type, None)
            continue

        if base.startswith(WHITEOUT_PREFIX):
            name = base[len(WHITEOUT_PREFIX):]
            if not name:
                raise EngineError(f"invalid whiteout entry {entry.path!r}")
            _ensure_dir(tree, parent, index, entry.path, history)
            target = parent + "/" + name if parent else name
            # Deleting a path absent from the union is a tolerated no-op.
            _drop_subtree(tree, target, "whiteout", index, entry.path,
                          deletions, history)
            continue

        _ensure_dir(tree, parent, index, entry.path, history)
        ntype = "dir" if entry.type == TYPE_DIR else "file"
        existing = tree.get(entry.path)
        replaced = False
        if existing is not None and not (existing.type == "dir" and ntype == "dir"):
            # File/dir replacement (either direction) or file superseded:
            # the lower content is removed and recorded as evidence.
            _drop_subtree(tree, entry.path, "replaced", index, entry.path,
                          deletions, history, root_to_type=ntype)
            existing = None
            replaced = True
        if existing is None:
            tree[entry.path] = Node(
                ntype, index, entry.link if entry.type == TYPE_LINK else None)
            if not replaced:
                _record(history, entry.path, "created", index, entry.path,
                        None, ntype,
                        entry.link if entry.type == TYPE_LINK else None)

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
    """Apply validated layers bottom-to-top; return the frozen adjudication.

    The returned dict carries the final ``paths`` list, the ``deletions``
    evidence and the per-path evolution ``history`` (path -> events in
    layer order).  The history is derived from the same adjudication, so a
    present path's last event always agrees with its ``paths[]`` entry.
    """
    tree: dict[str, Node] = {}
    deletions: list[dict] = []
    history: dict[str, list[dict]] = {}
    for index, entries in enumerate(layers):
        try:
            _apply_one(tree, deletions, history, index, entries)
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
