#!/usr/bin/env python3
"""
tdtool.py - helper for OWASP Threat Dragon v2 threat models.

Pure Python standard library (3.8+), no install needed, so any coding agent
(Claude Code, OpenCode, Cline, Codex, Cursor, ...) or a CI job can run it.

Commands
  build    SPEC OUT [--force]    Build a NEW Threat Dragon model from a draft spec (JSON).
                                 Refuses to overwrite an existing model (ids must stay pinned);
                                 use extend to add to a model.
  extend   MODEL DELTA [-o OUT]  Add elements/flows/threats from a delta spec to an existing
                                 model without touching anything a human already edited.
  validate MODEL [--fix]         Check structure, enums, references; --fix repairs derived
                                 fields (hasOpenThreats, styles, threat numbers, threatTop).
  extract  MODEL [--format json|md] [--status Open,Mitigated,...]
                                 Flatten the model: elements, flows and threats with T-ids.
  set-status MODEL --threat T-12 --status Mitigated [--note TEXT]
                                 Change one threat's status (and append a dated note).
  diff     NEW [OLD] [--base GITREF] [--format md|json] [--strict]
                                 Compare two versions of a model by pinned threat id (T-nnn): added,
                                 removed, status/severity changes, and identity violations (an id that
                                 was reused for a different threat, threatTop that went down).
                                 Exit 1 on violations; use it in CI to protect the model's stable ids.
  stats    MODEL [--draft-log FILE]
                                 Counts by status/severity and, with a draft log, how many
                                 AI-drafted threats were kept / rejected / added by humans.

Spec format: see references/spec-format.md in the threat-model-draft skill.
"""
import argparse
import copy
import datetime
import json
import os
import sys
import uuid

TD_VERSION = "2.6.2"

STRIDE = ["Spoofing", "Tampering", "Repudiation", "Information disclosure",
          "Denial of service", "Elevation of privilege"]
STRIDE_PER_ELEMENT = {
    "tm.Actor": {"Spoofing", "Repudiation"},
    "tm.Store": {"Tampering", "Repudiation", "Information disclosure", "Denial of service"},
    "tm.Process": set(STRIDE),
    "tm.Flow": {"Tampering", "Information disclosure", "Denial of service"},
}
CATEGORY_ALIASES = {
    "s": "Spoofing", "spoofing": "Spoofing",
    "t": "Tampering", "tampering": "Tampering",
    "r": "Repudiation", "repudiation": "Repudiation",
    "i": "Information disclosure", "informationdisclosure": "Information disclosure",
    "disclosure": "Information disclosure",
    "d": "Denial of service", "denialofservice": "Denial of service", "dos": "Denial of service",
    "e": "Elevation of privilege", "elevationofprivilege": "Elevation of privilege",
    "eop": "Elevation of privilege", "privilegeescalation": "Elevation of privilege",
}
SEVERITIES = ["TBD", "Low", "Medium", "High", "Critical"]
STATUSES = ["NotApplicable", "Open", "Mitigated", "Accepted", "Transferred", "Avoided", "Eliminated"]
STATUS_ALIASES = {s.lower(): s for s in STATUSES}
STATUS_ALIASES.update({"n/a": "NotApplicable", "na": "NotApplicable", "notapplicable": "NotApplicable",
                       "not applicable": "NotApplicable"})

SHAPE_OF = {"tm.Actor": "actor", "tm.Process": "process", "tm.Store": "store", "tm.Flow": "flow",
            "tm.BoundaryBox": "trust-boundary-box", "tm.Boundary": "trust-boundary-curve",
            "tm.Text": "td-text-block"}
SPEC_TYPE = {"actor": "tm.Actor", "external": "tm.Actor", "externalentity": "tm.Actor", "user": "tm.Actor",
             "process": "tm.Process", "service": "tm.Process", "component": "tm.Process",
             "store": "tm.Store", "datastore": "tm.Store", "database": "tm.Store"}
SIZE = {"tm.Actor": (150, 80), "tm.Process": (100, 100), "tm.Store": (150, 75)}

DEFAULT_COLOR, OPEN_COLOR = "#333333", "red"
DEFAULT_WIDTH, OPEN_WIDTH = 1.5, 2.5
OUT_OF_SCOPE_DASH = "4 3"

# Optional element properties understood by Threat Dragon, per element type
PROPS = {
    "tm.Actor": {"providesAuthentication": False},
    "tm.Process": {"handlesCardPayment": False, "handlesGoodsOrServices": False,
                   "isWebApplication": False, "privilegeLevel": ""},
    "tm.Store": {"isALog": False, "isEncrypted": False, "isSigned": False,
                 "storesCredentials": False, "storesInventory": False},
}

# Layout constants
MARGIN_X, TOP_Y = 40, 150
COL_GAP, ROW_GAP, BOX_PAD, BOX_HEADER = 80, 70, 40, 50


class ToolError(Exception):
    pass


# ---------------------------------------------------------------- helpers
def uid():
    return str(uuid.uuid4())


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise ToolError("File not found: %s" % path)
    except json.JSONDecodeError as e:
        raise ToolError("Invalid JSON in %s: %s" % (path, e))


def save_json(path, data):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def norm_key(s):
    return "".join(ch for ch in str(s).lower() if ch.isalnum())


def norm_category(c):
    if c in STRIDE:
        return c
    k = norm_key(c)
    if k in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[k]
    raise ToolError("Unknown STRIDE category '%s' (use one of: %s)" % (c, ", ".join(STRIDE)))


def norm_severity(s):
    if not s:
        return "TBD"
    for v in SEVERITIES:
        if v.lower() == str(s).lower():
            return v
    raise ToolError("Unknown severity '%s' (use one of: %s)" % (s, ", ".join(SEVERITIES)))


def norm_status(s):
    if not s:
        return "Open"
    k = str(s).strip().lower()
    if k in STATUS_ALIASES:
        return STATUS_ALIASES[k]
    if norm_key(s) in STATUS_ALIASES:
        return STATUS_ALIASES[norm_key(s)]
    raise ToolError("Unknown status '%s' (use one of: %s)" % (s, ", ".join(STATUSES)))


def ports():
    groups = {}
    for pos in ("top", "right", "bottom", "left"):
        groups[pos] = {"position": pos, "attrs": {"circle": {
            "r": 4, "magnet": True, "stroke": "#5F95FF", "strokeWidth": 1, "fill": "#fff",
            "style": {"visibility": "hidden"}}}}
    return {"groups": groups, "items": [{"group": g, "id": uid()} for g in ("top", "right", "bottom", "left")]}


def cell_name(cell):
    data = cell.get("data") or {}
    if data.get("name"):
        return str(data["name"])
    attrs = cell.get("attrs") or {}
    for key in ("text", "label"):
        v = attrs.get(key)
        if isinstance(v, dict) and v.get("text"):
            return str(v["text"])
    for lab in cell.get("labels") or []:
        t = ((lab.get("attrs") or {}).get("labelText") or {}).get("text")
        if t:
            return str(t)
    return ""


def name_key(s):
    return " ".join(str(s).replace("\n", " ").split()).lower()


# ---------------------------------------------------------------- cell factories
def make_node(td_type, name, description="", props=None, out_of_scope=False, reason=""):
    w, h = SIZE[td_type]
    data = {"type": td_type, "name": name, "description": description or "",
            "outOfScope": bool(out_of_scope), "reasonOutOfScope": reason or "",
            "isTrustBoundary": False, "hasOpenThreats": False, "threats": []}
    defaults = copy.deepcopy(PROPS[td_type])
    for k, v in (props or {}).items():
        if k in defaults:
            defaults[k] = v
        else:
            raise ToolError("Unknown property '%s' for %s (allowed: %s)"
                            % (k, td_type, ", ".join(PROPS[td_type]) or "none"))
    data.update(defaults)
    cell = {"position": {"x": 0, "y": 0}, "size": {"width": w, "height": h}, "visible": True,
            "shape": SHAPE_OF[td_type], "zIndex": 1, "id": uid(), "ports": ports(), "data": data}
    if td_type == "tm.Store":
        cell["attrs"] = {"text": {"text": name},
                         "topLine": {"stroke": DEFAULT_COLOR, "strokeWidth": DEFAULT_WIDTH, "strokeDasharray": None},
                         "bottomLine": {"stroke": DEFAULT_COLOR, "strokeWidth": DEFAULT_WIDTH, "strokeDasharray": None}}
    else:
        cell["attrs"] = {"text": {"text": name},
                         "body": {"stroke": DEFAULT_COLOR, "strokeWidth": DEFAULT_WIDTH, "strokeDasharray": None}}
    return cell


def make_box(name, description=""):
    return {"position": {"x": 0, "y": 0}, "size": {"width": 200, "height": 200},
            "attrs": {"label": {"text": name}}, "visible": True, "shape": "trust-boundary-box",
            "id": uid(), "zIndex": -1,
            "data": {"type": "tm.BoundaryBox", "name": name, "description": description or "",
                     "isTrustBoundary": True, "hasOpenThreats": False}}


def make_text(text, x, y):
    return {"position": {"x": x, "y": y}, "size": {"width": 340, "height": 60},
            "attrs": {"text": {"text": text}}, "visible": True, "shape": "td-text-block",
            "zIndex": 2, "id": uid(), "data": {"type": "tm.Text", "name": text, "hasOpenThreats": False}}


def make_flow(src_id, dst_id, f):
    name = f.get("name", "")
    bidir = bool(f.get("bidirectional", False))
    return {
        "shape": "flow",
        "attrs": {"line": {"stroke": DEFAULT_COLOR, "strokeWidth": DEFAULT_WIDTH,
                           "targetMarker": {"name": "block"},
                           "sourceMarker": {"name": "block" if bidir else ""},
                           "strokeDasharray": None}},
        "width": 200, "height": 100, "zIndex": 10,
        "labels": [{"markup": [{"tagName": "ellipse", "selector": "labelBody"},
                               {"tagName": "text", "selector": "labelText"}],
                    "attrs": {"labelText": {"text": name, "textAnchor": "middle", "textVerticalAnchor": "middle"},
                              "labelBody": {"ref": "labelText", "refRx": "50%", "refRy": "60%",
                                            "fill": "#fff", "strokeWidth": 0}},
                    "position": {"distance": 0.5, "args": {"keepGradient": True, "ensureLegibility": True}}}],
        "connector": "smooth",
        "data": {"type": "tm.Flow", "name": name, "description": f.get("description", ""),
                 "outOfScope": bool(f.get("outOfScope", False)), "reasonOutOfScope": f.get("reasonOutOfScope", ""),
                 "isTrustBoundary": False, "hasOpenThreats": False, "isBidirectional": bidir,
                 "isEncrypted": bool(f.get("encrypted", False)), "isPublicNetwork": bool(f.get("publicNetwork", False)),
                 "protocol": f.get("protocol", ""), "threats": []},
        "id": uid(),
        "source": {"cell": src_id},
        "target": {"cell": dst_id},
        "vertices": [],
    }


def make_threat(t, number):
    return {"id": uid(), "title": str(t["title"]).strip(), "status": norm_status(t.get("status", "Open")),
            "severity": norm_severity(t.get("severity")), "type": norm_category(t["category"]),
            "description": str(t.get("description", "")).strip(), "mitigation": str(t.get("mitigation", "")).strip(),
            "modelType": "STRIDE", "new": False, "number": number, "score": str(t.get("score", "") or "")}


# ---------------------------------------------------------------- style / derived fields
def refresh_cell(cell):
    data = cell.get("data")
    if not isinstance(data, dict):
        return
    if "threats" in data:
        data["hasOpenThreats"] = any(str(t.get("status", "")).lower() == "open" for t in data.get("threats") or [])
    elif "hasOpenThreats" not in data:
        data["hasOpenThreats"] = False
    if data.get("type") in ("tm.BoundaryBox", "tm.Boundary", "tm.Text"):
        return
    color = OPEN_COLOR if data.get("hasOpenThreats") else DEFAULT_COLOR
    width = OPEN_WIDTH if data.get("hasOpenThreats") else DEFAULT_WIDTH
    dash = OUT_OF_SCOPE_DASH if data.get("outOfScope") else None
    attrs = cell.setdefault("attrs", {})
    if data["type"] == "tm.Flow":
        line = attrs.setdefault("line", {})
        line.update({"stroke": color, "strokeWidth": width, "strokeDasharray": dash})
        line.setdefault("targetMarker", {"name": "block"})
        line["sourceMarker"] = {"name": "block" if data.get("isBidirectional") else ""}
    elif data["type"] == "tm.Store":
        for k in ("topLine", "bottomLine"):
            attrs.setdefault(k, {}).update({"stroke": color, "strokeWidth": width, "strokeDasharray": dash})
    else:
        attrs.setdefault("body", {}).update({"stroke": color, "strokeWidth": width, "strokeDasharray": dash})


def all_cells(model):
    for d in model.get("detail", {}).get("diagrams", []):
        for c in d.get("cells", []):
            yield d, c


def all_threats(model):
    for d, c in all_cells(model):
        for t in (c.get("data") or {}).get("threats") or []:
            yield d, c, t


def refresh_model(model):
    """Recompute derived fields; give numbers to un-numbered threats; fix threatTop."""
    detail = model.setdefault("detail", {})
    top = 0
    for _, _, t in all_threats(model):
        n = t.get("number")
        if isinstance(n, int) and n > top:
            top = n
    seen = set()
    for _, _, t in all_threats(model):
        n = t.get("number")
        if not isinstance(n, int) or n in seen:
            top += 1
            t["number"] = top
        seen.add(t["number"])
    detail["threatTop"] = max(top, detail.get("threatTop") or 0)
    detail["diagramTop"] = len(detail.get("diagrams", []))
    for _, c in all_cells(model):
        refresh_cell(c)
    return model


# ---------------------------------------------------------------- geometry
def bbox(cell):
    p, s = cell.get("position") or {}, cell.get("size") or {}
    return p.get("x", 0), p.get("y", 0), s.get("width", 0), s.get("height", 0)


def inside(cell, box):
    x, y, w, h = bbox(cell)
    bx, by, bw, bh = bbox(box)
    cx, cy = x + w / 2.0, y + h / 2.0
    return bx <= cx <= bx + bw and by <= cy <= by + bh


def boundary_of(cell, boxes):
    hits = [b for b in boxes if inside(cell, b)]
    if not hits:
        return ""
    hits.sort(key=lambda b: bbox(b)[2] * bbox(b)[3])  # innermost (smallest) box wins
    return cell_name(hits[0])


def layout_columns(columns, start_x, top_y, cells):
    """columns: list of (box_cell_or_None, [node cells]). Places nodes and sizes boxes."""
    x = start_x
    for box, nodes in columns:
        if not nodes and box is None:
            continue
        width = max([n["size"]["width"] for n in nodes] + [160])
        inner_x = x + (BOX_PAD if box else 0)
        y = top_y + (BOX_HEADER if box else 0)
        for n in nodes:
            n["position"] = {"x": inner_x + (width - n["size"]["width"]) / 2.0, "y": y}
            y += n["size"]["height"] + ROW_GAP
            cells.append(n)
        col_w = width + (2 * BOX_PAD if box else 0)
        if box:
            box["position"] = {"x": x, "y": top_y}
            box["size"] = {"width": col_w, "height": max(y - ROW_GAP + BOX_PAD - top_y, 160)}
            cells.append(box)
        x += col_w + COL_GAP
    return x


# ---------------------------------------------------------------- spec handling
def check_spec(spec, partial=False):
    if not isinstance(spec, dict):
        raise ToolError("Spec must be a JSON object")
    if not partial and not spec.get("title"):
        raise ToolError("Spec needs a 'title'")
    ids = set()
    for key in ("boundaries", "elements", "flows"):
        for item in spec.get(key, []) or []:
            i = item.get("id")
            if not i:
                raise ToolError("Every item in '%s' needs an 'id': %s" % (key, json.dumps(item)[:120]))
            if i in ids:
                raise ToolError("Duplicate id '%s' in spec" % i)
            ids.add(i)
    for e in spec.get("elements", []) or []:
        if norm_key(e.get("type", "")) not in SPEC_TYPE:
            raise ToolError("Element '%s' has unknown type '%s' (use actor, process or store)" % (e["id"], e.get("type")))
        if not e.get("name"):
            raise ToolError("Element '%s' needs a 'name'" % e["id"])
    for t in spec.get("threats", []) or []:
        for k in ("target", "category", "title"):
            if not t.get(k):
                raise ToolError("Threat needs '%s': %s" % (k, json.dumps(t, ensure_ascii=False)[:160]))


def stride_warnings(td_type, category, label):
    allowed = STRIDE_PER_ELEMENT.get(td_type)
    if allowed and category not in allowed:
        return ["note: '%s' is %s on a %s - outside the classic STRIDE-per-element table; "
                "keep it only if it is a real threat" % (label, category, td_type.replace("tm.", ""))]
    return []


def cmd_build(args):
    if os.path.exists(args.out) and not args.force:
        raise ToolError("%s already exists. Rebuilding would renumber threats and discard reviewer edits; "
                        "use 'extend' to add to it, or pass --force to overwrite deliberately." % args.out)
    spec = load_json(args.spec)
    check_spec(spec)
    cells, warnings = [], []
    title = spec["title"]
    cells.append(make_text(title + ("\n" + spec["diagram"] if spec.get("diagram") else ""), MARGIN_X, 20))

    boxes, idmap, kinds = {}, {}, {}
    for b in spec.get("boundaries", []) or []:
        boxes[b["id"]] = make_box(b.get("name") or b["id"], b.get("description", ""))
    columns = {None: []}
    for bid in boxes:
        columns[bid] = []
    for e in spec.get("elements", []) or []:
        td_type = SPEC_TYPE[norm_key(e["type"])]
        node = make_node(td_type, e["name"], e.get("description", ""), e.get("props"),
                         e.get("outOfScope", False), e.get("reasonOutOfScope", ""))
        idmap[e["id"]], kinds[e["id"]] = node, td_type
        b = e.get("boundary")
        if b and b not in boxes:
            raise ToolError("Element '%s' refers to unknown boundary '%s'" % (e["id"], b))
        columns[b if b else None].append(node)
    order = [(None, columns[None])] + [(boxes[b], columns[b]) for b in boxes]
    layout_columns(order, MARGIN_X, TOP_Y, cells)

    for f in spec.get("flows", []) or []:
        for end in ("from", "to"):
            if f.get(end) not in idmap:
                raise ToolError("Flow '%s' %s '%s' is not an element id" % (f["id"], end, f.get(end)))
        flow = make_flow(idmap[f["from"]]["id"], idmap[f["to"]]["id"], f)
        idmap[f["id"]], kinds[f["id"]] = flow, "tm.Flow"
        cells.append(flow)

    number, log = 0, []
    for t in spec.get("threats", []) or []:
        target = idmap.get(t["target"])
        if target is None or kinds.get(t["target"]) is None:
            raise ToolError("Threat '%s' targets unknown element/flow id '%s'" % (t["title"], t["target"]))
        number += 1
        th = make_threat(t, number)
        target["data"]["threats"].append(th)
        warnings += stride_warnings(kinds[t["target"]], th["type"], th["title"])
        log.append({"number": number, "id": th["id"], "title": th["title"], "type": th["type"],
                    "severity": th["severity"], "target": cell_name(target)})

    model = {"version": TD_VERSION,
             "summary": {"title": title, "owner": spec.get("owner", ""),
                         "description": spec.get("description", ""), "id": 0},
             "detail": {"contributors": [{"name": c} for c in spec.get("contributors", [])],
                        "diagrams": [{"id": 0, "title": spec.get("diagram") or title, "diagramType": "STRIDE",
                                      "placeholder": "New STRIDE diagram description",
                                      "thumbnail": "./public/content/images/thumbnail.stride.jpg",
                                      "version": TD_VERSION, "description": spec.get("description", ""),
                                      "cells": cells}],
                        "diagramTop": 1, "reviewer": spec.get("reviewer", ""), "threatTop": number}}
    refresh_model(model)
    problems = validate_model(model)
    if [p for p in problems if p.startswith("ERROR")]:
        raise ToolError("Built model failed validation:\n" + "\n".join(problems))
    save_json(args.out, model)
    if not args.no_log:
        write_draft_log(args.out, log, "build")
    for w in warnings:
        print(w)
    print("OK: wrote %s (%d elements, %d flows, %d threats)" % (
        args.out, len(spec.get("elements", []) or []), len(spec.get("flows", []) or []), number))


def write_draft_log(model_path, entries, mode):
    path = draft_log_path(model_path)
    existing = load_json(path) if os.path.exists(path) else {"model": os.path.basename(model_path), "runs": []}
    existing["runs"].append({"date": datetime.date.today().isoformat(), "mode": mode, "threats": entries})
    save_json(path, existing)
    print("draft log: %s" % path)


def draft_log_path(model_path):
    base = model_path[:-5] if model_path.endswith(".json") else model_path
    return base + ".draft-log.json"


def cmd_extend(args):
    model = load_json(args.model)
    delta = load_json(args.delta)
    check_spec(delta, partial=True)
    out = args.out or args.model
    diagram = model["detail"]["diagrams"][args.diagram]
    cells = diagram["cells"]
    warnings = []

    boxes_by_name = {name_key(cell_name(c)): c for c in cells
                     if (c.get("data") or {}).get("type") == "tm.BoundaryBox"}
    existing_by_name = {}
    for c in cells:
        t = (c.get("data") or {}).get("type")
        if t in ("tm.Actor", "tm.Process", "tm.Store", "tm.Flow"):
            existing_by_name.setdefault(name_key(cell_name(c)), c)

    def resolve(ref):
        if ref in idmap:
            return idmap[ref]
        hit = existing_by_name.get(name_key(ref))
        if hit is None:
            raise ToolError("'%s' is neither a new id in the delta nor the name of an existing element/flow" % ref)
        return hit

    idmap = {}
    added_elements = 0
    # new boundaries go to a new column area right of the current drawing
    max_x = max([bbox(c)[0] + bbox(c)[2] for c in cells if c.get("shape") != "flow"] + [MARGIN_X])
    new_boxes = {}
    for b in delta.get("boundaries", []) or []:
        if name_key(b.get("name") or b["id"]) in boxes_by_name:
            new_boxes[b["id"]] = boxes_by_name[name_key(b.get("name") or b["id"])]
        else:
            new_boxes[b["id"]] = make_box(b.get("name") or b["id"], b.get("description", ""))
    fresh_cols = {None: []}
    for e in delta.get("elements", []) or []:
        if name_key(e["name"]) in existing_by_name:
            warnings.append("skip element '%s': an element with that name already exists" % e["name"])
            idmap[e["id"]] = existing_by_name[name_key(e["name"])]
            continue
        td_type = SPEC_TYPE[norm_key(e["type"])]
        node = make_node(td_type, e["name"], e.get("description", ""), e.get("props"),
                         e.get("outOfScope", False), e.get("reasonOutOfScope", ""))
        idmap[e["id"]] = node
        added_elements += 1
        bref = e.get("boundary")
        box = None
        if bref:
            box = new_boxes.get(bref) or boxes_by_name.get(name_key(bref))
            if box is None:
                raise ToolError("Element '%s' refers to unknown boundary '%s'" % (e["id"], bref))
        if box is not None and any(c is box for c in cells):
            # place inside an existing box, below its current content, and grow the box
            bx, by, bw, bh = bbox(box)
            inner = [c for c in cells if c is not box and c.get("shape") != "flow" and inside(c, box)]
            y = max([bbox(c)[1] + bbox(c)[3] for c in inner] + [by + BOX_HEADER - ROW_GAP]) + ROW_GAP
            node["position"] = {"x": bx + max((bw - node["size"]["width"]) / 2.0, BOX_PAD / 2.0), "y": y}
            needed_w = node["size"]["width"] + BOX_PAD
            box["size"] = {"width": max(bw, needed_w), "height": max(bh, y + node["size"]["height"] + BOX_PAD - by)}
            cells.append(node)
        else:
            fresh_cols.setdefault(id(box) if box is not None else None, (box, []))
            key = id(box) if box is not None else None
            if key is None:
                fresh_cols[None].append(node)
            else:
                fresh_cols[key][1].append(node)
    columns = [(None, fresh_cols.pop(None))] + list(fresh_cols.values())
    layout_columns(columns, max_x + COL_GAP, TOP_Y, cells)

    for f in delta.get("flows", []) or []:
        if name_key(f.get("name", "")) in existing_by_name and f.get("name"):
            warnings.append("note: a flow named '%s' already exists; adding another one" % f["name"])
        src, dst = resolve(f["from"]), resolve(f["to"])
        flow = make_flow(src["id"], dst["id"], f)
        idmap[f["id"]] = flow
        cells.append(flow)

    top = model["detail"].get("threatTop") or 0
    for _, _, t in all_threats(model):
        if isinstance(t.get("number"), int):
            top = max(top, t["number"])
    log, added = [], 0
    for t in delta.get("threats", []) or []:
        target = resolve(t["target"])
        dup = [x for x in target["data"].get("threats", [])
               if name_key(x.get("title", "")) == name_key(t["title"])]
        if dup:
            warnings.append("skip threat '%s': same title already on '%s'" % (t["title"], cell_name(target)))
            continue
        top += 1
        th = make_threat(t, top)
        target["data"].setdefault("threats", []).append(th)
        warnings += stride_warnings(target["data"]["type"], th["type"], th["title"])
        log.append({"number": top, "id": th["id"], "title": th["title"], "type": th["type"],
                    "severity": th["severity"], "target": cell_name(target)})
        added += 1
    model["detail"]["threatTop"] = top
    model["version"] = model.get("version") or TD_VERSION
    refresh_model(model)
    problems = validate_model(model)
    if [p for p in problems if p.startswith("ERROR")]:
        raise ToolError("Extended model failed validation:\n" + "\n".join(problems))
    save_json(out, model)
    if not args.no_log:
        write_draft_log(out, log, "extend")
    for w in warnings:
        print(w)
    print("OK: wrote %s (+%d elements, +%d flows, +%d threats)" % (
        out, added_elements, len(delta.get("flows", []) or []), added))


# ---------------------------------------------------------------- validate
def validate_model(model):
    p = []
    if not isinstance(model, dict):
        return ["ERROR: model is not a JSON object"]
    v = str(model.get("version", ""))
    if not v or v.startswith("1."):
        p.append("ERROR: 'version' missing or a v1 model (open and re-save it in Threat Dragon 2.x first)")
    if not (model.get("summary") or {}).get("title"):
        p.append("ERROR: summary.title is required")
    detail = model.get("detail")
    if not isinstance(detail, dict) or not isinstance(detail.get("diagrams"), list):
        return p + ["ERROR: detail.diagrams must be a list"]
    ids, numbers = set(), {}
    for di, d in enumerate(detail["diagrams"]):
        if not isinstance(d.get("id"), int):
            p.append("ERROR: diagram #%d needs an integer id" % di)
        if not d.get("diagramType"):
            p.append("ERROR: diagram #%d needs diagramType" % di)
        cell_ids = {c.get("id") for c in d.get("cells", [])}
        for c in d.get("cells", []):
            label = "%s '%s'" % (c.get("shape"), cell_name(c))
            for k in ("id", "shape", "zIndex"):
                if k not in c:
                    p.append("ERROR: %s is missing '%s'" % (label, k))
            if c.get("id") in ids:
                p.append("ERROR: duplicate cell id %s" % c.get("id"))
            ids.add(c.get("id"))
            data = c.get("data")
            if not isinstance(data, dict) or "type" not in data or "hasOpenThreats" not in data:
                p.append("ERROR: %s needs data.type and data.hasOpenThreats" % label)
                continue
            if SHAPE_OF.get(data["type"]) and c.get("shape") not in (SHAPE_OF[data["type"]], "trust-broundary-curve"):
                p.append("WARN: %s has data.type %s" % (label, data["type"]))
            if c.get("shape") == "flow":
                for end in ("source", "target"):
                    ref = (c.get(end) or {}).get("cell")
                    if not ref:
                        p.append("WARN: flow '%s' has no %s element (dangling)" % (cell_name(c), end))
                    elif ref not in cell_ids:
                        p.append("ERROR: flow '%s' %s points to a missing cell" % (cell_name(c), end))
            threats = data.get("threats") or []
            should_open = any(str(t.get("status", "")).lower() == "open" for t in threats)
            if "threats" in data and bool(data.get("hasOpenThreats")) != should_open:
                p.append("WARN: %s hasOpenThreats=%s but threats say %s (run --fix)"
                         % (label, data.get("hasOpenThreats"), should_open))
            for t in threats:
                tl = "threat '%s' on %s" % (t.get("title", "?"), label)
                for k in ("id", "title", "status", "severity", "type", "modelType"):
                    if not t.get(k):
                        p.append("ERROR: %s is missing '%s'" % (tl, k))
                if t.get("status") and t["status"] not in STATUSES:
                    p.append("ERROR: %s has unknown status '%s'" % (tl, t["status"]))
                if t.get("severity") and t["severity"] not in SEVERITIES:
                    p.append("ERROR: %s has unknown severity '%s'" % (tl, t["severity"]))
                if t.get("modelType") == "STRIDE" and t.get("type") and t["type"] not in STRIDE:
                    p.append("ERROR: %s has unknown STRIDE type '%s'" % (tl, t["type"]))
                if t.get("status") == "Open" and not str(t.get("mitigation", "")).strip():
                    p.append("WARN: %s is Open with no mitigation text" % tl)
                n = t.get("number")
                if not isinstance(n, int):
                    p.append("WARN: %s has no number (run --fix)" % tl)
                elif n in numbers:
                    p.append("WARN: threat number %d used twice (run --fix)" % n)
                else:
                    numbers[n] = t
    if numbers and (detail.get("threatTop") or 0) < max(numbers):
        p.append("WARN: detail.threatTop is lower than the highest threat number (run --fix)")
    return p


def cmd_validate(args):
    model = load_json(args.model)
    if args.fix:
        refresh_model(model)
        save_json(args.model, model)
        print("fixed derived fields in %s" % args.model)
    problems = validate_model(model)
    for x in problems:
        print(x)
    errors = [x for x in problems if x.startswith("ERROR")]
    print("%s: %d error(s), %d warning(s)" % ("FAIL" if errors else "OK", len(errors), len(problems) - len(errors)))
    return 1 if errors else 0


# ---------------------------------------------------------------- extract
def tid(n):
    return "T-%03d" % n if isinstance(n, int) else "T-?"


def flatten(model, statuses=None):
    out = {"title": (model.get("summary") or {}).get("title", ""), "elements": [], "flows": [], "threats": []}
    for d in model.get("detail", {}).get("diagrams", []):
        cells = d.get("cells", [])
        boxes = [c for c in cells if (c.get("data") or {}).get("type") == "tm.BoundaryBox"]
        by_id = {c.get("id"): c for c in cells}
        for c in cells:
            data = c.get("data") or {}
            ty = data.get("type")
            if ty in ("tm.Actor", "tm.Process", "tm.Store"):
                props = {k: data.get(k) for k in PROPS.get(ty, {}) if data.get(k) not in (False, "", None)}
                out["elements"].append({"name": cell_name(c), "type": ty.replace("tm.", ""),
                                        "boundary": boundary_of(c, boxes), "description": data.get("description", ""),
                                        "outOfScope": data.get("outOfScope", False), "props": props,
                                        "diagram": d.get("title", "")})
            elif ty == "tm.Flow":
                s, t = by_id.get((c.get("source") or {}).get("cell")), by_id.get((c.get("target") or {}).get("cell"))
                sb, tb = (boundary_of(s, boxes) if s else ""), (boundary_of(t, boxes) if t else "")
                out["flows"].append({"name": cell_name(c), "from": cell_name(s) if s else "",
                                     "to": cell_name(t) if t else "", "protocol": data.get("protocol", ""),
                                     "encrypted": data.get("isEncrypted", False),
                                     "publicNetwork": data.get("isPublicNetwork", False),
                                     "bidirectional": data.get("isBidirectional", False),
                                     "crossesBoundary": sb != tb, "fromBoundary": sb, "toBoundary": tb,
                                     "description": data.get("description", ""), "diagram": d.get("title", "")})
            if ty in ("tm.Actor", "tm.Process", "tm.Store", "tm.Flow"):
                for th in data.get("threats") or []:
                    if statuses and th.get("status") not in statuses:
                        continue
                    if ty == "tm.Flow":
                        s = by_id.get((c.get("source") or {}).get("cell"))
                        t = by_id.get((c.get("target") or {}).get("cell"))
                        where = "%s -> %s" % (cell_name(s) if s else "?", cell_name(t) if t else "?")
                    else:
                        where = boundary_of(c, boxes)
                    out["threats"].append({"tid": tid(th.get("number")), "number": th.get("number"),
                                           "uuid": th.get("id"), "title": th.get("title", ""),
                                           "category": th.get("type", ""), "severity": th.get("severity", ""),
                                           "status": th.get("status", ""), "score": th.get("score", ""),
                                           "description": th.get("description", ""),
                                           "mitigation": th.get("mitigation", ""),
                                           "element": cell_name(c), "elementType": ty.replace("tm.", ""),
                                           "where": where, "diagram": d.get("title", "")})
    sev_rank = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    out["threats"].sort(key=lambda x: (sev_rank.get(x["severity"], 99), x["number"] or 0))
    return out


def md_cell(s):
    return str(s or "").replace("|", "\\|").replace("\n", "<br>")


def cmd_extract(args):
    model = load_json(args.model)
    statuses = [norm_status(s) for s in args.status.split(",")] if args.status else None
    flat = flatten(model, statuses)
    if args.format == "json":
        text = json.dumps(flat, indent=2, ensure_ascii=False)
    else:
        lines = ["# Threat model extract: %s" % flat["title"], "",
                 "## Elements", "", "| Name | Type | Boundary | Notes |", "|---|---|---|---|"]
        for e in flat["elements"]:
            notes = ", ".join("%s=%s" % kv for kv in e["props"].items())
            if e["outOfScope"]:
                notes = (notes + ", " if notes else "") + "out of scope"
            lines.append("| %s | %s | %s | %s |" % (md_cell(e["name"]), e["type"], md_cell(e["boundary"]), md_cell(notes)))
        lines += ["", "## Flows", "", "| Name | From -> To | Protocol | Encrypted | Crosses boundary |",
                  "|---|---|---|---|---|"]
        for f in flat["flows"]:
            lines.append("| %s | %s -> %s | %s | %s | %s |" % (
                md_cell(f["name"]), md_cell(f["from"]), md_cell(f["to"]), md_cell(f["protocol"]),
                "yes" if f["encrypted"] else "no",
                ("yes (%s -> %s)" % (f["fromBoundary"] or "none", f["toBoundary"] or "none")) if f["crossesBoundary"] else "no"))
        lines += ["", "## Threats", "", "| ID | Severity | Status | Category | Element | Title | Mitigation |",
                  "|---|---|---|---|---|---|---|"]
        for t in flat["threats"]:
            lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
                t["tid"], t["severity"], t["status"], t["category"], md_cell(t["element"]),
                md_cell(t["title"]), md_cell(t["mitigation"])))
        text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print("OK: wrote %s" % args.out)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


# ---------------------------------------------------------------- set-status
def parse_tid(s):
    k = str(s).strip().upper().replace("T-", "").replace("#", "")
    try:
        return int(k)
    except ValueError:
        raise ToolError("Threat reference must look like T-12, #12 or 12 (got '%s')" % s)


def cmd_set_status(args):
    model = load_json(args.model)
    n = parse_tid(args.threat)
    status = norm_status(args.status)
    hit = None
    for _, c, t in all_threats(model):
        if t.get("number") == n:
            hit = (c, t)
            break
    if not hit:
        raise ToolError("No threat with number %d in %s" % (n, args.model))
    c, t = hit
    old = t.get("status")
    t["status"] = status
    if args.note:
        stamp = "[%s] %s -> %s: %s" % (datetime.date.today().isoformat(), old, status, args.note.strip())
        t["mitigation"] = (t.get("mitigation", "").rstrip() + "\n\n" + stamp).strip()
    refresh_cell(c)
    save_json(args.model, model)
    print("OK: %s '%s' %s -> %s" % (tid(n), t.get("title"), old, status))


# ---------------------------------------------------------------- diff (id integrity)
def _git_show(ref, path):
    import subprocess
    d = os.path.dirname(os.path.abspath(path))
    r = subprocess.run(["git", "-C", d, "show", "%s:./%s" % (ref, os.path.basename(path))],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        return None
    return json.loads(r.stdout.decode("utf-8"))


def compare_models(old, new):
    """Compare two Threat Dragon models by pinned threat number. Pure function, no I/O."""
    fo, fn = flatten(old), flatten(new)
    to = {t["number"]: t for t in fo["threats"] if isinstance(t["number"], int)}
    tn = {}
    res = {"violations": [], "warnings": [], "addedThreats": [], "removedThreats": [], "changedThreats": [],
           "addedElements": [], "removedElements": [], "addedFlows": [], "removedFlows": []}
    for t in fn["threats"]:
        n = t["number"]
        if not isinstance(n, int):
            res["violations"].append("a threat ('%s') has no number" % t["title"])
        elif n in tn:
            res["violations"].append("%s is used by two threats ('%s' and '%s')" % (tid(n), tn[n]["title"], t["title"]))
        else:
            tn[n] = t
    top_old = (old.get("detail") or {}).get("threatTop") or 0
    top_new = (new.get("detail") or {}).get("threatTop") or 0
    if top_new < top_old:
        res["violations"].append("threatTop went down (%d -> %d): ids of deleted threats could be reused" % (top_old, top_new))
    for n in sorted(tn):
        t = tn[n]
        o = to.get(n)
        if o is None:
            if n <= max(top_old, max(to) if to else 0):
                res["violations"].append("%s '%s' reuses or backfills an id from the base model" % (tid(n), t["title"]))
            res["addedThreats"].append({"tid": tid(n), "title": t["title"], "severity": t["severity"],
                                        "element": t["element"], "status": t["status"]})
            continue
        same_target = name_key(o["element"]) == name_key(t["element"])
        same_title = name_key(o["title"]) == name_key(t["title"])
        same_cat = o["category"] == t["category"]
        if not same_target and not same_title:
            res["violations"].append("%s now describes a different threat: '%s' on '%s' was '%s' on '%s'" % (
                tid(n), t["title"], t["element"], o["title"], o["element"]))
            continue
        ch = {}
        for k in ("title", "element", "category", "severity", "status"):
            if o[k] != t[k]:
                ch[k] = [o[k], t[k]]
        if ch:
            res["changedThreats"].append({"tid": tid(n), "title": t["title"], "changes": ch})
            if not same_cat:
                res["warnings"].append("%s changed STRIDE category %s -> %s" % (tid(n), o["category"], t["category"]))
    for n in sorted(to):
        if n not in tn:
            res["removedThreats"].append({"tid": tid(n), "title": to[n]["title"], "element": to[n]["element"]})
    ek = lambda e: name_key(e["name"])
    eo, en = {ek(e): e for e in fo["elements"]}, {ek(e): e for e in fn["elements"]}
    res["addedElements"] = [{"name": en[k]["name"], "type": en[k]["type"], "boundary": en[k]["boundary"]} for k in en if k not in eo]
    res["removedElements"] = [{"name": eo[k]["name"], "type": eo[k]["type"]} for k in eo if k not in en]
    fk = lambda f: (name_key(f["from"]), name_key(f["to"]), name_key(f["name"]))
    flo, fln = {fk(f): f for f in fo["flows"]}, {fk(f): f for f in fn["flows"]}
    res["addedFlows"] = [{"name": fln[k]["name"], "from": fln[k]["from"], "to": fln[k]["to"],
                          "crossesBoundary": fln[k]["crossesBoundary"]} for k in fln if k not in flo]
    res["removedFlows"] = [{"name": flo[k]["name"], "from": flo[k]["from"], "to": flo[k]["to"]} for k in flo if k not in fln]
    if res["removedThreats"]:
        res["warnings"].append("%d threat(s) removed: confirm a human deleted them on purpose (%s)" % (
            len(res["removedThreats"]), ", ".join(x["tid"] for x in res["removedThreats"])))
    if res["removedElements"]:
        res["warnings"].append("%d element(s) removed or renamed (%s); threats are matched by id, but check the model still reflects the system" % (
            len(res["removedElements"]), ", ".join(x["name"] for x in res["removedElements"])))
    return res


def cmd_diff(args):
    new = load_json(args.new)
    if args.old:
        old = load_json(args.old)
    else:
        ref = args.base or "HEAD"
        old = _git_show(ref, args.new)
        if old is None:
            print("No base model: %s is not present at %s (new model, nothing to compare)." % (args.new, ref))
            return 0
    res = compare_models(old, new)
    fails = list(res["violations"]) + (res["warnings"] if args.strict else [])
    if args.format == "json":
        res["ok"] = not fails
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 1 if fails else 0
    L = ["# Threat model id check: %s" % args.new, ""]
    if res["violations"]:
        L += ["## Violations (pinned ids broken)"] + ["- %s" % v for v in res["violations"]] + [""]
    if res["warnings"]:
        L += ["## Warnings"] + ["- %s" % w for w in res["warnings"]] + [""]
    def sec(name, rows, fmt):
        if rows:
            L.extend(["## " + name] + ["- " + fmt(r) for r in rows] + [""])
    sec("Threats added", res["addedThreats"], lambda r: "%s [%s, %s] %s (on %s)" % (r["tid"], r["severity"], r["status"], r["title"], r["element"]))
    sec("Threats removed", res["removedThreats"], lambda r: "%s %s (on %s)" % (r["tid"], r["title"], r["element"]))
    sec("Threats changed", res["changedThreats"], lambda r: "%s %s: %s" % (r["tid"], r["title"], "; ".join("%s %s -> %s" % (k, v[0], v[1]) for k, v in r["changes"].items())))
    sec("Elements added", res["addedElements"], lambda r: "%s (%s, boundary: %s)" % (r["name"], r["type"], r["boundary"] or "none"))
    sec("Elements removed", res["removedElements"], lambda r: "%s (%s)" % (r["name"], r["type"]))
    sec("Flows added", res["addedFlows"], lambda r: "%s -> %s%s" % (r["from"], r["to"], " (crosses a trust boundary)" if r["crossesBoundary"] else ""))
    sec("Flows removed", res["removedFlows"], lambda r: "%s -> %s" % (r["from"], r["to"]))
    if len(L) == 2:
        L.append("No differences.")
    L.append("RESULT: %s" % ("FAIL" if fails else "OK"))
    print("\n".join(L))
    return 1 if fails else 0


# ---------------------------------------------------------------- stats
def cmd_stats(args):
    model = load_json(args.model)
    flat = flatten(model)
    by_status, by_sev = {}, {}
    for t in flat["threats"]:
        by_status[t["status"]] = by_status.get(t["status"], 0) + 1
        by_sev[t["severity"]] = by_sev.get(t["severity"], 0) + 1
    result = {"model": flat["title"], "elements": len(flat["elements"]), "flows": len(flat["flows"]),
              "threats": len(flat["threats"]), "byStatus": by_status, "bySeverity": by_sev}
    log_path = args.draft_log or draft_log_path(args.model)
    if os.path.exists(log_path):
        log = load_json(log_path)
        drafted = {}
        for run in log.get("runs", []):
            for e in run.get("threats", []):
                drafted[e["id"]] = e
        current = {t["uuid"]: t for t in flat["threats"]}
        kept = [u for u in drafted if u in current and current[u]["status"] != "NotApplicable"]
        rejected_na = [u for u in drafted if u in current and current[u]["status"] == "NotApplicable"]
        deleted = [u for u in drafted if u not in current]
        human = [u for u in current if u not in drafted]
        result["aiDraft"] = {"drafted": len(drafted), "kept": len(kept),
                             "rejectedNotApplicable": len(rejected_na), "deleted": len(deleted),
                             "addedByHumans": len(human),
                             "keepRate": round(len(kept) / len(drafted), 2) if drafted else None}
    print(json.dumps(result, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description="Helper for OWASP Threat Dragon v2 models")
    sub = ap.add_subparsers(dest="cmd")
    b = sub.add_parser("build", help="spec -> new Threat Dragon model")
    b.add_argument("spec"); b.add_argument("out")
    b.add_argument("--no-log", action="store_true", help="do not write the .draft-log.json sidecar")
    b.add_argument("--force", action="store_true", help="overwrite an existing model (renumbers threats!)")
    e = sub.add_parser("extend", help="add a delta spec to an existing model")
    e.add_argument("model"); e.add_argument("delta"); e.add_argument("-o", "--out")
    e.add_argument("--diagram", type=int, default=0, help="index of the diagram to extend (default 0)")
    e.add_argument("--no-log", action="store_true")
    v = sub.add_parser("validate", help="check a model")
    v.add_argument("model"); v.add_argument("--fix", action="store_true")
    x = sub.add_parser("extract", help="flatten a model")
    x.add_argument("model"); x.add_argument("--format", choices=["json", "md"], default="json")
    x.add_argument("--status", help="comma list, e.g. Open,Mitigated"); x.add_argument("-o", "--out")
    s = sub.add_parser("set-status", help="change a threat's status")
    s.add_argument("model"); s.add_argument("--threat", required=True); s.add_argument("--status", required=True)
    s.add_argument("--note")
    d = sub.add_parser("diff", help="compare model versions by pinned threat id (CI integrity check)")
    d.add_argument("new"); d.add_argument("old", nargs="?", help="older model file (default: NEW as of --base)")
    d.add_argument("--base", help="git ref to read the old model from (default HEAD)")
    d.add_argument("--format", choices=["md", "json"], default="md")
    d.add_argument("--strict", action="store_true", help="also fail on warnings (removed threats/elements)")
    st = sub.add_parser("stats", help="counts and AI-draft keep rate")
    st.add_argument("model"); st.add_argument("--draft-log")
    args = ap.parse_args(argv)
    handlers = {"build": cmd_build, "extend": cmd_extend, "validate": cmd_validate, "extract": cmd_extract,
                "set-status": cmd_set_status, "diff": cmd_diff, "stats": cmd_stats}
    if not args.cmd:
        ap.print_help()
        return 2
    try:
        return handlers[args.cmd](args) or 0
    except ToolError as err:
        print("ERROR: %s" % err, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
