<div align="center">

```
 █████╗ ██████╗       ██████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗
██╔══██╗██╔══██╗     ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║
███████║██║  ██║     ██║  ███╗██████╔╝███████║██████╔╝███████║
██╔══██║██║  ██║     ██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║
██║  ██║██████╔╝     ╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║
╚═╝  ╚═╝╚═════╝       ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
```

# ADAutoGraph

**A modern local BloodHound-style graph UI for Active Directory attack paths.**

ADAutoGraph imports BloodHound collector ZIPs, indexes them into SQLite, and lets
you explore AD relationships through a clean, fast, operator-focused web UI.

Crafted by **c4sh3r** · authorized security testing only

![python](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![sqlite](https://img.shields.io/badge/storage-SQLite-044a64?style=flat-square&logo=sqlite&logoColor=white)
![offline](https://img.shields.io/badge/offline-local%20web%20app-2ea44f?style=flat-square)
![license](https://img.shields.io/badge/license-PolyForm%20Noncommercial-orange?style=flat-square)

</div>

---

## Preview

![ADAutoGraph screenshot](assets/screenshot.png)

---

## Why

BloodHound is excellent, but sometimes you want a lightweight local viewer that:

- opens fast,
- does not load every object at once,
- keeps one domain/project isolated at a time,
- highlights abuse paths with commands,
- and feels integrated with an offensive workflow like ADAutoPwn.

ADAutoGraph is built for that workflow. You import a BloodHound ZIP, choose a
domain, then build the visible graph progressively from searches, focused object
actions, ACL views, or attack paths.

---

## Features

- **BloodHound ZIP import**
  - Parses users, groups, computers, domains, OUs, GPOs, containers and ACL edges.
  - Stores normalized objects in `data/graph.db`.

- **Domain/project selector**
  - Pick an existing imported domain.
  - Import a new BloodHound ZIP without mixing datasets.

- **Progressive graph loading**
  - The graph starts empty.
  - Search or choose a view to build only the context you need.
  - Prevents huge BloodHound datasets from becoming unreadable.

- **Modern canvas renderer**
  - Static layout, no force physics, no magnetic nodes.
  - Independent drag per node.
  - Direction arrows show who controls/abuses whom.
  - Edge labels are embedded into the line and colored by severity.

- **Severity-aware ACLs**
  - Critical: `DCSync`, `GenericAll`, `WriteDACL`, `GetChangesAll`.
  - High: `WriteOwner`, `Owns`, `ForceChangePassword`, Shadow Credentials.
  - Medium: `WriteSPN`, `AddMember`, `ReadGMSAPassword`, delegation-style pivots.

- **Focused object inspector**
  - Full imported object properties.
  - Outbound and inbound edges.
  - Abuse-focused edge list.
  - Raw property view.

- **Attack path builder**
  - Mark one or more objects as `owned`.
  - Build attack chains from owned principals.
  - Traverses abuse edges and group membership.
  - Falls back to useful reachable chains when no high-value path exists.

- **Command snippets**
  - Linux and Windows abuse commands.
  - Copy button per command.
  - Colored command blocks for readability.

---

## Requirements

ADAutoGraph currently uses only the Python standard library.

Recommended:

- Python `3.10+`
- A modern browser
- A BloodHound collector ZIP

No Node.js, npm, Docker or external Python packages are required.

---

## Installation

```bash
git clone https://github.com/C4sh3R/ADAutoGraph.git
cd ADAutoGraph
```

Optional:

```bash
chmod +x server.py
```

---

## Usage

Start the local web server:

```bash
python3 -B server.py
```

Open:

```text
http://127.0.0.1:8765
```

Then:

1. Import a BloodHound `.zip`.
2. Open the imported domain.
3. Search for a user, group, computer or domain object.
4. Click a node to inspect it.
5. Mark compromised objects as `owned`.
6. Use `Attack paths` to build chains from owned objects.

---

## CLI Options

```bash
python3 -B server.py --host 127.0.0.1 --port 8765
```

| Option | Description |
|--------|-------------|
| `--host` | Bind address. Default: `127.0.0.1` |
| `--port` | HTTP port. Default: `8765` |

---

## Data Storage

Imported data is stored locally:

```text
data/graph.db
```

The database is intentionally ignored by git. Delete it if you want to reset all
imported domains.

---

## Project Structure

```text
ADAutoGraph/
├── assets/
│   └── screenshot.png
├── data/
│   └── graph.db              # local only, ignored by git
├── web/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── server.py
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Notes

ADAutoGraph is not a replacement for BloodHound Enterprise or the official
BloodHound UI. It is a lightweight local graph viewer focused on offensive
workflow, abuse readability and fast inspection.

---

## Legal

Use only against systems you are explicitly authorized to test: your own lab, a
CTF, or a signed engagement. You are responsible for your actions.

---

## License

This project uses the **PolyForm Noncommercial License 1.0.0**, matching
ADAutoPwn. Commercial use is reserved by the author.
