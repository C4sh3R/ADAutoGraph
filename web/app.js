const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const COLORS = {
  User: "#61a8ff",
  Group: "#f5c84c",
  Computer: "#ff7474",
  Domain: "#49d99f",
  GPO: "#b69cff",
  OU: "#72d9f7",
  Container: "#72d9f7",
  Base: "#a2aec0",
};
const HILITE = {
  User: "#b8dcff",
  Group: "#fff0a8",
  Computer: "#ffc0c0",
  Domain: "#b8ffe4",
  GPO: "#e1d4ff",
  OU: "#c8f4ff",
  Container: "#c8f4ff",
  Base: "#e4ebf5",
};
const DARKS = {
  User: "#143257",
  Group: "#5b4308",
  Computer: "#5a171f",
  Domain: "#0b4a36",
  GPO: "#2f245d",
  OU: "#124454",
  Container: "#124454",
  Base: "#263241",
};
const SEVERITY = {
  critical: "#ff3b5f",
  high: "#ff9f43",
  medium: "#ffd45a",
  low: "#69a8ff",
  info: "#9aa8bb",
};

function edgeSeverity(e) {
  const rights = e.rights || [e.right || ""];
  let best = "info";
  for (const raw of rights) {
    const k = `${raw}`.toLowerCase().replace(/[^a-z]/g, "");
    const sev =
      ["dcsync", "getchangesall", "genericall", "writedacl"].includes(k) ? "critical" :
      ["writeowner", "owns", "addkeycredentiallink", "forcechangepassword", "allextendedrights"].includes(k) ? "high" :
      ["readgmsapassword", "genericwrite", "writespn", "addspn", "addmember", "addself", "allowedtoact", "allowedtodelegate"].includes(k) ? "medium" :
      e.abusable ? "low" : "info";
    if (["critical", "high", "medium", "low", "info"].indexOf(sev) < ["critical", "high", "medium", "low", "info"].indexOf(best)) best = sev;
  }
  return best;
}
let domains = [];
let active = null;
let view = "none";
let focusSid = "";
let relationMode = "abusable";
let graph = { nodes: [], edges: [], drawEdges: [], totalNodes: 0, totalEdges: 0 };
let nodeBySid = new Map();
let selected = -1;
let hover = -1;
let hoverEdge = -1;
let scale = 1;
let tx = 0;
let ty = 0;
let dpr = Math.min(devicePixelRatio || 1, 2);
let dragging = -1;
let panning = false;
let last = [0, 0];
let moved = false;
let drawQueued = false;

const canvas = $("#graph");
const ctx = canvas.getContext("2d");

function api(path, options) {
  return fetch(path, options).then(async (r) => {
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || r.statusText);
    return data;
  });
}

function toast(msg) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => el.classList.remove("show"), 1300);
}

function esc(s) {
  return `${s ?? ""}`.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function short(s, n = 28) {
  s = `${s ?? ""}`;
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function loadDomains() {
  return api("/api/domains").then((data) => {
    domains = data.domains || [];
    renderDomains();
  });
}

function renderDomains() {
  const list = $("#domainsList");
  if (!domains.length) {
    list.innerHTML = `<div class="empty">No domains imported yet. Import a BloodHound zip to begin.</div>`;
    return;
  }
  list.innerHTML = domains.map((d) => `
    <article class="domain-card" data-id="${d.id}">
      <div>
        <h3>${esc(d.name)}</h3>
        <p>${esc(d.source || "BloodHound import")} · ${new Date(d.created_at * 1000).toLocaleString()}</p>
      </div>
      <div class="stats">
        <span class="pill">${d.node_count} nodes</span>
        <span class="pill">${d.edge_count} edges</span>
      </div>
    </article>
  `).join("");
  $$(".domain-card").forEach((el) => el.addEventListener("click", () => openDomain(+el.dataset.id)));
}

async function openDomain(id) {
  active = domains.find((d) => d.id === id) || { id, name: `Domain ${id}` };
  $("#welcome").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#activeDomain").textContent = active.name;
  view = "none";
  focusSid = "";
  relationMode = "abusable";
  graph = { nodes: [], edges: [], drawEdges: [], totalNodes: active.node_count || 0, totalEdges: active.edge_count || 0 };
  nodeBySid = new Map();
  selected = -1;
  hover = -1;
  $$(".view").forEach((b) => b.classList.remove("active"));
  resize();
  loadStats();
  $("#graphMeta").textContent = `${active.node_count || 0} nodes · ${active.edge_count || 0} edges · waiting for context`;
  setStatus("Search or choose a view to begin.");
  updateEmptyState();
  requestDraw();
}

async function loadStats() {
  if (!active) return;
  try {
    const s = await api(`/api/domain/${active.id}/stats`);
    $("#domainStats").innerHTML = `
      <span class="stat-chip"><b>${s.nodes}</b>nodes</span>
      <span class="stat-chip"><b>${s.edges}</b>edges</span>
      <span class="stat-chip"><b>${s.abusable}</b>abusable</span>
      <span class="stat-chip"><b>${s.highValue}</b>high value</span>
      <span class="stat-chip"><b>${s.owned}</b>owned</span>
      ${(s.rights || []).slice(0, 4).map((r) => `<span class="stat-chip"><b>${r.count}</b>${esc(r.right_name)}</span>`).join("")}
    `;
  } catch {
    $("#domainStats").innerHTML = "";
  }
}

async function loadGraph(query = "") {
  if (view === "none" && !query && !focusSid) {
    clearGraph();
    return;
  }
  $("#graphMeta").textContent = "loading graph...";
  const params = new URLSearchParams({
    view,
    q: query,
    focus: focusSid,
    rel: relationMode,
    limit: "900",
  });
  const data = await api(`/api/domain/${active.id}/graph?${params}`);
  graph = data;
  nodeBySid = new Map(graph.nodes.map((n, i) => [n.id, i]));
  graph.drawEdges = buildDrawEdges(graph.edges);
  selected = -1;
  hover = -1;
  layoutGraph();
  fitGraph();
  $("#graphMeta").textContent = `${graph.nodes.length}/${graph.totalNodes} shown · ${graph.edges.length}/${graph.totalEdges} edges · ${focusSid ? relationMode : view}`;
  const emptyMsg = view === "paths"
    ? "No attack path found. Mark a starting object as owned, then open Attack paths."
    : "No objects matched this context.";
  setStatus(graph.nodes.length ? `${graph.nodes.length} nodes · ${graph.drawEdges.length} visual links. Click a node to inspect; use object actions to narrow context.` : emptyMsg);
  if (!focusSid) closePanel();
  updateEmptyState();
  requestDraw();
}

function clearGraph() {
  graph = { nodes: [], edges: [], drawEdges: [], totalNodes: active?.node_count || 0, totalEdges: active?.edge_count || 0 };
  nodeBySid = new Map();
  selected = -1;
  hover = -1;
  focusSid = "";
  view = "none";
  $$(".view").forEach((b) => b.classList.remove("active"));
  closePanel();
  $("#graphMeta").textContent = `${active?.node_count || 0} nodes · ${active?.edge_count || 0} edges · waiting for context`;
  setStatus("Canvas cleared. Search an object or choose a view.");
  updateEmptyState();
  requestDraw();
}

function updateEmptyState() {
  $("#emptyGraph")?.classList.toggle("hidden", graph.nodes.length > 0);
}

function setStatus(text) {
  const el = $("#statusText");
  if (el) el.textContent = text || "Ready";
}

function buildDrawEdges(edges) {
  const groups = new Map();
  edges.forEach((e) => {
    const k = `${e.sourceSid}→${e.targetSid}`;
    let g = groups.get(k);
    if (!g) {
      g = {
        source: e.source,
        target: e.target,
        sourceSid: e.sourceSid,
        targetSid: e.targetSid,
        rights: [],
        abusable: false,
        count: 0,
      };
      groups.set(k, g);
    }
    g.count += 1;
    g.abusable = g.abusable || e.abusable;
    if (!g.rights.includes(e.right)) g.rights.push(e.right);
  });
  return [...groups.values()];
}

function hash01(s) {
  let h = 2166136261;
  s = `${s ?? ""}`;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 100000) / 100000;
}

function layoutGraph() {
  if (focusSid && nodeBySid.has(focusSid)) {
    layoutFocusedGraph();
    return;
  }
  const buckets = { Domain: [], Group: [], User: [], Computer: [], GPO: [], OU: [], Container: [], Base: [] };
  graph.nodes.forEach((n, i) => {
    n.i = i;
    n.r = (n.type === "Domain" ? 25 : n.highValue ? 22 : n.owned ? 21 : 18) + Math.min(n.degree || 0, 40) * 0.06;
    n.locked = false;
    (buckets[n.type] || buckets.Base).push(i);
  });
  Object.values(buckets).forEach((items) => items.sort((a, b) => (graph.nodes[b].degree || 0) - (graph.nodes[a].degree || 0)));
  const focused = focusSid && nodeBySid.has(focusSid);
  const centers = focused
    ? { Domain: [0, -180], Group: [-290, -30], User: [-110, 230], Computer: [300, 20], GPO: [-360, 240], OU: [360, 240], Container: [360, 240], Base: [0, 0] }
    : { Domain: [0, -290], Group: [-410, -40], User: [-80, 300], Computer: [420, -20], GPO: [-520, 330], OU: [520, 320], Container: [520, 320], Base: [0, 40] };
  for (const [type, items] of Object.entries(buckets)) {
    const [cx, cy] = centers[type] || centers.Base;
    items.forEach((idx, k) => {
      const n = graph.nodes[idx];
      if (n.id === focusSid) {
        n.x = 0; n.y = 0; return;
      }
      const ring = Math.floor(Math.sqrt(k));
      const pos = k - ring * ring;
      const per = Math.max(1, ring * 2 + 1);
      const angle = (pos / per) * Math.PI * 2 + hash01(n.id) * .95;
      const radius = (focused ? 96 : 76) * ring + hash01(n.label) * 28 + (focused ? 120 : 0);
      n.x = cx + Math.cos(angle) * radius;
      n.y = cy + Math.sin(angle) * radius;
    });
  }
}

function layoutFocusedGraph() {
  graph.nodes.forEach((n, i) => {
    n.i = i;
    n.r = (n.type === "Domain" ? 25 : n.highValue ? 22 : n.owned ? 21 : 18) + Math.min(n.degree || 0, 40) * 0.06;
    n.locked = false;
  });
  const fidx = nodeBySid.get(focusSid);
  const focus = graph.nodes[fidx];
  focus.x = 0;
  focus.y = 0;
  focus.r = Math.max(focus.r, 28);

  const outbound = [];
  const inbound = [];
  const both = new Set();
  graph.drawEdges.forEach((e) => {
    if (e.sourceSid === focusSid && e.targetSid !== focusSid) outbound.push(e.target);
    if (e.targetSid === focusSid && e.sourceSid !== focusSid) inbound.push(e.source);
  });
  const outSet = new Set(outbound);
  const inSet = new Set(inbound);
  outSet.forEach((i) => { if (inSet.has(i)) both.add(i); });

  const place = (items, side) => {
    const uniq = [...new Set(items)].filter((i) => i !== fidx);
    uniq.sort((a, b) => (graph.nodes[b].highValue - graph.nodes[a].highValue) || (graph.nodes[b].degree || 0) - (graph.nodes[a].degree || 0));
    const count = Math.max(1, uniq.length);
    uniq.forEach((idx, k) => {
      const n = graph.nodes[idx];
      const row = Math.floor(k / 10);
      const slot = k % 10;
      const spread = Math.min(Math.PI * .82, Math.PI * (.22 + count * .035));
      const t = count === 1 ? 0 : (slot / Math.min(9, count - 1)) - .5;
      const angle = (side === "right" ? 0 : Math.PI) + t * spread;
      const radius = 230 + row * 118 + (both.has(idx) ? 28 : 0);
      n.x = Math.cos(angle) * radius;
      n.y = Math.sin(angle) * radius;
    });
  };
  place(outbound, "right");
  place(inbound.filter((i) => !outSet.has(i)), "left");

  graph.nodes.forEach((n, i) => {
    if (i === fidx || outSet.has(i) || inSet.has(i)) return;
    const k = i;
    const angle = Math.PI / 2 + hash01(n.id) * Math.PI;
    const radius = 360 + (k % 6) * 70;
    n.x = Math.cos(angle) * radius;
    n.y = Math.sin(angle) * radius;
  });
}

function resize() {
  canvas.width = innerWidth * dpr;
  canvas.height = innerHeight * dpr;
  canvas.style.width = `${innerWidth}px`;
  canvas.style.height = `${innerHeight}px`;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  requestDraw();
}

function fitGraph() {
  if (!graph.nodes.length) return;
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  graph.nodes.forEach((n) => {
    const labelPad = Math.max(90, (n.label || "").length * 3.6);
    x0 = Math.min(x0, n.x - labelPad); y0 = Math.min(y0, n.y - 70);
    x1 = Math.max(x1, n.x + labelPad); y1 = Math.max(y1, n.y + 78);
  });
  const pad = 360;
  const w = Math.max(400, x1 - x0 + pad);
  const h = Math.max(400, y1 - y0 + pad);
  scale = Math.max(.18, Math.min(1.28, Math.min(innerWidth / w, innerHeight / h)));
  tx = innerWidth / 2 - ((x0 + x1) / 2) * scale + 70;
  ty = innerHeight / 2 - ((y0 + y1) / 2) * scale;
}

function world(px, py) { return [(px - tx) / scale, (py - ty) / scale]; }
function screen(x, y) { return [x * scale + tx, y * scale + ty]; }

function requestDraw() {
  if (drawQueued) return;
  drawQueued = true;
  requestAnimationFrame(() => {
    drawQueued = false;
    draw();
  });
}

function draw() {
  ctx.clearRect(0, 0, innerWidth, innerHeight);
  if (!graph.nodes.length) return;
  drawGrid();
  const activeIdx = selected >= 0 ? selected : hover;
  const activeSid = activeIdx >= 0 ? graph.nodes[activeIdx].id : null;
  const linked = new Set();
  if (activeSid) {
    graph.edges.forEach((e) => {
      if (e.sourceSid === activeSid) linked.add(e.targetSid);
      if (e.targetSid === activeSid) linked.add(e.sourceSid);
    });
  }

  graph.drawEdges.forEach((e, edgeIdx) => {
    const a = graph.nodes[e.source], b = graph.nodes[e.target];
    if (!a || !b) return;
    const [ax, ay] = screen(a.x, a.y);
    const [bx, by] = screen(b.x, b.y);
    const rel = activeSid && (e.sourceSid === activeSid || e.targetSid === activeSid);
    const isHoverEdge = edgeIdx === hoverEdge;
    const dim = activeSid && !rel && !isHoverEdge;
    ctx.globalAlpha = dim ? .08 : 1;
    const sev = edgeSeverity(e);
    const sevColor = SEVERITY[sev];
    ctx.strokeStyle = e.abusable ? hexA(sevColor, (rel || isHoverEdge) ? .98 : .58) : ((rel || isHoverEdge) ? "rgba(105,168,255,.85)" : "rgba(140,154,176,.15)");
    ctx.lineWidth = e.abusable ? ((rel || isHoverEdge) ? 3.1 : 1.85) : ((rel || isHoverEdge) ? 2.0 : .9);
    const mx = (ax + bx) / 2, my = (ay + by) / 2;
    const dx = bx - ax, dy = by - ay;
    const cx = mx - dy * .16, cy = my + dx * .16;
    if (rel || e.abusable || isHoverEdge) {
      ctx.save();
      ctx.shadowBlur = (rel || isHoverEdge) ? 14 : 7;
      ctx.shadowColor = e.abusable ? sevColor : "#69a8ff";
    }
    ctx.beginPath();
    ctx.moveTo(ax, ay);
    ctx.quadraticCurveTo(cx, cy, bx, by);
    ctx.stroke();
    if (rel || e.abusable) ctx.restore();
    if (rel || isHoverEdge || (e.abusable && graph.drawEdges.length < 90)) {
      const willLabel = isHoverEdge || (rel && graph.drawEdges.length < 24) || (graph.drawEdges.length < 12 && scale > .72);
      drawDirectionMarkers(ax, ay, cx, cy, bx, by, e.abusable ? sevColor : "#69a8ff", rel || isHoverEdge, willLabel);
      if (willLabel) {
        drawEdgeLabel(e, ax, ay, cx, cy, bx, by, e.abusable, sevColor);
      }
    }
    ctx.globalAlpha = 1;
  });

  graph.nodes.forEach((n, i) => {
    const isActive = i === activeIdx;
    const isLinked = activeSid && linked.has(n.id);
    const dim = activeSid && !isActive && !isLinked;
    drawNode(n, isActive, dim);
  });
}

function hexA(hex, alpha) {
  const h = hex.replace("#", "");
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

function drawGrid() {
  const step = 42 * scale;
  if (step < 14) return;
  ctx.save();
  ctx.strokeStyle = "rgba(255,255,255,.035)";
  ctx.lineWidth = 1;
  const ox = tx % step, oy = ty % step;
  for (let x = ox; x < innerWidth; x += step) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, innerHeight); ctx.stroke();
  }
  for (let y = oy; y < innerHeight; y += step) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(innerWidth, y); ctx.stroke();
  }
  ctx.restore();
}

function qPoint(a, c, b, t) {
  const mt = 1 - t;
  return mt * mt * a + 2 * mt * t * c + t * t * b;
}

function qTangent(a, c, b, t) {
  return 2 * (1 - t) * (c - a) + 2 * t * (b - c);
}

function drawDirectionMarkers(ax, ay, cx, cy, bx, by, color, strong, hasLabel) {
  const marks = hasLabel ? [.88] : (strong ? [.42, .72, .90] : [.72, .90]);
  marks.forEach((t, idx) => {
    const x = qPoint(ax, cx, bx, t);
    const y = qPoint(ay, cy, by, t);
    const txv = qTangent(ax, cx, bx, t);
    const tyv = qTangent(ay, cy, by, t);
    const size = idx === marks.length - 1 ? 11 : 7.5;
    drawChevron(x, y, Math.atan2(tyv, txv), size, color, idx === marks.length - 1 || strong);
  });
}

function drawChevron(x, y, ang, size, color, filled) {
  ctx.save();
  ctx.shadowBlur = filled ? 13 : 8;
  ctx.shadowColor = color;
  ctx.fillStyle = filled ? color : "rgba(8,12,18,.86)";
  ctx.strokeStyle = "rgba(6,10,16,.88)";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(x, y);
  ctx.lineTo(x - Math.cos(ang - .46) * size, y - Math.sin(ang - .46) * size);
  ctx.lineTo(x - Math.cos(ang + .46) * size, y - Math.sin(ang + .46) * size);
  ctx.closePath();
  ctx.stroke();
  if (filled) ctx.fill();
  else {
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.4;
    ctx.beginPath();
    ctx.moveTo(x, y);
    ctx.lineTo(x - Math.cos(ang - .46) * size, y - Math.sin(ang - .46) * size);
    ctx.moveTo(x, y);
    ctx.lineTo(x - Math.cos(ang + .46) * size, y - Math.sin(ang + .46) * size);
    ctx.stroke();
  }
  ctx.restore();
}

function drawEdgeLabel(e, ax, ay, cx, cy, bx, by, hot, color) {
  const text = edgeLabel(e);
  ctx.save();
  ctx.font = "11px Inter, system-ui, sans-serif";
  const x = qPoint(ax, cx, bx, .5);
  const y = qPoint(ay, cy, by, .5);
  const txv = qTangent(ax, cx, bx, .5);
  const tyv = qTangent(ay, cy, by, .5);
  const len = Math.max(1, Math.hypot(txv, tyv));
  const nx = -tyv / len;
  const ny = txv / len;
  const w = ctx.measureText(text).width + 18;
  const h = 22;
  const lx = x + nx * 14;
  const ly = y + ny * 14;
  ctx.translate(lx, ly);
  ctx.shadowBlur = 10;
  ctx.shadowColor = "rgba(0,0,0,.70)";
  ctx.fillStyle = "rgba(8,12,18,.96)";
  ctx.strokeStyle = hot ? hexA(color || "#ff5474", .80) : "rgba(105,168,255,.56)";
  ctx.lineWidth = 1.2;
  roundRect(-w / 2, -h / 2, w, h, 7);
  ctx.fill();
  ctx.shadowBlur = 0;
  ctx.stroke();
  ctx.fillStyle = hot ? "#fff2f4" : "#d5e7ff";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(text, 0, .5);
  ctx.restore();
}

function edgeLabel(e) {
  if (!e.rights || e.rights.length === 0) return "";
  const first = e.rights.slice(0, 2).map((r) => short(r, 14)).join(" / ");
  const rest = e.rights.length - 2;
  return rest > 0 ? `${first} +${rest}` : first;
}

function drawNode(n, activeNode, dim) {
  const [x, y] = screen(n.x, n.y);
  const r = n.r;
  const color = COLORS[n.type] || COLORS.Base;
  const hi = HILITE[n.type] || HILITE.Base;
  const dark = DARKS[n.type] || DARKS.Base;
  ctx.save();
  ctx.globalAlpha = dim ? .22 : 1;
  ctx.shadowBlur = dim ? 0 : activeNode ? 24 : 13;
  ctx.shadowColor = color;
  ctx.beginPath();
  ctx.arc(x, y, r + 7, 0, Math.PI * 2);
  ctx.fillStyle = activeNode ? "rgba(255,255,255,.10)" : "rgba(0,0,0,.34)";
  ctx.fill();
  ctx.shadowBlur = 0;
  const grad = ctx.createRadialGradient(x - r * .38, y - r * .48, 2, x, y, r + 5);
  grad.addColorStop(0, hi);
  grad.addColorStop(.38, color);
  grad.addColorStop(1, dark);
  ctx.beginPath();
  ctx.arc(x, y, r, 0, Math.PI * 2);
  ctx.fillStyle = grad;
  ctx.fill();
  ctx.strokeStyle = activeNode ? "#ffffff" : hi;
  ctx.lineWidth = activeNode ? 2.7 : 1.6;
  ctx.beginPath();
  ctx.arc(x, y, r, 0, Math.PI * 2);
  ctx.stroke();
  ctx.beginPath();
  ctx.arc(x, y, r - 4, 0, Math.PI * 2);
  ctx.strokeStyle = "rgba(255,255,255,.13)";
  ctx.lineWidth = 1;
  ctx.stroke();
  ctx.globalAlpha = dim ? .45 : 1;
  drawNodeIcon(n.type, x, y, r, n.type === "Group" ? "#151103" : "#061017");
  if (n.highValue) {
    ctx.strokeStyle = "#ffd45a";
    ctx.lineWidth = 2;
    roundRect(x - r - 5, y - r - 5, (r + 5) * 2, (r + 5) * 2, 9);
    ctx.stroke();
  }
  if (n.owned) {
    ctx.fillStyle = "#ff5474";
    ctx.beginPath();
    ctx.arc(x + r * .72, y - r * .72, 6, 0, Math.PI * 2);
    ctx.fill();
  }
  if (!dim && (scale > .88 || activeNode || n.highValue || n.owned || n.id === focusSid)) {
    ctx.font = "12px Inter, system-ui, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    const label = short(n.label, activeNode ? 38 : (view === "paths" ? 22 : 24));
    const [sx] = screen(n.x, n.y);
    const maxLabelWidth = Math.max(80, Math.min(210, innerWidth - Math.abs(sx - innerWidth / 2) * 0.18));
    ctx.lineWidth = 4;
    ctx.strokeStyle = "rgba(5,8,12,.86)";
    ctx.save();
    if (ctx.measureText(label).width > maxLabelWidth) ctx.font = "11px Inter, system-ui, sans-serif";
    ctx.strokeText(label, x, y + r + 7);
    ctx.fillStyle = "#eaf2ff";
    ctx.fillText(label, x, y + r + 7);
    ctx.restore();
  }
  ctx.restore();
}

function drawNodeIcon(type, x, y, r, ink) {
  ctx.save();
  ctx.strokeStyle = ink;
  ctx.fillStyle = ink;
  ctx.lineWidth = Math.max(1.6, r * .09);
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  if (type === "User") {
    ctx.beginPath(); ctx.arc(x, y - r * .22, r * .20, 0, Math.PI * 2); ctx.fill();
    ctx.beginPath(); ctx.arc(x, y + r * .30, r * .34, Math.PI, 0); ctx.stroke();
  } else if (type === "Group") {
    ctx.beginPath(); ctx.arc(x, y - r * .18, r * .17, 0, Math.PI * 2); ctx.fill();
    ctx.beginPath(); ctx.arc(x - r * .34, y + r * .02, r * .13, 0, Math.PI * 2); ctx.fill();
    ctx.beginPath(); ctx.arc(x + r * .34, y + r * .02, r * .13, 0, Math.PI * 2); ctx.fill();
    ctx.beginPath(); ctx.arc(x, y + r * .38, r * .38, Math.PI, 0); ctx.stroke();
  } else if (type === "Computer") {
    roundRect(x - r * .42, y - r * .32, r * .84, r * .52, 3); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(x - r * .20, y + r * .40); ctx.lineTo(x + r * .20, y + r * .40); ctx.moveTo(x, y + r * .20); ctx.lineTo(x, y + r * .40); ctx.stroke();
  } else if (type === "Domain") {
    ctx.beginPath(); ctx.arc(x, y, r * .42, 0, Math.PI * 2); ctx.stroke();
    ctx.beginPath(); ctx.ellipse(x, y, r * .18, r * .42, 0, 0, Math.PI * 2); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(x - r * .42, y); ctx.lineTo(x + r * .42, y); ctx.stroke();
  } else if (type === "GPO") {
    roundRect(x - r * .30, y - r * .42, r * .60, r * .78, 3); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(x - r * .16, y - r * .12); ctx.lineTo(x + r * .16, y - r * .12); ctx.moveTo(x - r * .16, y + r * .10); ctx.lineTo(x + r * .16, y + r * .10); ctx.stroke();
  } else if (type === "OU" || type === "Container") {
    ctx.beginPath(); ctx.moveTo(x - r * .42, y - r * .22); ctx.lineTo(x - r * .12, y - r * .22); ctx.lineTo(x, y - r * .06); ctx.lineTo(x + r * .42, y - r * .06); ctx.lineTo(x + r * .42, y + r * .34); ctx.lineTo(x - r * .42, y + r * .34); ctx.closePath(); ctx.stroke();
  } else {
    ctx.font = `${Math.max(12, r * .72)}px Inter, system-ui, sans-serif`; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText("?", x, y);
  }
  ctx.restore();
}

function roundRect(x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

function pick(px, py) {
  let best = -1, bd = Infinity;
  for (let i = graph.nodes.length - 1; i >= 0; i--) {
    const n = graph.nodes[i];
    const [x, y] = screen(n.x, n.y);
    const d = (px - x) ** 2 + (py - y) ** 2;
    const rr = (n.r + 8) ** 2;
    if (d < rr && d < bd) { best = i; bd = d; }
  }
  return best;
}

function pickEdge(px, py) {
  if (!graph.drawEdges?.length || graph.drawEdges.length > 900) return -1;
  let best = -1, bd = 16;
  graph.drawEdges.forEach((e, idx) => {
    const a = graph.nodes[e.source], b = graph.nodes[e.target];
    if (!a || !b) return;
    const [ax, ay] = screen(a.x, a.y);
    const [bx, by] = screen(b.x, b.y);
    const mx = (ax + bx) / 2, my = (ay + by) / 2;
    const dx = bx - ax, dy = by - ay;
    const cx = mx - dy * .16, cy = my + dx * .16;
    for (const t of [.25, .5, .75]) {
      const x = qPoint(ax, cx, bx, t);
      const y = qPoint(ay, cy, by, t);
      const d = Math.hypot(px - x, py - y);
      if (d < bd) { bd = d; best = idx; }
    }
  });
  return best;
}

function openPanel(idx) {
  selected = idx;
  requestDraw();
  const n = graph.nodes[idx];
  $("#panel").classList.add("open");
  $("#panelBody").innerHTML = `<div class="empty">Loading node...</div>`;
  api(`/api/domain/${active.id}/node/${encodeURIComponent(n.id)}`).then((detail) => {
    $("#panelBody").innerHTML = renderPanel(detail);
    $$(".copy").forEach((b) => b.addEventListener("click", () => copyText(b.dataset.cmd)));
    $(".owned-toggle")?.addEventListener("click", () => toggleOwned(detail.id));
    $$(".graph-rel").forEach((b) => b.addEventListener("click", () => focusGraph(detail.id, b.dataset.rel)));
    $$(".ptab").forEach((b) => b.addEventListener("click", () => switchPanelTab(b.dataset.tab)));
  }).catch((e) => $("#panelBody").innerHTML = `<div class="empty">${esc(e.message)}</div>`);
}

function switchPanelTab(tab) {
  $$(".ptab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $$(".tabpage").forEach((p) => p.classList.toggle("active", p.dataset.page === tab));
}

function closePanel() {
  selected = -1;
  $("#panel").classList.remove("open");
  requestDraw();
}

function renderPanel(n) {
  const out = n.outgoing || [];
  const inc = n.incoming || [];
  const props = Object.entries(n.props || {}).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && !v.length));
  const abuseOut = out.filter((e) => e.abusable);
  const abuseIn = inc.filter((e) => e.abusable);
  return `
    <div class="node-head">
      <div class="node-type">${esc(n.type)}</div>
      <div class="node-title">${esc(n.label)}</div>
      <div class="badges">
        ${n.highValue ? `<span class="badge hv">★ HIGH VALUE</span>` : ""}
        ${n.owned ? `<span class="badge owned">☠ OWNED</span>` : ""}
        <span class="badge">${out.length} outbound</span>
        <span class="badge">${inc.length} inbound</span>
        <span class="badge owned-toggle">${n.owned ? "unmark owned" : "mark owned"}</span>
      </div>
      <div class="graph-actions">
        <button class="graph-rel ${focusSid === n.id && relationMode === "abusable" ? "active" : ""}" data-rel="abusable"><b>Abusable</b><span>only exploitable edges</span></button>
        <button class="graph-rel ${focusSid === n.id && relationMode === "outbound" ? "active" : ""}" data-rel="outbound"><b>Outbound</b><span>what this controls</span></button>
        <button class="graph-rel ${focusSid === n.id && relationMode === "inbound" ? "active" : ""}" data-rel="inbound"><b>Inbound</b><span>who controls this</span></button>
        <button class="graph-rel ${focusSid === n.id && relationMode === "all" ? "active" : ""}" data-rel="all"><b>All links</b><span>full local context</span></button>
      </div>
    </div>
    <div class="panel-tabs">
      <button class="ptab active" data-tab="summary">Overview</button>
      <button class="ptab" data-tab="edges">Edges</button>
      <button class="ptab" data-tab="commands">Commands</button>
      <button class="ptab" data-tab="raw">Raw</button>
    </div>
    <section class="tabpage active" data-page="summary">
      <div class="metric-grid">
        <div><b>${out.length}</b><span>Outbound</span></div>
        <div><b>${inc.length}</b><span>Inbound</span></div>
        <div><b>${abuseOut.length}</b><span>Can abuse</span></div>
        <div><b>${abuseIn.length}</b><span>Can be abused</span></div>
      </div>
      <div class="section-title">Top properties</div>
      <div class="props">
        ${props.slice(0, 14).map(([k, v]) => `<div class="prop"><b>${esc(k)}</b><span>${esc(formatProp(v))}</span></div>`).join("") || `<div class="empty">No object properties were present in the import.</div>`}
      </div>
    </section>
    <section class="tabpage" data-page="edges">
      <div class="section-title">Abuse from this node</div>
      ${abuseOut.slice(0, 40).map(renderCompactEdge).join("") || `<div class="empty">No directly abusable outbound rights mapped.</div>`}
      <div class="section-title">Who can take this over</div>
      ${abuseIn.slice(0, 45).map((e) => renderCompactEdge(e, true)).join("") || `<div class="empty">No inbound takeover edges in the loaded view.</div>`}
      <div class="section-title">Other outbound connections</div>
      ${out.filter((e) => !e.abusable).slice(0, 45).map(renderCompactEdge).join("") || `<div class="empty">No other outbound connections.</div>`}
    </section>
    <section class="tabpage" data-page="commands">
      <div class="section-title">Commands generated from outbound abuse</div>
      ${abuseOut.slice(0, 30).map(renderAbuseEdge).join("") || `<div class="empty">No commands available for this object.</div>`}
    </section>
    <section class="tabpage" data-page="raw">
      <div class="section-title">All imported properties</div>
      <div class="props">
        ${props.slice(0, 100).map(([k, v]) => `<div class="prop"><b>${esc(k)}</b><span>${esc(formatProp(v))}</span></div>`).join("") || `<div class="empty">No raw properties.</div>`}
      </div>
    </section>
  `;
}

function renderCompactEdge(e, reverse = false) {
  const name = reverse ? e.sourceLabel : e.targetLabel;
  const type = reverse ? e.sourceType : e.targetType;
  const arrow = reverse ? "←" : "→";
  return `<div class="edge-row ${e.abusable ? "hot" : ""}"><div><b>${esc(e.right)}</b> ${arrow} ${esc(name)}</div><small>${esc(type || "")}</small></div>`;
}

function renderAbuseEdge(e) {
  return `
    <div class="edge-row">
      <div><b>${esc(e.right)}</b> → ${esc(e.targetLabel)}</div>
      <small>${esc(e.targetType)}</small>
      ${(e.abuse || []).map((a) => `
        <div class="cmd">
          <div class="cmd__head"><span><i class="os-badge ${esc(a.os)}">${esc(a.os)}</i> · ${esc(a.tool)}</span><button class="copy" data-cmd="${esc(a.cmd)}">copy</button></div>
          <pre>${colorCommand(a.cmd)}</pre>
        </div>
      `).join("")}
    </div>
  `;
}

function formatProp(v) {
  if (Array.isArray(v)) return v.map(formatProp).join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return `${v}`;
}

function colorCommand(cmd) {
  return esc(cmd)
    .replace(/(&lt;[^&]+&gt;)/g, `<span class="placeholder">$1</span>`)
    .replace(/('[^']*')/g, `<span class="quote">$1</span>`)
    .replace(/\b(--?[a-zA-Z0-9][a-zA-Z0-9-]*)/g, `<span class="flag">$1</span>`)
    .replace(/^([a-zA-Z0-9_.-]+)/, `<span class="tool">$1</span>`);
}

async function focusGraph(sid, rel) {
  focusSid = sid;
  relationMode = rel || relationMode;
  await loadGraph();
  const idx = nodeBySid.get(sid);
  if (idx != null) openPanel(idx);
}

async function toggleOwned(sid) {
  const data = await api(`/api/domain/${active.id}/owned/${encodeURIComponent(sid)}`, { method: "POST" });
  const idx = nodeBySid.get(sid);
  if (idx != null) graph.nodes[idx].owned = data.owned;
  toast(data.owned ? "Marked owned" : "Unmarked owned");
  openPanel(idx);
  requestDraw();
}

function copyText(text) {
  navigator.clipboard?.writeText(text);
  toast("Command copied");
}

canvas.addEventListener("mousedown", (ev) => {
  moved = false;
  const i = pick(ev.clientX, ev.clientY);
  if (i >= 0) dragging = i;
  else panning = true;
  last = [ev.clientX, ev.clientY];
  canvas.classList.add("grab");
});
addEventListener("mousemove", (ev) => {
  const dx = ev.clientX - last[0], dy = ev.clientY - last[1];
  if (Math.abs(dx) + Math.abs(dy) > 3) moved = true;
  if (dragging >= 0) {
    const [x, y] = world(ev.clientX, ev.clientY);
    graph.nodes[dragging].x = x;
    graph.nodes[dragging].y = y;
    graph.nodes[dragging].locked = true;
    requestDraw();
  } else if (panning) {
    tx += dx; ty += dy; requestDraw();
  } else {
    const i = pick(ev.clientX, ev.clientY);
    const ei = i >= 0 ? -1 : pickEdge(ev.clientX, ev.clientY);
    if (i !== hover || ei !== hoverEdge) {
      hover = i;
      hoverEdge = ei;
      updateHoverTip(ev.clientX, ev.clientY);
      requestDraw();
    } else {
      moveHoverTip(ev.clientX, ev.clientY);
    }
  }
  last = [ev.clientX, ev.clientY];
});

function updateHoverTip(x, y) {
  const tip = $("#hoverTip");
  if (!tip) return;
  if (hover >= 0) {
    const n = graph.nodes[hover];
    tip.innerHTML = `<b>${esc(n.label)}</b><small>${esc(n.type)} · ${n.degree || 0} edges${n.highValue ? " · high value" : ""}${n.owned ? " · owned" : ""}</small>`;
    tip.style.display = "block";
    setStatus(`${n.type}: ${n.label}`);
    moveHoverTip(x, y);
  } else if (hoverEdge >= 0) {
    const e = graph.drawEdges[hoverEdge];
    const src = graph.nodes[e.source], dst = graph.nodes[e.target];
    tip.innerHTML = `<b>${esc(edgeLabel(e))}</b><small>${esc(src?.label || "")} → ${esc(dst?.label || "")}${e.count > 1 ? ` · ${e.count} relations` : ""}</small>`;
    tip.style.display = "block";
    setStatus(`${src?.label || "source"} controls/relates to ${dst?.label || "target"} via ${edgeLabel(e)}`);
    moveHoverTip(x, y);
  } else {
    tip.style.display = "none";
    setStatus(graph.nodes.length ? "Drag canvas, zoom, or click a node." : "Search or choose a view to begin.");
  }
}

function moveHoverTip(x, y) {
  const tip = $("#hoverTip");
  if (!tip || tip.style.display === "none") return;
  tip.style.left = `${Math.min(innerWidth - 340, x + 14)}px`;
  tip.style.top = `${Math.min(innerHeight - 100, y + 14)}px`;
}
addEventListener("mouseup", () => {
  if (dragging >= 0 && !moved) openPanel(dragging);
  dragging = -1;
  panning = false;
  canvas.classList.remove("grab");
});
canvas.addEventListener("wheel", (ev) => {
  ev.preventDefault();
  const f = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
  const [wx, wy] = world(ev.clientX, ev.clientY);
  scale = Math.max(.12, Math.min(4.5, scale * f));
  tx = ev.clientX - wx * scale;
  ty = ev.clientY - wy * scale;
  requestDraw();
}, { passive: false });

$("#importForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const file = $("#zipInput").files[0];
  const st = $("#importStatus");
  if (!file) { st.textContent = "Choose a BloodHound zip first."; st.className = "status err"; return; }
  st.textContent = "Importing and indexing BloodHound data...";
  st.className = "status";
  const fd = new FormData();
  fd.append("zip", file);
  fd.append("name", $("#domainName").value.trim());
  try {
    const data = await api("/api/import", { method: "POST", body: fd });
    st.textContent = "Import complete.";
    st.className = "status ok";
    await loadDomains();
    openDomain(data.domainId);
  } catch (e) {
    st.textContent = e.message;
    st.className = "status err";
  }
});

$("#zipInput").addEventListener("change", () => {
  const f = $("#zipInput").files[0];
  if (f) $("#importStatus").textContent = f.name;
});
["dragenter", "dragover"].forEach((name) => $("#drop").addEventListener(name, (ev) => {
  ev.preventDefault();
  $("#drop").classList.add("drag");
}));
["dragleave", "drop"].forEach((name) => $("#drop").addEventListener(name, (ev) => {
  ev.preventDefault();
  $("#drop").classList.remove("drag");
}));
$("#drop").addEventListener("drop", (ev) => {
  const file = ev.dataTransfer.files[0];
  if (!file) return;
  const dt = new DataTransfer();
  dt.items.add(file);
  $("#zipInput").files = dt.files;
  $("#importStatus").textContent = file.name;
});

$("#refreshDomains").addEventListener("click", loadDomains);
$("#backBtn").addEventListener("click", () => {
  $("#app").classList.add("hidden");
  $("#welcome").classList.remove("hidden");
  $("#domainStats").innerHTML = "";
  active = null;
  clearGraph();
});
$("#closePanel").addEventListener("click", closePanel);
$("#fitBtn").addEventListener("click", () => { fitGraph(); requestDraw(); setStatus("Graph fitted to viewport."); });
$("#clearBtn").addEventListener("click", clearGraph);
$$(".view").forEach((b) => b.addEventListener("click", async () => {
  if (view === b.dataset.view && !focusSid) {
    clearGraph();
    return;
  }
  view = b.dataset.view;
  focusSid = "";
  $$(".view").forEach((x) => x.classList.toggle("active", x === b));
  await loadGraph();
}));


let searchTimer = 0;
$("#searchInput").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(runSearch, 160);
});
$("#searchInput").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") loadGraph($("#searchInput").value.trim());
  if (ev.key === "Escape") {
    $("#searchInput").value = "";
    $("#searchResults").classList.remove("show");
    clearGraph();
  }
});

async function runSearch() {
  const q = $("#searchInput").value.trim();
  const box = $("#searchResults");
  if (!active || q.length < 2) { box.classList.remove("show"); return; }
  const data = await api(`/api/domain/${active.id}/search?q=${encodeURIComponent(q)}`);
  box.innerHTML = (data.nodes || []).map((n) => `
    <div class="result" data-sid="${esc(n.id)}">
      <span class="dot ${n.type.toLowerCase()}"></span>
      <div>${n.owned ? "☠ " : ""}${n.highValue ? "★ " : ""}${esc(n.label)}</div>
      <small>${esc(n.type)}</small>
    </div>
  `).join("") || `<div class="empty" style="padding:12px">No results</div>`;
  box.classList.add("show");
  $$(".result").forEach((el) => el.addEventListener("mousedown", async (ev) => {
    ev.preventDefault();
    const sid = el.dataset.sid;
    await loadGraph(sid);
    const idx = nodeBySid.get(sid);
    if (idx != null) {
      const n = graph.nodes[idx];
      scale = Math.max(scale, 1.1);
      tx = innerWidth / 2 - n.x * scale;
      ty = innerHeight / 2 - n.y * scale;
      openPanel(idx);
    }
    box.classList.remove("show");
  }));
}

addEventListener("resize", resize);
loadDomains();
