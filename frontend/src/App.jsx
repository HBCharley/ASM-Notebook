import React, { useEffect, useMemo, useState } from "react";
import { api } from "./api.js";

const ADD_CUSTOMER_OPTION = "__add_customer__";

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function normalizeDomain(input) {
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split("/")[0]
    .replace(/\.$/, "");
}

function deriveCustomerFromDomain(domain) {
  const base = domain.split(".")[0] || "customer";
  const slugBase = base
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "") || "customer";
  return {
    slugBase,
  };
}

function ensureUniqueSlug(base, existingSlugs) {
  if (!existingSlugs.has(base)) return base;
  let n = 2;
  while (existingSlugs.has(`${base}-${n}`)) {
    n += 1;
  }
  return `${base}-${n}`;
}

function isInRootScope(domain, root) {
  return domain === root || domain.endsWith(`.${root}`);
}

function buildDnsIndex(records) {
  const idx = new Map();
  for (const rec of records || []) {
    if (rec && rec.domain) {
      idx.set(rec.domain, rec);
    }
  }
  return idx;
}

function suggestInitialZoom(totalDomains, rootCount, maxLabelCap) {
  const roots = Math.max(1, rootCount);
  if (totalDomains <= maxLabelCap) return 1.7;
  const minFocused = 8 * roots;
  const maxFocused = 15 * roots;
  if (maxLabelCap < minFocused) return 1.0;
  if (maxLabelCap <= maxFocused) {
    return Math.max(1.1, Math.min(1.54, maxLabelCap / (roots * 10)));
  }
  return 1.54;
}

function DomainRelationshipGraph({ artifacts }) {
  const [hoveredKey, setHoveredKey] = useState(null);
  const [selectedKey, setSelectedKey] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [maxLabelCap, setMaxLabelCap] = useState(36);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState(null);
  const [graphEl, setGraphEl] = useState(null);
  const graph = useMemo(() => {
    const roots = Array.from(new Set(artifacts?.domains?.roots || []));
    const allDomains = Array.from(
      new Set([...(artifacts?.domains?.domains || []), ...roots])
    );
    const dnsIndex = buildDnsIndex(artifacts?.dns?.records || []);

    if (!allDomains.length) {
      return null;
    }

    const width = 920;
    const height = 520;
    const cx = 320;
    const cy = 260;

    const rootAngles = new Map();
    roots.forEach((root, i) => {
      const angle = (Math.PI * 2 * i) / Math.max(roots.length, 1) - Math.PI / 2;
      rootAngles.set(root, angle);
    });

    const rootNodes = roots.map((root) => {
      const angle = rootAngles.get(root) ?? -Math.PI / 2;
      return {
        key: `root:${root}`,
        domain: root,
        kind: "root",
        x: cx + Math.cos(angle) * 78,
        y: cy + Math.sin(angle) * 78,
      };
    });

    const grouped = new Map();
    roots.forEach((r) => grouped.set(r, []));
    const unscoped = [];

    allDomains.forEach((domain) => {
      if (roots.includes(domain)) return;
      const parent = roots.find((r) => isInRootScope(domain, r));
      if (parent) {
        grouped.get(parent).push(domain);
      } else {
        unscoped.push(domain);
      }
    });

    const domainNodes = [];
    const edges = [];

    roots.forEach((root) => {
      const domains = grouped.get(root) || [];
      const rootNode = rootNodes.find((r) => r.domain === root);
      const rootBase = Math.atan2(
        (rootNode?.y ?? cy) - cy,
        (rootNode?.x ?? cx) - cx
      );
      const useFull360 = domains.length > 20; // >5 domains per 90 degrees

      domains.forEach((domain, idx) => {
        let angle;
        let radius;
        if (useFull360) {
          const golden = 2.399963229728653;
          angle = idx * golden;
          radius = 44 + 9 * Math.sqrt(idx + 1);
        } else {
          // Lower-density hubs use a constrained arc to keep local structure readable.
          const spread = Math.min(Math.PI * 1.25, Math.max(0.7, domains.length * 0.19));
          const t = domains.length <= 1 ? 0 : idx / (domains.length - 1) - 0.5;
          angle = rootBase + t * spread;
          radius = 52 + (idx % 4) * 14 + Math.floor(idx / 4) * 4;
        }
        const node = {
          key: `domain:${domain}`,
          domain,
          kind: "domain",
          root,
          x: (rootNode?.x ?? cx) + Math.cos(angle) * radius,
          y: (rootNode?.y ?? cy) + Math.sin(angle) * radius,
        };
        domainNodes.push(node);
        edges.push({
          key: `edge:${root}->${domain}`,
          from: root,
          to: domain,
        });
      });
    });

    unscoped.forEach((domain, idx) => {
      const angle = Math.PI / 3 + (idx / Math.max(unscoped.length, 1)) * (Math.PI / 1.5);
      const node = {
        key: `domain:${domain}`,
        domain,
        kind: "domain",
        root: null,
        x: cx + Math.cos(angle) * 250,
        y: cy + Math.sin(angle) * 250,
      };
      domainNodes.push(node);
    });

    const nodeMap = new Map(
      [...rootNodes, ...domainNodes].map((n) => [n.domain, n])
    );
    const hub = {
      key: "hub:scope",
      domain: "Scan Scope",
      kind: "hub",
      x: cx,
      y: cy,
    };

    const hubEdges = rootNodes.map((root) => ({
      key: `edge:hub->${root.domain}`,
      from: "Scan Scope",
      to: root.domain,
    }));

    const nodes = [hub, ...rootNodes, ...domainNodes].map((n) => {
      const rec = dnsIndex.get(n.domain);
      const totalRecords = rec
        ? ["A", "AAAA", "CNAME", "MX", "NS"].reduce(
            (sum, k) => sum + ((rec[k] || []).length || 0),
            0
          )
        : 0;
      return {
        ...n,
        dns: rec || null,
        totalRecords,
      };
    });

    return {
      width,
      height,
      nodes,
      edges: [...hubEdges, ...edges],
      nodeMap,
      counts: {
        roots: roots.length,
        domains: allDomains.length,
      },
    };
  }, [artifacts]);

  if (!graph) {
    return <div className="empty">No graphable domain artifacts for this scan</div>;
  }

  function clampZoom(value) {
    return Math.max(0.7, Math.min(4.2, +value.toFixed(2)));
  }

  useEffect(() => {
    if (!graphEl) return;
    const onWheel = (e) => {
      if (!e.ctrlKey) return;
      e.preventDefault();
      e.stopPropagation();
      const delta = e.deltaY > 0 ? -0.1 : 0.1;
      setZoom((z) => clampZoom(z + delta));
    };
    graphEl.addEventListener("wheel", onWheel, { passive: false });
    return () => {
      graphEl.removeEventListener("wheel", onWheel);
    };
  }, [graphEl]);

  function handleMouseDown(e) {
    setDragging(true);
    setDragStart({
      x: e.clientX - pan.x,
      y: e.clientY - pan.y,
    });
  }

  function handleMouseMove(e) {
    if (!dragging || !dragStart) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  }

  function handleMouseUp() {
    setDragging(false);
    setDragStart(null);
  }

  const hubNode = graph.nodes.find((n) => n.kind === "hub");
  const rootNodes = graph.nodes.filter((n) => n.kind === "root");
  const domainNodes = graph.nodes.filter((n) => n.kind === "domain");
  const detailMode = zoom < 1.1 ? "overview" : zoom < 1.55 ? "focused" : "full";

  useEffect(() => {
    const suggested = suggestInitialZoom(
      graph.counts.domains,
      graph.counts.roots,
      maxLabelCap
    );
    setZoom(suggested);
    setPan({ x: 0, y: 0 });
  }, [artifacts, maxLabelCap]);

  const domainsByRoot = new Map(rootNodes.map((r) => [r.domain, []]));
  for (const d of domainNodes) {
    if (d.root && domainsByRoot.has(d.root)) {
      domainsByRoot.get(d.root).push(d);
    }
  }
  for (const [root, list] of domainsByRoot) {
    list.sort((a, b) => a.domain.localeCompare(b.domain));
    domainsByRoot.set(root, list);
  }

  const renderNodes = [hubNode, ...rootNodes];
  const renderEdges = rootNodes.map((root) => ({
    key: `edge:${hubNode.key}->${root.key}`,
    fromKey: hubNode.key,
    toKey: root.key,
  }));

  if (detailMode === "full") {
    for (const d of domainNodes) {
      renderNodes.push(d);
      if (d.root) {
        renderEdges.push({
          key: `edge:root:${d.root}->${d.key}`,
          fromKey: `root:${d.root}`,
          toKey: d.key,
        });
      }
    }
  } else if (detailMode === "focused") {
    const maxPerRoot = Math.max(8, Math.round(zoom * 10));
    for (const root of rootNodes) {
      const visible = (domainsByRoot.get(root.domain) || []).slice(0, maxPerRoot);
      for (const d of visible) {
        renderNodes.push(d);
        renderEdges.push({
          key: `edge:root:${root.domain}->${d.key}`,
          fromKey: root.key,
          toKey: d.key,
        });
      }
    }
  } else {
    for (const root of rootNodes) {
      const count = (domainsByRoot.get(root.domain) || []).length;
      if (!count) continue;
      const dx = root.x - hubNode.x;
      const dy = root.y - hubNode.y;
      const mag = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const agg = {
        key: `aggregate:${root.domain}`,
        domain: `+${count} domains`,
        kind: "aggregate",
        root: root.domain,
        count,
        x: root.x + (dx / mag) * 55,
        y: root.y + (dy / mag) * 55,
        dns: null,
        totalRecords: 0,
      };
      renderNodes.push(agg);
      renderEdges.push({
        key: `edge:${root.key}->${agg.key}`,
        fromKey: root.key,
        toKey: agg.key,
      });
    }
  }

  const renderNodeMap = new Map(renderNodes.map((n) => [n.key, n]));
  const selectedGlobalNode =
    graph.nodes.find((n) => n.key === selectedKey) ||
    (selectedKey?.startsWith("aggregate:")
      ? { kind: "aggregate", root: selectedKey.replace("aggregate:", "") }
      : null);
  const focusedRoot =
    selectedGlobalNode?.kind === "root"
      ? selectedGlobalNode.domain
      : selectedGlobalNode?.root || null;
  const focusRootNode = focusedRoot
    ? renderNodes.find((n) => n.kind === "root" && n.domain === focusedRoot)
    : null;

  const spreadFactor =
    focusRootNode && zoom > 1.2 ? 1 + Math.min(2.4, (zoom - 1.2) * 1.0) : 1;
  const clusterOffsets = new Map();
  if (focusRootNode && spreadFactor > 1) {
    for (const root of rootNodes) {
      if (root.domain === focusedRoot) {
        clusterOffsets.set(root.domain, { x: 0, y: 0 });
        continue;
      }
      const dx = root.x - focusRootNode.x;
      const dy = root.y - focusRootNode.y;
      const mag = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const push = (spreadFactor - 1) * 90;
      clusterOffsets.set(root.domain, {
        x: (dx / mag) * push,
        y: (dy / mag) * push,
      });
    }
  }

  const displayNodes = renderNodes.map((n) => {
    if (!focusRootNode || spreadFactor === 1) return n;
    if (n.kind === "hub") return n;
    const clusterRoot =
      n.kind === "root" ? n.domain : n.root;
    if (!clusterRoot || clusterRoot === focusedRoot) return n;
    const off = clusterOffsets.get(clusterRoot);
    if (!off) return n;
    return {
      ...n,
      x: n.x + off.x,
      y: n.y + off.y,
    };
  });
  const displayNodeMap = new Map(displayNodes.map((n) => [n.key, n]));

  const outgoing = new Map();
  for (const edge of renderEdges) {
    if (!outgoing.has(edge.fromKey)) outgoing.set(edge.fromKey, []);
    const toNode = displayNodeMap.get(edge.toKey);
    if (toNode) outgoing.get(edge.fromKey).push(toNode);
  }
  const fixedLabelCount = displayNodes.filter((n) => n.kind !== "domain").length;
  const labelBudget = Math.max(0, maxLabelCap - fixedLabelCount);
  const budgetedDomainLabels = new Set(
    displayNodes
      .filter((n) => n.kind === "domain")
      .sort(
        (a, b) =>
          (b.totalRecords || 0) - (a.totalRecords || 0) ||
          a.domain.localeCompare(b.domain)
      )
      .slice(0, labelBudget)
      .map((n) => n.key)
  );
  const selectedNode =
    (selectedKey && displayNodeMap.get(selectedKey)) ||
    graph.nodes.find((n) => n.key === selectedKey) ||
    null;
  const hoveredNode =
    selectedNode || displayNodeMap.get(hoveredKey) || hubNode;

  function focusNode(node, targetZoom = Math.max(zoom, 2.1)) {
    const z = clampZoom(Math.max(targetZoom, 2.5));
    setZoom(z);
    setPan({
      x: -z * (node.x - graph.width / 2),
      y: -z * (node.y - graph.height / 2),
    });
    setSelectedKey(node.key);
  }

  return (
    <div className="graph-wrap">
      <div className="graph-meta muted">
        {graph.counts.roots} roots · {graph.counts.domains} domains · mode: {detailMode} · labels: {maxLabelCap}
      </div>
      <div className="graph-grid">
        <div className="graph-canvas">
          <svg
            ref={setGraphEl}
            className={`domain-graph ${dragging ? "dragging" : ""}`}
            viewBox={`0 0 ${graph.width} ${graph.height}`}
            role="img"
            aria-label="Domain relationship graph"
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
          >
            <g
              transform={`translate(${pan.x} ${pan.y}) translate(${graph.width / 2} ${graph.height / 2}) scale(${zoom}) translate(${-graph.width / 2} ${-graph.height / 2})`}
            >
              {renderEdges.map((e) => {
                const from = displayNodeMap.get(e.fromKey);
                const to = displayNodeMap.get(e.toKey);
                if (!from || !to) return null;
                return (
                  <line
                    key={e.key}
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    className="graph-edge"
                  />
                );
              })}

              {displayNodes.map((node) => (
                <g
                  key={node.key}
                  className={`graph-node graph-node-${node.kind}`}
                  onMouseEnter={() => setHoveredKey(node.key)}
                  onMouseLeave={() => setHoveredKey(null)}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedKey(node.key);
                  }}
                >
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={
                      node.kind === "hub"
                        ? 6.5
                        : node.kind === "root"
                          ? 3.75
                          : node.kind === "aggregate"
                            ? 3.1
                            : 2.75
                    }
                  />
                  {node.kind !== "domain" ||
                  budgetedDomainLabels.has(node.key) ||
                  node.key === hoveredKey ||
                  node.key === selectedKey ? (
                    <text
                      x={node.x}
                      y={node.y + (node.kind === "hub" ? 42 : 27)}
                      fontSize={Math.max(4.5, 10 / Math.pow(Math.max(1, zoom), 1.8))}
                    >
                      {node.domain}
                    </text>
                  ) : null}
                </g>
              ))}
            </g>
          </svg>
          <div className="graph-help-bug">Ctrl + Scroll to zoom</div>
        </div>

        <div className="graph-hover panel">
          <div className="graph-controls">
            <button className="ghost" onClick={() => setZoom((z) => clampZoom(z - 0.15))}>
              -
            </button>
            <span className="muted">{Math.round(zoom * 100)}%</span>
            <button className="ghost" onClick={() => setZoom((z) => clampZoom(z + 0.2))}>
              +
            </button>
            <button
              className="ghost"
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
              }}
            >
              Reset
            </button>
            {selectedNode ? (
              <button className="ghost" onClick={() => setSelectedKey(null)}>
                Unpin
              </button>
            ) : null}
          </div>
          <div className="graph-cap">
            <span className="muted">Max labels</span>
            <input
              type="range"
              min="12"
              max="120"
              step="4"
              value={maxLabelCap}
              onChange={(e) => setMaxLabelCap(Number(e.target.value))}
            />
            <span className="muted">{maxLabelCap}</span>
          </div>
          <h3>{hoveredNode?.domain || "Details"}</h3>
          {selectedNode ? <div className="muted">Pinned selection</div> : null}
          <div className="muted">
            Type: {hoveredNode?.kind || "unknown"}
            {hoveredNode?.root ? ` · Root: ${hoveredNode.root}` : ""}
          </div>
          {hoveredNode && (hoveredNode.kind === "hub" || hoveredNode.kind === "root") ? (
            <div className="spoke-list">
              <div className="muted">
                Spokes ({(outgoing.get(hoveredNode.key) || []).length})
              </div>
              <div className="spoke-items">
                {(outgoing.get(hoveredNode.key) || []).slice(0, 60).map((node) => (
                  <button
                    key={`spoke-${hoveredNode.key}-${node.key}`}
                    className="ghost spoke-btn"
                    onClick={() => focusNode(node)}
                  >
                    {node.domain}
                  </button>
                ))}
                {(outgoing.get(hoveredNode.key) || []).length > 60 ? (
                  <div className="muted">
                    +{(outgoing.get(hoveredNode.key) || []).length - 60} more
                  </div>
                ) : null}
              </div>
            </div>
          ) : null}
          {hoveredNode?.kind === "aggregate" ? (
            <div className="muted">
              {hoveredNode.count} domains hidden at this zoom level. Zoom in to expand.
            </div>
          ) : null}
          {hoveredNode?.kind === "domain" || hoveredNode?.kind === "root" ? (
            <>
              <div className="graph-kv">
                <span>DNS Records</span>
                <span>{hoveredNode.totalRecords || 0}</span>
              </div>
              {hoveredNode?.dns ? (
                <div className="graph-records">
                  {["A", "AAAA", "CNAME", "MX", "NS"].map((k) => (
                    <div key={k} className="graph-record-row">
                      <span>{k}</span>
                      <span>{(hoveredNode.dns[k] || []).length}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="muted">No DNS artifact for this node.</div>
              )}
            </>
          ) : (
            <div className="muted">
              Center hub for the scan scope. Hover domains for details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [companies, setCompanies] = useState([]);
  const [selectedCustomer, setSelectedCustomer] = useState(ADD_CUSTOMER_OPTION);
  const [activeCompany, setActiveCompany] = useState(null);
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [artifacts, setArtifacts] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [theme, setTheme] = useState("light");

  const [newCustomerName, setNewCustomerName] = useState("");
  const [newCustomerDomain, setNewCustomerDomain] = useState("");
  const [addDomainInput, setAddDomainInput] = useState("");
  const [renameInput, setRenameInput] = useState("");
  const [scanInFlight, setScanInFlight] = useState(false);

  const activeScan = useMemo(
    () => scans.find((s) => s.id === selectedScanId),
    [scans, selectedScanId]
  );
  const hasRunningScan = useMemo(
    () => scans.some((s) => s.status === "running"),
    [scans]
  );
  const scanBlocked = scanInFlight || hasRunningScan;

  async function loadCompanies() {
    const data = await api.listCompanies();
    setCompanies(data);

    if (
      selectedCustomer !== ADD_CUSTOMER_OPTION &&
      !data.some((c) => c.slug === selectedCustomer)
    ) {
      setSelectedCustomer(ADD_CUSTOMER_OPTION);
      setActiveCompany(null);
      setScans([]);
      setSelectedScanId(null);
      setArtifacts(null);
    }
  }

  async function loadCompany(slug) {
    const [company, scanList] = await Promise.all([
      api.getCompany(slug),
      api.listScans(slug),
    ]);
    setActiveCompany(company);
    setScans(scanList);
    setAddDomainInput("");
    setRenameInput(company.name);
  }

  async function loadArtifacts(slug, scanId) {
    const data = await api.getArtifacts(slug, scanId);
    setArtifacts(data);
  }

  async function startScan(slug) {
    if (scanBlocked) {
      throw new Error("A scan is already running. Wait for it to finish.");
    }
    setScanInFlight(true);
    try {
      const result = await api.runScan(slug);
      await loadCompany(slug);
      if (result?.scan_id) {
        setSelectedScanId(result.scan_id);
        await loadArtifacts(slug, result.scan_id);
      }
    } finally {
      setScanInFlight(false);
    }
  }

  async function handleSelectCustomer(option) {
    setSelectedCustomer(option);
    setSelectedScanId(null);
    setArtifacts(null);
  }

  async function runWithStatus(fn) {
    setLoading(true);
    setError("");
    try {
      await fn();
    } catch (err) {
      setError(err.message || "Request failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    runWithStatus(loadCompanies);
  }, []);

  useEffect(() => {
    if (selectedCustomer === ADD_CUSTOMER_OPTION) {
      setActiveCompany(null);
      setScans([]);
      return;
    }
    runWithStatus(() => loadCompany(selectedCustomer));
  }, [selectedCustomer]);

  return (
    <div className={`app theme-${theme}`}>
      <header className="topbar">
        <div className="brand">
          <div className="brand-title">ASM Notebook</div>
          <div className="brand-sub">
            Passive attack surface inventory and scan history
          </div>
        </div>
        <div className="status">
          <button
            className="ghost"
            onClick={() => setTheme((t) => (t === "light" ? "dark" : "light"))}
          >
            {theme === "light" ? "Dark mode" : "Light mode"}
          </button>
          <span className={loading ? "dot pulse" : "dot"} />
          {loading ? "Syncing" : "Idle"}
        </div>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <div className="panel-header">
            <h2>Customers</h2>
            <button
              className="ghost"
              onClick={() => runWithStatus(loadCompanies)}
            >
              Refresh
            </button>
          </div>

          <div className="form">
            <label>
              Customer
              <select
                value={selectedCustomer}
                onChange={(e) => handleSelectCustomer(e.target.value)}
              >
                <option value={ADD_CUSTOMER_OPTION}>Add Customer</option>
                {companies.map((c) => (
                  <option key={c.slug} value={c.slug}>
                    {c.name} ({c.slug})
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="divider" />

          {selectedCustomer === ADD_CUSTOMER_OPTION ? (
            <div className="form">
              <div className="panel-header">
                <h2>Add customer</h2>
              </div>
              <label>
                Customer name
                <input
                  value={newCustomerName}
                  onChange={(e) => setNewCustomerName(e.target.value)}
                  placeholder="Acme Corp"
                />
              </label>
              <label>
                Domain
                <input
                  value={newCustomerDomain}
                  onChange={(e) => setNewCustomerDomain(e.target.value)}
                  placeholder="example.com"
                />
              </label>
              <button
                onClick={() =>
                  runWithStatus(async () => {
                    const name = newCustomerName.trim();
                    const domain = normalizeDomain(newCustomerDomain);
                    if (!name) throw new Error("Customer name is required");
                    if (!domain) throw new Error("Domain is required");
                    const customer = deriveCustomerFromDomain(domain);
                    const existingSlugs = new Set(
                      companies.map((c) => (c.slug || "").toLowerCase())
                    );
                    const uniqueSlug = ensureUniqueSlug(
                      customer.slugBase,
                      existingSlugs
                    );
                    const created = await api.createCompany({
                      slug: uniqueSlug,
                      name,
                      domains: [domain],
                    });
                    setNewCustomerName("");
                    setNewCustomerDomain("");
                    await loadCompanies();
                    setSelectedCustomer(created.slug);
                  })
                }
              >
                Create customer
              </button>
            </div>
          ) : (
            <div className="form">
              <div className="panel-header">
                <h2>Domains</h2>
              </div>
              <div className="domain-list">
                {activeCompany?.domains?.length ? (
                  activeCompany.domains.map((domain) => (
                    <div key={domain} className="domain-item">
                      {domain}
                    </div>
                  ))
                ) : (
                  <div className="empty">No domains configured</div>
                )}
              </div>
              <label>
                Add domain
                <input
                  value={addDomainInput}
                  onChange={(e) => setAddDomainInput(e.target.value)}
                  placeholder="new.example.com"
                />
              </label>
              <button
                onClick={() =>
                  runWithStatus(async () => {
                    if (!activeCompany) return;
                    const nextDomain = normalizeDomain(addDomainInput);
                    if (!nextDomain) throw new Error("Domain is required");
                    const domains = Array.from(
                      new Set([...activeCompany.domains, nextDomain])
                    );
                    await api.replaceDomains(activeCompany.slug, domains);
                    await loadCompany(activeCompany.slug);
                  })
                }
              >
                Add domain
              </button>
            </div>
          )}
        </aside>

        <main className="content">
          {!activeCompany ? (
            <div className="empty-state">
              <h2>Add or select a customer</h2>
              <p>
                Choose an existing customer from the dropdown or create one with
                a domain.
              </p>
            </div>
          ) : (
            <>
              <section className="card">
                <div className="card-header">
                  <div>
                    <h1>{activeCompany.name}</h1>
                    <div className="muted">
                      {activeCompany.slug} · {activeCompany.domains.length} domains
                    </div>
                  </div>
                  <div className="actions">
                    <button
                      disabled={scanBlocked}
                      onClick={() =>
                        runWithStatus(async () => {
                          await startScan(activeCompany.slug);
                        })
                      }
                    >
                      Start scan
                    </button>
                    <button
                      className="danger"
                      onClick={() =>
                        runWithStatus(async () => {
                          if (
                            !confirm(
                              `Delete company '${activeCompany.slug}' and all scans?`
                            )
                          ) {
                            return;
                          }
                          await api.deleteCompany(activeCompany.slug);
                          setSelectedCustomer(ADD_CUSTOMER_OPTION);
                          setActiveCompany(null);
                          setScans([]);
                          setArtifacts(null);
                          await loadCompanies();
                        })
                      }
                    >
                      Delete company
                    </button>
                  </div>
                </div>

                {scanBlocked ? (
                  <div className="scan-progress">
                    <div className="scan-progress-title">Scan in progress</div>
                    <div className="scan-progress-bar">
                      <span className="scan-progress-fill" />
                    </div>
                    <div className="muted">
                      Starting a new scan is disabled until completion.
                    </div>
                  </div>
                ) : null}

                <div className="grid">
                  <div className="panel">
                    <h3>Rename customer</h3>
                    <div className="row">
                      <input
                        value={renameInput}
                        onChange={(e) => setRenameInput(e.target.value)}
                      />
                      <button
                        onClick={() =>
                          runWithStatus(async () => {
                            await api.updateCompany(activeCompany.slug, {
                              name: renameInput,
                            });
                            await loadCompany(activeCompany.slug);
                          })
                        }
                      >
                        Save
                      </button>
                    </div>
                  </div>

                  <div className="panel">
                    <h3>Domains</h3>
                    <div className="domain-list">
                      {activeCompany.domains.map((domain) => (
                        <div key={domain} className="domain-item">
                          {domain}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </section>

              <section className="card">
                <div className="card-header">
                  <div>
                    <h2>Scans</h2>
                    <div className="muted">
                      {scans.length} total · newest first
                    </div>
                  </div>
                  <div className="actions">
                    <button
                      disabled={scanBlocked}
                      onClick={() =>
                        runWithStatus(async () => {
                          await startScan(activeCompany.slug);
                        })
                      }
                    >
                      Start scan
                    </button>
                    <button
                      className="ghost"
                      onClick={() =>
                        runWithStatus(async () => {
                          const latest = await api.latestScan(activeCompany.slug);
                          setSelectedScanId(latest.id);
                          await loadArtifacts(activeCompany.slug, latest.id);
                        })
                      }
                    >
                      Load latest
                    </button>
                  </div>
                </div>

                <div className="scan-list">
                  {scans.length === 0 ? (
                    <div className="empty empty-with-action">
                      <span>No scans yet</span>
                      <button
                        disabled={scanBlocked}
                        onClick={() =>
                          runWithStatus(async () => {
                            await startScan(activeCompany.slug);
                          })
                        }
                      >
                        Start first scan
                      </button>
                    </div>
                  ) : (
                    scans.map((scan) => (
                      <div
                        key={scan.id}
                        className={
                          scan.id === selectedScanId ? "scan active" : "scan"
                        }
                      >
                        <div className="scan-main">
                          <div className="scan-title">
                            #{scan.company_scan_number} · id {scan.id}
                          </div>
                          <div className="scan-meta">
                            {scan.status} · started {formatDate(scan.started_at)}
                          </div>
                        </div>
                        <div className="scan-actions">
                          <button
                            className="ghost"
                            onClick={() =>
                              runWithStatus(async () => {
                                setSelectedScanId(scan.id);
                                await loadArtifacts(activeCompany.slug, scan.id);
                              })
                            }
                          >
                            View
                          </button>
                          <button
                            className="danger ghost"
                            onClick={() =>
                              runWithStatus(async () => {
                                if (
                                  !confirm(
                                    `Delete scan id ${scan.id} for ${activeCompany.slug}?`
                                  )
                                ) {
                                  return;
                                }
                                await api.deleteScan(activeCompany.slug, scan.id);
                                setSelectedScanId(null);
                                setArtifacts(null);
                                await loadCompany(activeCompany.slug);
                              })
                            }
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>

              <section className="card">
                <div className="card-header">
                  <div>
                    <h2>Artifacts</h2>
                    <div className="muted">
                      {activeScan
                        ? `Scan #${activeScan.company_scan_number} (id ${activeScan.id})`
                        : "Select a scan to view artifacts"}
                    </div>
                  </div>
                </div>
                {!artifacts ? (
                  <div className="empty">No artifacts loaded</div>
                ) : (
                  <>
                    <DomainRelationshipGraph artifacts={artifacts} />
                    <details>
                      <summary className="muted">Raw JSON artifacts</summary>
                      <pre className="code">
                        {JSON.stringify(artifacts, null, 2)}
                      </pre>
                    </details>
                  </>
                )}
              </section>
            </>
          )}

          {error ? <div className="toast">{error}</div> : null}
        </main>
      </div>
    </div>
  );
}
