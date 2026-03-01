import React, { useEffect, useMemo, useRef, useState } from "react";
import { api, setAuthToken } from "./api.js";
import logoLight from "./assets/logo-light.png";
import logoDark from "./assets/logo-dark.png";
import ExecutiveDashboard from "./components/dashboard/ExecutiveDashboard.jsx";
import SocDashboard from "./components/dashboard/SocDashboard.jsx";
import ViewModeSwitcher from "./components/ViewModeSwitcher.jsx";
import {
  classifySeverity,
  filterFindings,
  countFindingsBySeverity,
} from "./lib/cveSeverity.js";

const ADD_CUSTOMER_OPTION = "__add_customer__";
const USER_STORAGE_KEY = "asm.users";
const GROUP_STORAGE_KEY = "asm.groups";
const ACTIVE_USER_KEY = "asm.user.active";
const COMPANY_GROUP_KEY = "asm.company.groups";
const USER_THEME_KEY = "asm.user.theme";
const UI_MODE_KEY = "asm_ui_mode";
const NEW_GROUP_OPTION = "__new_group__";
const MIN_CVE_SEVERITY_KEY = "asm_settings_min_cve_severity";
const AUTH_TOKEN_KEY = "asm_auth_id_token";

function readStoredJson(key, fallback) {
  if (typeof window === "undefined") return fallback;
  const raw = window.localStorage.getItem(key);
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
}

function writeStoredJson(key, value) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(key, JSON.stringify(value));
}

function getThemeForUser(userId) {
  const map = readStoredJson(USER_THEME_KEY, {});
  if (userId && map[userId]) return map[userId];
  return map.__guest || "light";
}

function setThemeForUser(userId, theme) {
  const map = readStoredJson(USER_THEME_KEY, {});
  const key = userId || "__guest";
  const next = { ...map, [key]: theme };
  writeStoredJson(USER_THEME_KEY, next);
}

function normalizeUiMode(value) {
  if (value === "executive") return "executive";
  if (value === "soc") return "soc";
  return "standard";
}


function makeId(prefix = "id") {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return `${prefix}-${crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function formatDuration(start, end) {
  if (!start || !end) return "-";
  const startDate = new Date(start);
  const endDate = new Date(end);
  const ms = endDate.getTime() - startDate.getTime();
  if (!Number.isFinite(ms) || ms < 0) return "-";
  const totalSeconds = Math.round(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

function formatScanMode(mode) {
  if (!mode) return "";
  return mode === "deep" ? "Deep scan" : "Standard scan";
}

function parseScanProgress(scan) {
  if (!scan) {
    return null;
  }
  const notes = (scan.notes || "").trim();
  const status = (scan.status || "").toLowerCase();
  const m = notes.match(/^(\d+)\s*\/\s*(\d+)\s*(.*)$/);
  if (m) {
    const step = Number(m[1]);
    const total = Number(m[2]);
    const message = (m[3] || "").trim();
    if (Number.isFinite(step) && Number.isFinite(total) && total > 0) {
      let percent = Math.round((step / total) * 100);
      if (status === "running") {
        percent = Math.min(percent, 98);
      }
      percent = Math.max(0, Math.min(100, percent));
      return {
        percent,
        message: message || notes,
        indeterminate: false,
      };
    }
  }
  if (status === "success") {
    return {
      percent: 100,
      message: notes || "Scan complete",
      indeterminate: false,
    };
  }
  if (status === "running") {
    return {
      percent: 20,
      message: notes || "Running scan...",
      indeterminate: true,
    };
  }
  return null;
}

function getScanTimestamp(scan) {
  const candidate = scan.completed_at || scan.started_at || "";
  if (!candidate) return 0;
  const ts = new Date(candidate).getTime();
  return Number.isFinite(ts) ? ts : 0;
}

function getLatestCompleteScan(scans) {
  const completed = scans.filter(
    (scan) => (scan.status || "").toLowerCase() === "success"
  );
  if (!completed.length) return null;
  return completed.reduce((latest, scan) => {
    const latestTs = getScanTimestamp(latest);
    const currentTs = getScanTimestamp(scan);
    if (currentTs === latestTs) {
      return scan.id > latest.id ? scan : latest;
    }
    return currentTs > latestTs ? scan : latest;
  });
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

function formatCertEntity(entity) {
  if (!entity) return "-";
  if (Array.isArray(entity)) {
    return entity
      .map((entry) =>
        Array.isArray(entry)
          ? entry.map((pair) => `${pair[0]}=${pair[1]}`).join(", ")
          : String(entry)
      )
      .join(" / ");
  }
  if (typeof entity === "object") {
    return Object.entries(entity)
      .map(([k, v]) => `${k}=${v}`)
      .join(", ");
  }
  return String(entity);
}

function DomainRelationshipGraph({ artifacts, maxLabelCap = 36, minCveSeverity }) {
  const [hoveredKey, setHoveredKey] = useState(null);
  const [selectedKey, setSelectedKey] = useState(null);
  const [treeOpen, setTreeOpen] = useState(false);
  const [hideUnreachable, setHideUnreachable] = useState(false);
  const [graphSourceOpen, setGraphSourceOpen] = useState(false);
  const [graphSourceKey, setGraphSourceKey] = useState("intel");
  const [expandedRoots, setExpandedRoots] = useState({});
  const [domainFilter, setDomainFilter] = useState("");
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const panTargetRef = useRef({ x: 0, y: 0 });
  const zoomTargetRef = useRef(1);
  const animatingRef = useRef(false);
  const zoomRef = useRef(1);
  const panRef = useRef({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState(null);
  const [graphEl, setGraphEl] = useState(null);
  useEffect(() => {
    zoomRef.current = zoom;
  }, [zoom]);

  useEffect(() => {
    panRef.current = pan;
  }, [pan]);

  function startAnimation() {
    if (animatingRef.current) return;
    animatingRef.current = true;
    const step = () => {
      const targetZoom = zoomTargetRef.current;
      const targetPan = panTargetRef.current;
      setZoom((z) => {
        const next = z + (targetZoom - z) * 0.18;
        return Math.abs(targetZoom - next) < 0.01 ? targetZoom : next;
      });
      setPan((p) => {
        const nx = p.x + (targetPan.x - p.x) * 0.2;
        const ny = p.y + (targetPan.y - p.y) * 0.2;
        const done =
          Math.abs(targetPan.x - nx) < 0.5 && Math.abs(targetPan.y - ny) < 0.5;
        return done ? targetPan : { x: nx, y: ny };
      });

      const zoomDone = Math.abs(zoomTargetRef.current - zoomRef.current) < 0.01;
      const panDone =
        Math.abs(panTargetRef.current.x - panRef.current.x) < 0.5 &&
        Math.abs(panTargetRef.current.y - panRef.current.y) < 0.5;
      if (zoomDone && panDone) {
        animatingRef.current = false;
        return;
      }
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  function setZoomTarget(value) {
    zoomTargetRef.current = clampZoom(value);
    startAnimation();
  }

  function setPanTarget(next) {
    panTargetRef.current = next;
    startAnimation();
  }
  const intelByDomain = useMemo(
    () =>
      new Map(
        (artifacts?.dns_intel?.domains || []).map((row) => [row.domain, row])
      ),
    [artifacts]
  );
  const unreachableDomains = useMemo(
    () =>
      new Set(
        (artifacts?.dns_intel?.domains || [])
          .filter((row) => row?.domain && !row?.web?.reachable)
          .map((row) => row.domain)
      ),
    [artifacts]
  );
  const graph = useMemo(() => {
    const unreachableRootLabel = "Unreachable";
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
        isUnreachableBucket: false,
        x: cx + Math.cos(angle) * 78,
        y: cy + Math.sin(angle) * 78,
      };
    });

    const grouped = new Map();
    roots.forEach((r) => grouped.set(r, []));
    const unscoped = [];
    const unreachable = [];

    allDomains.forEach((domain) => {
      if (roots.includes(domain)) return;
      if (hideUnreachable && unreachableDomains.has(domain)) {
        unreachable.push(domain);
        return;
      }
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
          radius = 70 + 16 * Math.sqrt(idx + 1);
        } else {
          // Lower-density hubs use a constrained arc to keep local structure readable.
          const spread = Math.min(Math.PI * 1.25, Math.max(0.7, domains.length * 0.19));
          const t = domains.length <= 1 ? 0 : idx / (domains.length - 1) - 0.5;
          angle = rootBase + t * spread;
          radius = 64 + (idx % 5) * 18 + Math.floor(idx / 5) * 6;
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

    if (hideUnreachable && unreachable.length) {
      const unreachableRoot = {
        key: `root:${unreachableRootLabel}`,
        domain: unreachableRootLabel,
        kind: "root",
        isUnreachableBucket: true,
        x: cx + 236,
        y: cy,
      };
      rootNodes.push(unreachableRoot);
      unreachable.sort((a, b) => a.localeCompare(b));
      unreachable.forEach((domain, idx) => {
        const base = (Math.PI * 2 * idx) / Math.max(unreachable.length, 1) - Math.PI / 2;
        const radius = 52 + (idx % 4) * 14 + Math.floor(idx / 4) * 5;
        const node = {
          key: `domain:${domain}`,
          domain,
          kind: "domain",
          root: unreachableRootLabel,
          x: unreachableRoot.x + Math.cos(base) * radius,
          y: unreachableRoot.y + Math.sin(base) * radius,
          unreachable: true,
        };
        domainNodes.push(node);
        edges.push({
          key: `edge:${unreachableRootLabel}->${domain}`,
          from: unreachableRootLabel,
          to: domain,
        });
      });
    }

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
        unreachable: hideUnreachable ? unreachable.length : 0,
      },
    };
  }, [artifacts, hideUnreachable, unreachableDomains]);

  function clampZoom(value) {
    return Math.max(0.7, Math.min(4.2, +value.toFixed(2)));
  }

  const graphNodes = graph?.nodes ?? [];
  const graphCounts = graph?.counts ?? { roots: 0, domains: 0, unreachable: 0 };
  const graphWidth = graph?.width ?? 920;
  const graphHeight = graph?.height ?? 520;
  const hubNode = graph ? graphNodes.find((n) => n.kind === "hub") : null;
  const rootNodes = graph ? graphNodes.filter((n) => n.kind === "root") : [];
  const domainNodes = graph ? graphNodes.filter((n) => n.kind === "domain") : [];
  const detailMode =
    graphCounts.domains <= maxLabelCap
      ? "full"
      : zoom < 1.1
        ? "overview"
        : zoom < 1.55
          ? "focused"
          : "full";

  useEffect(() => {
    if (!graphEl) return;
    const onWheel = (e) => {
      if (!e.ctrlKey) return;
      e.preventDefault();
      e.stopPropagation();
      const delta = e.deltaY > 0 ? -0.1 : 0.1;
      setZoomTarget(zoomTargetRef.current + delta);
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
    setPanTarget({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  }

  function handleMouseUp() {
    setDragging(false);
    setDragStart(null);
  }

  useEffect(() => {
    if (!graph) return;
    const suggested = suggestInitialZoom(
      graphCounts.domains,
      graphCounts.roots,
      maxLabelCap
    );
    zoomTargetRef.current = suggested;
    panTargetRef.current = { x: 0, y: 0 };
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
  const unscopedDomains = domainNodes
    .filter((d) => !d.root)
    .slice()
    .sort((a, b) => a.domain.localeCompare(b.domain));
  const sortedRoots = rootNodes
    .slice()
    .sort((a, b) => a.domain.localeCompare(b.domain));
  const scopedRoots = sortedRoots.filter((r) => !r.isUnreachableBucket);
  const unreachableRootNode = sortedRoots.find((r) => r.isUnreachableBucket) || null;

  const renderNodes = hubNode ? [hubNode, ...rootNodes] : [...rootNodes];
  const renderEdges = hubNode
    ? rootNodes.map((root) => ({
        key: `edge:${hubNode.key}->${root.key}`,
        fromKey: hubNode.key,
        toKey: root.key,
      }))
    : [];

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
    graphNodes.find((n) => n.key === selectedKey) ||
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

  const hideNonFocusedDomains = Boolean(focusRootNode && zoom >= 2.2);
  const displayNodesBase = renderNodes.map((n) => {
    if (!focusRootNode || spreadFactor === 1) return n;
    if (n.kind === "hub") return n;
    const clusterRoot =
      n.kind === "root" ? n.domain : n.root;
    if (!clusterRoot || clusterRoot === focusedRoot) return n;
    if (hideNonFocusedDomains && n.kind === "domain") {
      return {
        ...n,
        hidden: true,
      };
    }
    const off = clusterOffsets.get(clusterRoot);
    if (!off) return n;
    return {
      ...n,
      x: n.x + off.x,
      y: n.y + off.y,
    };
  });
  const shouldSpreadAllDomains =
    selectedGlobalNode?.kind === "hub" || (!selectedGlobalNode && zoom > 2.4);
  const shouldSpreadFocusedRootDomains = Boolean(focusedRoot);
  const localSpread =
    zoom > 1.8 ? 1 + Math.min(1.6, (zoom - 1.8) * 0.65) : 1;
  const rootMapBase = new Map(
    displayNodesBase
      .filter((n) => n.kind === "root")
      .map((n) => [n.domain, n])
  );
  const displayNodes = displayNodesBase.map((n) => {
    if (n.kind !== "domain" || n.hidden || localSpread === 1) return n;
    if (shouldSpreadFocusedRootDomains && n.root !== focusedRoot) return n;
    if (!shouldSpreadFocusedRootDomains && !shouldSpreadAllDomains) return n;
    const rootNode = rootMapBase.get(n.root);
    if (!rootNode) return n;
    const dx = n.x - rootNode.x;
    const dy = n.y - rootNode.y;
    return {
      ...n,
      x: rootNode.x + dx * localSpread,
      y: rootNode.y + dy * localSpread,
    };
  });

  function applyForceLayout(nodes) {
    if (detailMode === "overview") return nodes;
    const result = nodes.map((n) => ({ ...n }));
    const indexByKey = new Map(result.map((n, i) => [n.key, i]));
    const rootPositions = new Map(
      result
        .filter((n) => n.kind === "root")
        .map((n) => [n.domain, { x: n.x, y: n.y }])
    );
    const domainsByRoot = new Map();
    const targetMap = new Map();
    for (const node of result) {
      if (node.kind !== "domain" || node.hidden || !node.root) continue;
      if (!domainsByRoot.has(node.root)) domainsByRoot.set(node.root, []);
      domainsByRoot.get(node.root).push(node.key);
    }
    for (const [root, keys] of domainsByRoot) {
      const rootPos = rootPositions.get(root);
      if (!rootPos) continue;
      const total = keys.length;
      const baseRadius = 90 + Math.sqrt(total) * 8;
      const spacing = 22;
      keys.forEach((key, idx) => {
        const node = result[indexByKey.get(key)];
        const angle = Math.atan2(node.y - rootPos.y, node.x - rootPos.x);
        const radius = baseRadius + spacing * Math.sqrt(idx + 1);
        targetMap.set(key, {
          x: rootPos.x + Math.cos(angle) * radius,
          y: rootPos.y + Math.sin(angle) * radius,
        });
      });
    }
    const repelRadius = 38 + zoom * 7;
    const repelRadiusSq = repelRadius * repelRadius;
    const spring = 0.01;
    const damp = 0.86;
    const step = 0.18;
    const iterations = 48;
    for (const [root, keys] of domainsByRoot) {
      const rootPos = rootPositions.get(root);
      if (!rootPos || keys.length < 2) continue;
      const velocities = new Map(keys.map((k) => [k, { x: 0, y: 0 }]));
      for (let iter = 0; iter < iterations; iter += 1) {
        for (let i = 0; i < keys.length; i += 1) {
          const ki = keys[i];
          const ni = result[indexByKey.get(ki)];
          let fx = 0;
          let fy = 0;
          for (let j = 0; j < keys.length; j += 1) {
            if (i === j) continue;
            const kj = keys[j];
            const nj = result[indexByKey.get(kj)];
            const dx = ni.x - nj.x;
            const dy = ni.y - nj.y;
            const distSq = dx * dx + dy * dy;
            if (distSq > 0 && distSq < repelRadiusSq) {
              const dist = Math.sqrt(distSq);
              const force = (repelRadius - dist) / repelRadius;
              fx += (dx / dist) * force * 2.8;
              fy += (dy / dist) * force * 2.8;
            }
          }
          const target = targetMap.get(ki);
          if (target) {
            fx += (target.x - ni.x) * spring;
            fy += (target.y - ni.y) * spring;
          } else {
            const dxr = rootPos.x - ni.x;
            const dyr = rootPos.y - ni.y;
            fx += dxr * spring;
            fy += dyr * spring;
          }
          const v = velocities.get(ki);
          v.x = (v.x + fx * step) * damp;
          v.y = (v.y + fy * step) * damp;
        }
        for (const key of keys) {
          const n = result[indexByKey.get(key)];
          const v = velocities.get(key);
          n.x += v.x;
          n.y += v.y;
        }
      }
    }
    return result;
  }

  const forceNodes = applyForceLayout(displayNodes);
  const visibleNodes = forceNodes.filter((n) => !n.hidden);
  const displayNodeMap = new Map(visibleNodes.map((n) => [n.key, n]));

  const outgoing = new Map();
  for (const edge of renderEdges) {
    if (!outgoing.has(edge.fromKey)) outgoing.set(edge.fromKey, []);
    const toNode = displayNodeMap.get(edge.toKey);
    if (toNode) outgoing.get(edge.fromKey).push(toNode);
  }
  const fixedLabelCount = visibleNodes.filter((n) => n.kind !== "domain").length;
  const labelBudget = Math.max(0, maxLabelCap - fixedLabelCount);
  const budgetedDomainLabels = new Set(
    visibleNodes
      .filter((n) => n.kind === "domain")
      .sort(
        (a, b) =>
          (b.totalRecords || 0) - (a.totalRecords || 0) ||
          a.domain.localeCompare(b.domain)
      )
      .slice(0, labelBudget)
      .map((n) => n.key)
  );
  const labelFontSize = Math.max(4.2, 10 / Math.pow(Math.max(1, zoom), 1.9));
  const shouldShowLabel = (node) =>
    node.kind !== "domain" ||
    budgetedDomainLabels.has(node.key);
  const labelPositions = (() => {
    const placed = [];
    const map = new Map();
    const options = [
      [8, 1],
      [14, 8],
      [14, -8],
      [20, 12],
      [20, -12],
      [0, 16],
      [0, -16],
      [28, 0],
      [-12, 0],
    ];
    const candidates = [
      ...visibleNodes.filter((n) => n.kind !== "domain"),
      ...visibleNodes
        .filter((n) => n.kind === "domain" && budgetedDomainLabels.has(n.key))
        .sort(
          (a, b) =>
            (b.totalRecords || 0) - (a.totalRecords || 0) ||
            a.domain.localeCompare(b.domain)
        ),
    ];
    for (const node of candidates) {
      if (!shouldShowLabel(node)) continue;
      const label = node.domain || "";
      const width = Math.max(10, label.length * labelFontSize * 0.58);
      const height = labelFontSize + 3;
      let placedBox = null;
      for (const [ox, oy] of options) {
        const x = node.x + ox;
        const y = node.y + oy;
        const box = { x, y: y - height / 2, w: width, h: height };
        const collides = placed.some(
          (p) =>
            box.x < p.x + p.w &&
            box.x + box.w > p.x &&
            box.y < p.y + p.h &&
            box.y + box.h > p.y
        );
        if (!collides) {
          placedBox = box;
          map.set(node.key, { x, y, hidden: false });
          placed.push(box);
          break;
        }
      }
    }
    return map;
  })();
  const selectedNode =
    (selectedKey && displayNodeMap.get(selectedKey)) ||
    graphNodes.find((n) => n.key === selectedKey) ||
    null;
  const hoveredNode =
    selectedNode || displayNodeMap.get(hoveredKey) || hubNode;
  const dnsSummary = artifacts?.dns?.summary || null;
  const intelSummary = artifacts?.dns_intel?.summary || null;
  const allDomains = artifacts?.domains?.domains || [];
  const domainList = useMemo(() => {
    const list = allDomains.filter((d) => {
      if (focusedRoot && !isInRootScope(d, focusedRoot)) return false;
      if (!domainFilter) return true;
      return d.includes(domainFilter.trim().toLowerCase());
    });
    return list.sort((a, b) => a.localeCompare(b));
  }, [allDomains, focusedRoot, domainFilter]);
  const nodeIntel = hoveredNode?.domain ? intelByDomain.get(hoveredNode.domain) : null;
  const ptrValues = hoveredNode?.dns?.PTR
    ? Object.values(hoveredNode.dns.PTR).flat().filter(Boolean)
    : [];
  const graphSourceOptions = useMemo(() => {
    if (!hoveredNode) return [];
    const options = [];
    if (nodeIntel) options.push({ key: "intel", label: "Intel" });
    if (hoveredNode.dns) options.push({ key: "dns", label: "DNS" });
    if (nodeIntel?.web) options.push({ key: "web", label: "Web" });
    return options;
  }, [hoveredNode, nodeIntel]);
  const graphSourcePayload =
    graphSourceKey === "dns"
      ? hoveredNode?.dns
      : graphSourceKey === "web"
        ? nodeIntel?.web
        : nodeIntel;
  useEffect(() => {
    if (!graphSourceOptions.length) {
      setGraphSourceOpen(false);
      setGraphSourceKey("intel");
      return;
    }
    if (!graphSourceOptions.some((opt) => opt.key === graphSourceKey)) {
      setGraphSourceKey(graphSourceOptions[0].key);
    }
  }, [graphSourceOptions, graphSourceKey]);
  const securityHeaderKeys = nodeIntel?.web?.security_headers
    ? Object.keys(nodeIntel.web.security_headers)
    : [];
  const fingerprints = nodeIntel?.web?.fingerprints || [];
  const reportedVersions = nodeIntel?.web?.reported_versions || [];
  const technologies = nodeIntel?.web?.technologies || [];
  const hsts = nodeIntel?.web?.hsts || null;
  const tls = nodeIntel?.web?.tls || null;
  const ipAsn = nodeIntel?.ip_asn || [];
  const edgeProvider = nodeIntel?.web?.edge_provider || null;
  const cloudStorage = nodeIntel?.web?.cloud_storage || null;
  const deepScan = nodeIntel?.web?.deep_scan || null;
  const mailProviders = nodeIntel?.mail_providers || [];
  const exposureScore = nodeIntel?.exposure_score ?? null;
  const exposureFactors = nodeIntel?.exposure_factors || [];
  const cveFindings = nodeIntel?.cve_findings || [];
  const visibleCveFindings = filterFindings(cveFindings, minCveSeverity);
  const cveCounts = countFindingsBySeverity(visibleCveFindings);
  const certNotBefore =
    tls?.cert?.not_before ||
    tls?.cert?.notBefore ||
    tls?.cert?.valid_from ||
    tls?.cert?.validFrom ||
    "";
  const certNotAfter =
    tls?.cert?.not_after ||
    tls?.cert?.notAfter ||
    tls?.cert?.valid_until ||
    tls?.cert?.validUntil ||
    "";

  function focusNode(node, targetZoom = Math.max(zoom, 2.1)) {
    const z = clampZoom(Math.max(targetZoom, 2.5));
    setZoomTarget(z);
    setPanTarget({
      x: -z * (node.x - graphWidth / 2),
      y: -z * (node.y - graphHeight / 2),
    });
    setSelectedKey(node.key);
  }

  function toggleRoot(rootDomain) {
    setExpandedRoots((prev) => ({
      ...prev,
      [rootDomain]: !prev[rootDomain],
    }));
  }

  function selectFromTree(node) {
    setHoveredKey(node.key);
    if (node.kind === "domain" || node.kind === "root") {
      focusNode(node, node.kind === "domain" ? 2.5 : 2.1);
      return;
    }
    setSelectedKey(node.key);
    setPanTarget({ x: 0, y: 0 });
    setZoomTarget(1.3);
  }

  useEffect(() => {
    const nextExpanded = {};
    scopedRoots.slice(0, 2).forEach((root) => {
      nextExpanded[root.domain] = true;
    });
    if (unreachableRootNode) {
      nextExpanded[unreachableRootNode.domain] = true;
    }
    setExpandedRoots(nextExpanded);
  }, [artifacts, hideUnreachable]);

  if (!graph || !hubNode) {
    return <div className="empty">No graphable domain artifacts for this scan</div>;
  }

  return (
    <div className="graph-wrap">
      <div className="graph-meta muted">
        {graphCounts.roots} roots · {graphCounts.domains} domains · mode: {detailMode} · labels: {maxLabelCap}
        {hideUnreachable ? ` · unreachable bucket: ${graphCounts.unreachable}` : ""}
      </div>
      <div className="graph-grid">
        <div className="graph-canvas">
          <button
            className={`graph-nav-bug ${treeOpen ? "active" : ""}`}
            onClick={() => setTreeOpen((v) => !v)}
            aria-pressed={treeOpen}
          >
            {treeOpen ? "Hide tree" : "Tree view"}
          </button>
          {treeOpen ? (
            <div className="graph-tree panel">
              <div className="graph-tree-head">
                <strong>Scope Browser</strong>
                <span className="muted">
                  {graphCounts.roots} roots · {graphCounts.domains} domains
                </span>
              </div>
              <button
                className={`tree-item tree-item-hub ${selectedKey === hubNode.key ? "active" : ""}`}
                onClick={() => selectFromTree(hubNode)}
              >
                Scan Scope
              </button>
              <div className="tree-section muted">Roots</div>
              {scopedRoots.map((root) => {
                const rootDomains = domainsByRoot.get(root.domain) || [];
                const isOpen = !!expandedRoots[root.domain];
                return (
                  <div key={`tree-root-${root.domain}`} className="tree-branch">
                    <button
                      className={`tree-item tree-item-root ${selectedKey === root.key ? "active" : ""}`}
                      onClick={() => {
                        toggleRoot(root.domain);
                        selectFromTree(root);
                      }}
                    >
                      <span>{isOpen ? "▾" : "▸"} {root.domain}</span>
                      <span className="tree-count">{rootDomains.length}</span>
                    </button>
                    {isOpen ? (
                      <div className="tree-children">
                        {rootDomains.map((domainNode) => {
                          const domainIntel = intelByDomain.get(domainNode.domain);
                          return (
                            <button
                              key={`tree-domain-${domainNode.domain}`}
                              className={`tree-item tree-item-domain ${selectedKey === domainNode.key ? "active" : ""}`}
                              onClick={() => selectFromTree(domainNode)}
                            >
                              <span className="tree-domain-name">{domainNode.domain}</span>
                              <span className="tree-domain-props">
                                {domainIntel?.resolves ? "DNS" : "No DNS"}
                                {domainIntel?.web?.reachable ? ` · HTTP ${domainIntel.web.status_code ?? "-"}` : ""}
                              </span>
                            </button>
                          );
                        })}
                        {rootDomains.length === 0 ? (
                          <div className="muted tree-empty">No discovered domains</div>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                );
              })}
              {unreachableRootNode ? (
                <>
                  <div className="tree-section muted">Unreachable</div>
                  <div className="tree-branch">
                    <button
                      className={`tree-item tree-item-root tree-item-unreachable ${selectedKey === unreachableRootNode.key ? "active" : ""}`}
                      onClick={() => {
                        toggleRoot(unreachableRootNode.domain);
                        selectFromTree(unreachableRootNode);
                      }}
                    >
                      <span>
                        {!!expandedRoots[unreachableRootNode.domain] ? "▾" : "▸"} {unreachableRootNode.domain}
                      </span>
                      <span className="tree-count">
                        {(domainsByRoot.get(unreachableRootNode.domain) || []).length}
                      </span>
                    </button>
                    {!!expandedRoots[unreachableRootNode.domain] ? (
                      <div className="tree-children">
                        {(domainsByRoot.get(unreachableRootNode.domain) || []).map((domainNode) => {
                          const domainIntel = intelByDomain.get(domainNode.domain);
                          return (
                            <button
                              key={`tree-unreachable-${domainNode.domain}`}
                              className={`tree-item tree-item-domain ${selectedKey === domainNode.key ? "active" : ""}`}
                              onClick={() => selectFromTree(domainNode)}
                            >
                              <span className="tree-domain-name">{domainNode.domain}</span>
                              <span className="tree-domain-props">
                                {domainIntel?.resolves ? "DNS" : "No DNS"}
                                {domainIntel?.web?.reachable ? ` · HTTP ${domainIntel.web.status_code ?? "-"}` : " · unreachable"}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    ) : null}
                  </div>
                </>
              ) : null}
              {unscopedDomains.length ? (
                <>
                  <div className="tree-section muted">Unscoped</div>
                  <div className="tree-children">
                    {unscopedDomains.map((domainNode) => {
                      const domainIntel = intelByDomain.get(domainNode.domain);
                      return (
                        <button
                          key={`tree-unscoped-${domainNode.domain}`}
                          className={`tree-item tree-item-domain ${selectedKey === domainNode.key ? "active" : ""}`}
                          onClick={() => selectFromTree(domainNode)}
                        >
                          <span className="tree-domain-name">{domainNode.domain}</span>
                          <span className="tree-domain-props">
                            {domainIntel?.resolves ? "DNS" : "No DNS"}
                            {domainIntel?.web?.reachable ? ` · HTTP ${domainIntel.web.status_code ?? "-"}` : ""}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </>
              ) : null}
            </div>
          ) : null}
          <svg
            ref={setGraphEl}
            className={`domain-graph ${dragging ? "dragging" : ""}`}
            viewBox={`0 0 ${graphWidth} ${graphHeight}`}
            role="img"
            aria-label="Domain relationship graph"
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
          >
            <g
              transform={`translate(${pan.x} ${pan.y}) translate(${graphWidth / 2} ${graphHeight / 2}) scale(${zoom}) translate(${-graphWidth / 2} ${-graphHeight / 2})`}
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

              {visibleNodes.map((node) => (
                <g
                  key={node.key}
                  className={`graph-node graph-node-${node.kind} ${node.unreachable || node.isUnreachableBucket ? "graph-node-unreachable" : ""}`.trim()}
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
                        ? 8.125
                        : node.kind === "root"
                          ? 4.6875
                          : node.kind === "aggregate"
                            ? 3.875
                            : 3.4375
                    }
                  />
                  {labelPositions.has(node.key) ||
                  node.key === hoveredKey ||
                  node.key === selectedKey ? (
                    <text
                      className="graph-label"
                      x={(labelPositions.get(node.key)?.x ?? node.x + 8)}
                      y={(labelPositions.get(node.key)?.y ?? node.y + 1)}
                      fontSize={labelFontSize}
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

        <div className={`graph-hover panel ${selectedNode ? "floating overlay" : ""}`}>
          {selectedNode ? (
            <div className="graph-hover-head">
              <div>
                <div className="muted">Details</div>
                <div className="graph-hover-title">
                  {hoveredNode?.domain || "Selection"}
                </div>
              </div>
              <div className="graph-hover-actions">
                <button
                  className="ghost"
                  onClick={() => setGraphSourceOpen((prev) => !prev)}
                  disabled={!graphSourceOptions.length}
                >
                  {graphSourceOpen ? "Hide source" : "Show source"}
                </button>
                <button className="ghost" onClick={() => setSelectedKey(null)}>
                  Close
                </button>
              </div>
            </div>
          ) : null}
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
            <label className="graph-toggle muted">
              <input
                type="checkbox"
                checked={hideUnreachable}
                onChange={(e) => setHideUnreachable(e.target.checked)}
              />
              Hide unreachable
            </label>
          </div>
          {!selectedNode ? <h3>{hoveredNode?.domain || "Details"}</h3> : null}
          {selectedNode ? <div className="muted">Pinned selection</div> : null}
          <div className="muted">
            Type: {hoveredNode?.kind || "unknown"}
            {hoveredNode?.root ? ` · Root: ${hoveredNode.root}` : ""}
          </div>
          {graphSourceOpen ? (
            <div className="graph-source">
              <div className="graph-source-head">
                <div className="muted">Source</div>
                <select
                  value={graphSourceKey}
                  onChange={(e) => setGraphSourceKey(e.target.value)}
                >
                  {graphSourceOptions.map((opt) => (
                    <option key={opt.key} value={opt.key}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
              <pre className="code">
                {graphSourcePayload ? JSON.stringify(graphSourcePayload, null, 2) : ""}
              </pre>
            </div>
          ) : null}
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
          {hoveredNode?.kind === "hub" && dnsSummary ? (
            <div className="graph-summary">
              <div className="graph-record-row">
                <span>Scanned domains</span>
                <span>{dnsSummary.scanned_domains ?? 0}</span>
              </div>
              <div className="graph-record-row">
                <span>Resolved domains</span>
                <span>{dnsSummary.resolved_domains ?? 0}</span>
              </div>
              <div className="graph-record-row">
                <span>Unique IPs</span>
                <span>{dnsSummary.unique_ip_count ?? 0}</span>
              </div>
            </div>
          ) : null}
          {hoveredNode?.kind === "hub" && intelSummary ? (
            <div className="graph-summary">
              <div className="graph-record-row">
                <span>Mail-enabled</span>
                <span>{intelSummary.mail_enabled_domains ?? 0}</span>
              </div>
              <div className="graph-record-row">
                <span>SPF</span>
                <span>{intelSummary.spf_domains ?? 0}</span>
              </div>
              <div className="graph-record-row">
                <span>DMARC</span>
                <span>{intelSummary.dmarc_domains ?? 0}</span>
              </div>
              <div className="graph-record-row">
                <span>IPv6 domains</span>
                <span>{intelSummary.ipv6_domains ?? 0}</span>
              </div>
            </div>
          ) : null}
          {(hoveredNode?.kind === "hub" || hoveredNode?.kind === "root") && domainList.length ? (
            <details className="graph-details" open>
              <summary>
                Discovered domains ({domainList.length}
                {focusedRoot ? ` in ${focusedRoot}` : ""})
              </summary>
              <input
                className="domain-filter"
                placeholder="Filter domains..."
                value={domainFilter}
                onChange={(e) => setDomainFilter(e.target.value.toLowerCase())}
              />
              <div className="graph-domain-list">
                {domainList.slice(0, 200).map((d) => (
                  <div key={`dl-${d}`} className="graph-domain-item">
                    {d}
                  </div>
                ))}
                {domainList.length > 200 ? (
                  <div className="muted">+{domainList.length - 200} more</div>
                ) : null}
              </div>
            </details>
          ) : null}
          {hoveredNode?.kind === "aggregate" ? (
            <div className="muted">
              {hoveredNode.count} domains hidden at this zoom level. Zoom in to expand.
            </div>
          ) : null}
          {hoveredNode?.kind === "domain" || hoveredNode?.kind === "root" ? (
            <>
              {nodeIntel ? (
                <div className="graph-summary">
                  <div className="graph-record-row">
                    <span>Resolves</span>
                    <span>{nodeIntel.resolves ? "yes" : "no"}</span>
                  </div>
                  <div className="graph-record-row">
                    <span>Root</span>
                    <span>{nodeIntel.root || "-"}</span>
                  </div>
                  <div className="graph-record-row">
                    <span>Depth</span>
                    <span>{nodeIntel.label_depth}</span>
                  </div>
                  <div className="graph-record-row">
                    <span>MX / SPF / DMARC</span>
                    <span>
                      {nodeIntel.has_mx ? "MX" : "-"} / {nodeIntel.has_spf ? "SPF" : "-"} /{" "}
                      {nodeIntel.has_dmarc ? "DMARC" : "-"}
                    </span>
                  </div>
                  <div className="graph-record-row">
                    <span>SPF records</span>
                    <span>
                      {nodeIntel.spf_txt_records ?? 0}
                      {nodeIntel.spf_multiple ? " (multiple)" : ""}
                    </span>
                  </div>
                  <div className="graph-record-row">
                    <span>DMARC policy</span>
                    <span>{nodeIntel.dmarc_policy || "-"}</span>
                  </div>
                  <div className="graph-record-row">
                    <span>Email security score</span>
                    <span>{nodeIntel.email_security_score ?? 0} / 10</span>
                  </div>
                  {mailProviders.length ? (
                    <div className="graph-record-row">
                      <span>Mail providers</span>
                      <span>{mailProviders.join(", ")}</span>
                    </div>
                  ) : null}
                  <div className="graph-record-row">
                    <span>Dangling CNAME</span>
                    <span>{nodeIntel.dangling_cname ? "possible" : "no"}</span>
                  </div>
                  <div className="graph-record-row">
                    <span>Takeover risk</span>
                    <span>{nodeIntel.takeover_risk ? "possible" : "no"}</span>
                  </div>
                  {nodeIntel.takeover_targets?.length ? (
                    <div className="graph-record-row">
                      <span>Takeover targets</span>
                      <span>{nodeIntel.takeover_targets.join(", ")}</span>
                    </div>
                  ) : null}
                  <div className="graph-record-row">
                    <span>Surface class</span>
                    <span>{nodeIntel.surface_class || "web"}</span>
                  </div>
                  <div className="graph-record-row">
                    <span>Root wildcard</span>
                    <span>{nodeIntel.root_wildcard ? "yes" : "no"}</span>
                  </div>
                  <div className="graph-record-row">
                    <span>CDN / Proxy</span>
                    <span>
                      {edgeProvider?.provider
                        ? `${edgeProvider.provider} (${edgeProvider.confidence || "low"})`
                        : nodeIntel.web?.is_cdn_or_proxy
                          ? nodeIntel.web?.cdn_or_proxy_provider || "yes"
                          : "no"}
                      {edgeProvider?.asn_provider
                        ? ` · ASN: ${edgeProvider.asn_provider}`
                        : ""}
                    </span>
                  </div>
                  {edgeProvider?.signals?.length || edgeProvider?.asn_signals?.length ? (
                    <details className="graph-details">
                      <summary>Edge signals</summary>
                      <div className="graph-chip-list">
                        {(edgeProvider.signals || []).map((sig) => (
                          <span key={`edge-sig-${hoveredNode.key}-${sig}`} className="graph-chip">
                            {sig}
                          </span>
                        ))}
                        {(edgeProvider.asn_signals || []).map((sig) => (
                          <span
                            key={`edge-asn-${hoveredNode.key}-${sig}`}
                            className="graph-chip"
                          >
                            {sig}
                          </span>
                        ))}
                      </div>
                    </details>
                  ) : null}
                  <div className="graph-record-row">
                    <span>HTTP</span>
                    <span>
                      {nodeIntel.web?.reachable
                        ? `${nodeIntel.web?.scheme?.toUpperCase() || "HTTP"} ${nodeIntel.web?.status_code ?? ""}`.trim()
                        : "unreachable"}
                    </span>
                  </div>
                  <div className="graph-record-row">
                    <span>Web Server</span>
                    <span>
                      {nodeIntel.web?.server_version_hint ||
                        nodeIntel.web?.server_header ||
                        "-"}
                    </span>
                  </div>
                  {nodeIntel.web?.title ? (
                    <div className="graph-record-row">
                      <span>Title</span>
                      <span>{nodeIntel.web.title}</span>
                    </div>
                  ) : null}
                  {cloudStorage && cloudStorage.provider ? (
                    <div className="graph-record-row">
                      <span>Cloud storage</span>
                      <span>
                        {cloudStorage.provider}
                        {cloudStorage.listing_detected ? " (listing)" : ""}
                        {cloudStorage.error_hint ? ` (${cloudStorage.error_hint})` : ""}
                      </span>
                    </div>
                  ) : null}
                  {exposureScore !== null ? (
                    <div className="graph-record-row">
                      <span>Exposure score</span>
                      <span>{exposureScore} / 10</span>
                    </div>
                  ) : null}
                  {deepScan?.enabled ? (
                    <details className="graph-details">
                      <summary>Deep scan</summary>
                      <div className="graph-records">
                        <div className="graph-record-row">
                          <span>favicon.ico</span>
                          <span>
                            {deepScan.favicon?.status_code ?? "-"}
                            {deepScan.favicon?.response_ms !== undefined
                              ? ` · ${deepScan.favicon.response_ms}ms`
                              : ""}
                          </span>
                        </div>
                        <div className="graph-record-row">
                          <span>robots.txt</span>
                          <span>
                            {deepScan.robots?.status_code ?? "-"}
                            {deepScan.robots?.response_ms !== undefined
                              ? ` · ${deepScan.robots.response_ms}ms`
                              : ""}
                          </span>
                        </div>
                        <div className="graph-record-row">
                          <span>sitemap.xml</span>
                          <span>
                            {deepScan.sitemap?.status_code ?? "-"}
                            {deepScan.sitemap?.response_ms !== undefined
                              ? ` · ${deepScan.sitemap.response_ms}ms`
                              : ""}
                          </span>
                        </div>
                        {deepScan.favicon?.hash_mmh3 ? (
                          <div className="graph-record-row">
                            <span>Favicon hash</span>
                            <span>
                              {deepScan.favicon.hash_mmh3}
                              {deepScan.favicon.hash_fingerprint
                                ? ` · ${deepScan.favicon.hash_fingerprint}`
                                : ""}
                            </span>
                          </div>
                        ) : null}
                      </div>
                    </details>
                  ) : null}
                  {securityHeaderKeys.length ? (
                    <details className="graph-details">
                      <summary>Security headers</summary>
                      <div className="graph-chip-list">
                        {securityHeaderKeys.map((k) => (
                          <span key={`sec-${hoveredNode.key}-${k}`} className="graph-chip">
                            {k}
                          </span>
                        ))}
                      </div>
                    </details>
                  ) : null}
                  {hsts && hsts.header ? (
                    <details className="graph-details">
                      <summary>HSTS</summary>
                      <div className="graph-record-row">
                        <span>Max-age</span>
                        <span>{hsts.max_age ?? "-"}</span>
                      </div>
                      <div className="graph-record-row">
                        <span>IncludeSubDomains</span>
                        <span>{hsts.include_subdomains ? "yes" : "no"}</span>
                      </div>
                      <div className="graph-record-row">
                        <span>Preload</span>
                        <span>{hsts.preload_directive ? "yes" : "no"}</span>
                      </div>
                      <div className="graph-record-row">
                        <span>Preload eligible</span>
                        <span>{hsts.preload_eligible ? "yes" : "no"}</span>
                      </div>
                    </details>
                  ) : null}
                  {tls && (tls.protocol || tls.cert) ? (
                    <details className="graph-details">
                      <summary>TLS certificate</summary>
                      <div className="graph-record-row">
                        <span>Protocol</span>
                        <span>{tls.protocol || "-"}</span>
                      </div>
                      <div className="graph-record-row">
                        <span>Cipher</span>
                        <span>{tls.cipher || "-"}</span>
                      </div>
                      <div className="graph-record-row">
                        <span>Valid from</span>
                        <span>{certNotBefore ? formatDate(certNotBefore) : "-"}</span>
                      </div>
                      <div className="graph-record-row">
                        <span>Valid until</span>
                        <span>{certNotAfter ? formatDate(certNotAfter) : "-"}</span>
                      </div>
                      <div className="graph-record-row">
                        <span>Issuer</span>
                        <span>{formatCertEntity(tls.cert?.issuer)}</span>
                      </div>
                      <div className="graph-record-row">
                        <span>Subject</span>
                        <span>{formatCertEntity(tls.cert?.subject)}</span>
                      </div>
                      {tls.cert?.san?.length ? (
                        <div className="graph-list-block">
                          <div className="muted">SANs</div>
                          <div className="graph-chip-list">
                            {tls.cert.san.slice(0, 10).map((san) => (
                              <span key={`san-${hoveredNode.key}-${san}`} className="graph-chip">
                                {san}
                              </span>
                            ))}
                            {tls.cert.san.length > 10 ? (
                              <span className="muted">+{tls.cert.san.length - 10} more</span>
                            ) : null}
                          </div>
                        </div>
                      ) : null}
                    </details>
                  ) : null}
                  {fingerprints.length || reportedVersions.length || technologies.length ? (
                    <details className="graph-details">
                      <summary>Fingerprints</summary>
                      {fingerprints.length ? (
                        <div className="graph-chip-list">
                          {fingerprints.map((fp) => (
                            <span key={`fp-${hoveredNode.key}-${fp}`} className="graph-chip">
                              {fp}
                            </span>
                          ))}
                        </div>
                      ) : null}
                      {technologies.length ? (
                        <div className="graph-list-block">
                          <div className="muted">Technologies</div>
                          <div className="graph-records">
                            {technologies.map((entry, idx) => (
                              <div
                                key={`tech-${hoveredNode.key}-${idx}-${entry.name}`}
                                className="graph-record-row"
                              >
                                <span>{entry.name}</span>
                                <span className="muted">{entry.source}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : null}
                      {reportedVersions.length ? (
                        <div className="graph-list-block">
                          <div className="muted">Reported versions</div>
                          <div className="graph-records">
                            {reportedVersions.map((entry, idx) => (
                              <div
                                key={`rv-${hoveredNode.key}-${idx}-${entry.name}-${entry.version}`}
                                className="graph-record-row"
                              >
                                <span>
                                  {entry.name}
                                  {entry.version ? ` ${entry.version}` : ""}
                                </span>
                                <span className="muted">{entry.source}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : null}
                    </details>
                  ) : null}
                  {exposureFactors.length ? (
                    <details className="graph-details">
                      <summary>Exposure factors</summary>
                      <div className="graph-chip-list">
                        {exposureFactors.map((factor) => (
                          <span key={`exp-${hoveredNode.key}-${factor}`} className="graph-chip">
                            {factor}
                          </span>
                        ))}
                      </div>
                    </details>
                  ) : null}
                  {visibleCveFindings.length ? (
                    <details className="graph-details">
                      <summary>CVE findings</summary>
                      <div className="muted">
                        Critical {cveCounts.Critical} · High {cveCounts.High} · Medium{" "}
                        {cveCounts.Medium} · Low {cveCounts.Low} · Total{" "}
                        {cveCounts.Total}
                      </div>
                      <div className="graph-records">
                        {visibleCveFindings.map((row, idx) => (
                          <div
                            key={`cve-${hoveredNode.key}-${idx}-${row.cve}`}
                            className="graph-record-row"
                          >
                            <span>
                              {row.cve} · {row.component} {row.version}
                            </span>
                            <span className="muted">
                              {classifySeverity(row.score)} · {row.score ?? "-"}
                            </span>
                          </div>
                        ))}
                      </div>
                    </details>
                  ) : null}
                  {ipAsn.length ? (
                    <details className="graph-details">
                      <summary>ASN</summary>
                      <div className="graph-records">
                        {ipAsn.map((row) => (
                          <div key={`asn-${hoveredNode.key}-${row.ip}`} className="graph-record-row">
                            <span>{row.ip}</span>
                            <span>
                              {row.asn ? `AS${row.asn}` : "-"} {row.asn_description || ""}
                            </span>
                          </div>
                        ))}
                      </div>
                    </details>
                  ) : null}
                  {nodeIntel.provider_hints?.length ? (
                    <div className="graph-list-block">
                      <div className="muted">Provider hints</div>
                      <div className="graph-chip-list">
                        {nodeIntel.provider_hints.map((p) => (
                          <span key={`hint-${hoveredNode.key}-${p}`} className="graph-chip">
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {nodeIntel.service_hints?.length ? (
                    <div className="graph-list-block">
                      <div className="muted">Service hints</div>
                      <div className="graph-chip-list">
                        {nodeIntel.service_hints.map((p) => (
                          <span key={`svc-${hoveredNode.key}-${p}`} className="graph-chip">
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              ) : null}
              <div className="graph-kv">
                <span>DNS Records</span>
                <span>{hoveredNode.totalRecords || 0}</span>
              </div>
              {hoveredNode?.dns ? (
                <div className="graph-records">
                  <div className="graph-record-row">
                    <span>Resolved At</span>
                    <span>{hoveredNode.dns.resolved_at ? formatDate(hoveredNode.dns.resolved_at) : "-"}</span>
                  </div>
                  {["A", "AAAA", "CNAME", "MX", "NS"].map((k) => (
                    <div key={k} className="graph-record-row">
                      <span>{k}</span>
                      <span>{(hoveredNode.dns[k] || []).length}</span>
                    </div>
                  ))}
                  <div className="graph-record-row">
                    <span>TXT</span>
                    <span>{(hoveredNode.dns.TXT || []).length}</span>
                  </div>
                  <div className="graph-record-row">
                    <span>CAA</span>
                    <span>{(hoveredNode.dns.CAA || []).length}</span>
                  </div>
                  <div className="graph-record-row">
                    <span>PTR names</span>
                    <span>{ptrValues.length}</span>
                  </div>
                  {(hoveredNode.dns.ips || []).length ? (
                    <div className="graph-list-block">
                      <div className="muted">IPs</div>
                      <div className="graph-chip-list">
                        {hoveredNode.dns.ips.slice(0, 10).map((ip) => (
                          <span key={`ip-${hoveredNode.key}-${ip}`} className="graph-chip">
                            {ip}
                          </span>
                        ))}
                        {hoveredNode.dns.ips.length > 10 ? (
                          <span className="muted">+{hoveredNode.dns.ips.length - 10} more</span>
                        ) : null}
                      </div>
                    </div>
                  ) : null}
                  {ptrValues.length ? (
                    <div className="graph-list-block">
                      <div className="muted">PTR</div>
                      <div className="graph-chip-list">
                        {ptrValues.slice(0, 8).map((ptr) => (
                          <span key={`ptr-${hoveredNode.key}-${ptr}`} className="graph-chip">
                            {ptr}
                          </span>
                        ))}
                        {ptrValues.length > 8 ? (
                          <span className="muted">+{ptrValues.length - 8} more</span>
                        ) : null}
                      </div>
                    </div>
                  ) : null}
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
  const [allCompanies, setAllCompanies] = useState([]);
  const [selectedCustomer, setSelectedCustomer] = useState(ADD_CUSTOMER_OPTION);
  const [activeCompany, setActiveCompany] = useState(null);
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [artifacts, setArtifacts] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [theme, setTheme] = useState(() => getThemeForUser(""));
  const [uiMode, setUiMode] = useState(() => {
    if (typeof window === "undefined") return "standard";
    const stored =
      window.localStorage.getItem(UI_MODE_KEY) ||
      window.localStorage.getItem("asm.ui.mode");
    return normalizeUiMode(stored);
  });
  const [minCveSeverity, setMinCveSeverity] = useState(() => {
    if (typeof window === "undefined") return "High";
    return window.localStorage.getItem(MIN_CVE_SEVERITY_KEY) || "High";
  });
  const [authToken, setAuthTokenState] = useState(() => {
    if (typeof window === "undefined") return "";
    return window.localStorage.getItem(AUTH_TOKEN_KEY) || "";
  });
  const [me, setMe] = useState(() => ({
    role: "public",
    email: null,
    allowed_company_slugs: [],
    public_company_slugs: [],
    max_companies: 0,
    owned_company_count: 0,
    scan_limits: { cooldown_seconds: 0, scans_per_hour: 0 },
  }));
  const [authReady, setAuthReady] = useState(false);
  const googleButtonRef = useRef(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [customerModalOpen, setCustomerModalOpen] = useState(false);
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [maxLabelCap, setMaxLabelCap] = useState(36);
  const [newCustomerName, setNewCustomerName] = useState("");
  const [newCustomerDomain, setNewCustomerDomain] = useState("");
  const [addDomainInput, setAddDomainInput] = useState("");
  const [renameInput, setRenameInput] = useState("");
  const [scanInFlight, setScanInFlight] = useState(false);
  const [deepScan, setDeepScan] = useState(
    () => window.localStorage.getItem("asm.scan.deep") === "true"
  );
  const [customerSectionOpen, setCustomerSectionOpen] = useState(
    () => window.localStorage.getItem("asm.customer.open") !== "false"
  );
  const [scansSectionOpen, setScansSectionOpen] = useState(
    () => window.localStorage.getItem("asm.scans.open") !== "false"
  );
  const [customerHeight, setCustomerHeight] = useState(() => {
    const raw = window.localStorage.getItem("asm.customer.height");
    return raw ? Number(raw) : null;
  });
  const [scansHeight, setScansHeight] = useState(() => {
    const raw = window.localStorage.getItem("asm.scans.height");
    return raw ? Number(raw) : null;
  });
  const customerCardRef = useRef(null);
  const scansCardRef = useRef(null);
  const [users, setUsers] = useState(() => readStoredJson(USER_STORAGE_KEY, []));
  const [groups, setGroups] = useState(() => {
    const stored = readStoredJson(GROUP_STORAGE_KEY, []);
    return stored.length ? stored : ["default"];
  });
  const [companyGroups, setCompanyGroups] = useState(() =>
    readStoredJson(COMPANY_GROUP_KEY, {})
  );
  const [activeUserId, setActiveUserId] = useState(
    () => window.localStorage.getItem(ACTIVE_USER_KEY) || ""
  );
  const [userError, setUserError] = useState("");
  const [newUserName, setNewUserName] = useState("");
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserRole, setNewUserRole] = useState("standard");
  const [newUserGroupId, setNewUserGroupId] = useState("");
  const [newUserGroupChoice, setNewUserGroupChoice] = useState(
    groups[0] || NEW_GROUP_OPTION
  );
  const [switchUserId, setSwitchUserId] = useState("");
  const [editingUserId, setEditingUserId] = useState("");
  const [editUserName, setEditUserName] = useState("");
  const [editUserEmail, setEditUserEmail] = useState("");
  const [editUserGroupId, setEditUserGroupId] = useState("");
  const [userModalRect, setUserModalRect] = useState(() => {
    const width = 760;
    const height = 520;
    if (typeof window !== "undefined") {
      const x = Math.max(24, Math.round((window.innerWidth - width) / 2));
      const y = Math.max(24, Math.round((window.innerHeight - height) / 2));
      return { x, y, width, height };
    }
    return { x: 80, y: 80, width, height };
  });
  const [userModalDragging, setUserModalDragging] = useState(false);
  const [userModalResizing, setUserModalResizing] = useState(false);
  const userModalDragRef = useRef({ x: 0, y: 0 });
  const userModalResizeRef = useRef({ x: 0, y: 0, width: 0, height: 0 });

  const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || "";

  function handleAuthToken(token) {
    const next = token || "";
    setAuthTokenState(next);
    if (typeof window !== "undefined") {
      if (next) {
        window.localStorage.setItem(AUTH_TOKEN_KEY, next);
      } else {
        window.localStorage.removeItem(AUTH_TOKEN_KEY);
      }
    }
  }

  function clearAuth(message) {
    handleAuthToken("");
    if (message) {
      setError(message);
    }
  }

  async function loadMe() {
    try {
      const data = await api.getMe();
      setMe(data);
    } catch (err) {
      if (err?.status === 401) {
        clearAuth("Session expired. Please sign in again.");
      }
      setMe((prev) => ({
        ...prev,
        role: "public",
        allowed_company_slugs: prev.public_company_slugs || [],
      }));
    } finally {
      setAuthReady(true);
    }
  }

  useEffect(() => {
    setAuthToken(authToken);
    setAuthReady(false);
    loadMe();
  }, [authToken]);

  useEffect(() => {
    if (!googleClientId) return;
    if (!window.google?.accounts?.id) return;
    window.google.accounts.id.initialize({
      client_id: googleClientId,
      callback: (resp) => {
        if (resp?.credential) {
          handleAuthToken(resp.credential);
        }
      },
    });
    if (googleButtonRef.current) {
      googleButtonRef.current.innerHTML = "";
      window.google.accounts.id.renderButton(googleButtonRef.current, {
        theme: "outline",
        size: "medium",
        text: "signin_with",
        width: 210,
      });
    }
  }, [googleClientId]);

  const activeUser = useMemo(
    () => users.find((u) => u.id === activeUserId) || null,
    [users, activeUserId]
  );
  const isAdmin = me.role === "admin";
  const publicSlugs = useMemo(
    () => new Set(me.public_company_slugs || []),
    [me.public_company_slugs]
  );
  const allowedSlugs = useMemo(
    () => new Set(me.allowed_company_slugs || []),
    [me.allowed_company_slugs]
  );
  const companies = useMemo(() => {
    if (me.role === "admin") {
      return allCompanies;
    }
    return allCompanies.filter((company) => allowedSlugs.has(company.slug));
  }, [allCompanies, allowedSlugs, me.role]);
  const activeScan = useMemo(
    () => scans.find((s) => s.id === selectedScanId),
    [scans, selectedScanId]
  );
  const ownedCompanyCount = useMemo(
    () => companies.filter((c) => !publicSlugs.has(c.slug)).length,
    [companies, publicSlugs]
  );
  const canCreateCompany =
    me.role === "admin" ||
    (me.role === "user" && ownedCompanyCount < (me.max_companies || 0));
  const canManageActiveCompany =
    me.role === "admin" ||
    (me.role === "user" && activeCompany?.owner_email === me.email);
  const canScanActiveCompany = canManageActiveCompany;
  const canDeleteScan = canManageActiveCompany;
  const hasRunningScan = useMemo(
    () => scans.some((s) => s.status === "running"),
    [scans]
  );
  const isActive = loading || hasRunningScan;
  const runningScan = useMemo(
    () => scans.find((s) => s.status === "running") || null,
    [scans]
  );
  const scanProgress = useMemo(
    () => parseScanProgress(runningScan || activeScan),
    [runningScan, activeScan]
  );
  const scanBlocked = scanInFlight || hasRunningScan;
  const whoisRoots = artifacts?.whois?.roots || [];
  const [showSource, setShowSource] = useState(false);
  const [sourceKey, setSourceKey] = useState("");
  const artifactKeys = useMemo(() => {
    if (!artifacts) return [];
    return Object.keys(artifacts).sort();
  }, [artifacts]);

  async function loadCompanies() {
    const data = await api.listCompanies();
    setAllCompanies(data);

    setCompanyGroups((current) => {
      let next = { ...current };
      let changed = false;
      let nextGroups = groups.slice();
      const fallbackGroup = nextGroups[0] || "default";
      if (!nextGroups.length) {
        nextGroups = ["default"];
        changed = true;
      }
      for (const company of data) {
        if (!next[company.slug]) {
          const assigned = fallbackGroup;
          next[company.slug] = assigned;
          if (assigned && !nextGroups.includes(assigned)) {
            nextGroups.push(assigned);
          }
          changed = true;
        }
      }
      if (changed) {
        if (nextGroups.length && nextGroups.join("|") !== groups.join("|")) {
          setGroups(nextGroups);
          writeStoredJson(GROUP_STORAGE_KEY, nextGroups);
        }
        writeStoredJson(COMPANY_GROUP_KEY, next);
        return next;
      }
      return current;
    });
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
    const selectedExists =
      selectedScanId && scanList.some((scan) => scan.id === selectedScanId);
    if (selectedExists) {
      return;
    }
    const latestComplete = getLatestCompleteScan(scanList);
    if (latestComplete) {
      setSelectedScanId(latestComplete.id);
      await loadArtifacts(slug, latestComplete.id);
    } else {
      setSelectedScanId(null);
      setArtifacts(null);
    }
  }

  async function loadArtifacts(slug, scanId) {
    const data = await api.getArtifacts(slug, scanId);
    setArtifacts(data);
  }

  async function startScan(slug) {
    if (scanBlocked) {
      throw new Error("A scan is already running. Wait for it to finish.");
    }
    if (!canScanActiveCompany) {
      throw new Error("Scan not permitted for this company.");
    }
    setScanInFlight(true);
    try {
      const result = await api.runScan(slug, {
        deep_scan: deepScan,
      });
      await loadCompany(slug);
      if (result?.scan_id) {
        setSelectedScanId(result.scan_id);
        setArtifacts(null);
      }
    } finally {
      setScanInFlight(false);
    }
  }

  async function removeDomainFromCompany(domain) {
    if (!activeCompany) return;
    const remaining = activeCompany.domains.filter((d) => d !== domain);
    if (remaining.length === 0) {
      throw new Error("A customer must have at least one domain");
    }
    if (!confirm(`Remove domain '${domain}' from ${activeCompany.slug}?`)) {
      return;
    }
    await api.replaceDomains(activeCompany.slug, remaining);
    await loadCompany(activeCompany.slug);
  }

  async function handleSelectCustomer(option) {
    if (option === ADD_CUSTOMER_OPTION && !canCreateCompany) {
      setError("Company creation is not available for this account.");
      return;
    }
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
      if (err?.status === 401) {
        clearAuth("Session expired. Please sign in again.");
      } else if (err?.status === 429 && err?.data?.retry_after_seconds) {
        const retry = Number(err.data.retry_after_seconds);
        const seconds = Number.isFinite(retry) ? retry : 60;
        const minutes = Math.ceil(seconds / 60);
        setError(
          `Rate limited. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`
        );
      } else if (err?.data?.message) {
        setError(err.data.message);
      } else {
        setError(err.message || "Request failed");
      }
    } finally {
      setLoading(false);
    }
  }

  function persistUiMode(next) {
    setUiMode(next);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(UI_MODE_KEY, next);
    }
  }

  function persistSectionHeight(which, ref) {
    const node = ref.current;
    if (!node) return;
    const next = Math.round(node.getBoundingClientRect().height);
    if (which === "customer") {
      setCustomerHeight(next);
      window.localStorage.setItem("asm.customer.height", String(next));
    } else {
      setScansHeight(next);
      window.localStorage.setItem("asm.scans.height", String(next));
    }
  }

  function setStoredUsers(next) {
    setUsers(next);
    writeStoredJson(USER_STORAGE_KEY, next);
  }

  function setStoredGroups(next) {
    const normalized = next.length ? next : ["default"];
    setGroups(normalized);
    writeStoredJson(GROUP_STORAGE_KEY, normalized);
  }

  function setStoredCompanyGroups(next) {
    setCompanyGroups(next);
    writeStoredJson(COMPANY_GROUP_KEY, next);
  }

  function setStoredActiveUser(nextId) {
    setActiveUserId(nextId);
    if (nextId) {
      window.localStorage.setItem(ACTIVE_USER_KEY, nextId);
    } else {
      window.localStorage.removeItem(ACTIVE_USER_KEY);
    }
  }

  function resetUserForm() {
    setNewUserName("");
    setNewUserEmail("");
    setNewUserRole("standard");
    setNewUserGroupChoice(groups[0] || NEW_GROUP_OPTION);
    setNewUserGroupId("");
  }

  function startEditUser(user) {
    setEditingUserId(user.id);
    setEditUserName(user.username);
    setEditUserEmail(user.email);
    setEditUserGroupId(user.groupId || "");
  }

  function startUserModalDrag(e) {
    if (e.button !== 0) return;
    userModalDragRef.current = {
      x: e.clientX - userModalRect.x,
      y: e.clientY - userModalRect.y,
    };
    setUserModalDragging(true);
  }

  function startUserModalResize(e) {
    if (e.button !== 0) return;
    userModalResizeRef.current = {
      x: e.clientX,
      y: e.clientY,
      width: userModalRect.width,
      height: userModalRect.height,
    };
    setUserModalResizing(true);
  }

  function handleCreateUser() {
    setUserError("");
    const username = newUserName.trim();
    const email = newUserEmail.trim();
    const role = newUserRole === "admin" ? "admin" : "standard";
    const normalized = username.toLowerCase();
    if (!username) {
      setUserError("Username is required.");
      return;
    }
    if (users.some((u) => u.username.toLowerCase() === normalized)) {
      setUserError("Username already exists.");
      return;
    }
    if (!email) {
      setUserError("Email is required.");
      return;
    }
    let groupId =
      newUserGroupChoice === NEW_GROUP_OPTION
        ? newUserGroupId.trim()
        : newUserGroupChoice;
    if (role === "standard" && !groupId) {
      setUserError("Standard users must have a group ID.");
      return;
    }
    let nextGroups = groups.slice();
    if (groupId && !nextGroups.includes(groupId)) {
      nextGroups.push(groupId);
    }
    if (!nextGroups.length) {
      nextGroups = ["default"];
      if (role === "standard" && !groupId) {
        groupId = "default";
      }
    }
    const user = {
      id: makeId("user"),
      username,
      email,
      role,
      groupId: role === "standard" ? groupId : "",
      createdAt: new Date().toISOString(),
    };
    setStoredUsers([...users, user]);
    setStoredGroups(nextGroups);
    if (!activeUserId) {
      setStoredActiveUser(user.id);
    }
    setSwitchUserId(user.id);
    resetUserForm();
  }

  function handleSwitchUser() {
    if (!switchUserId) return;
    setStoredActiveUser(switchUserId);
  }

  function handleRemoveUser(userId) {
    const target = users.find((u) => u.id === userId);
    if (!target) return;
    if (!confirm(`Remove user ${target.username}?`)) return;
    const next = users.filter((u) => u.id !== userId);
    setStoredUsers(next);
    if (activeUserId === userId) {
      setStoredActiveUser("");
    }
    if (editingUserId === userId) {
      setEditingUserId("");
    }
  }

  function handleUpdateUser() {
    if (!editingUserId) return;
    const username = editUserName.trim();
    const email = editUserEmail.trim();
    if (!username) {
      setUserError("Username is required.");
      return;
    }
    if (!email) {
      setUserError("Email is required.");
      return;
    }
    if (!editUserGroupId.trim()) {
      setUserError("Group ID is required.");
      return;
    }
    const normalized = username.toLowerCase();
    if (
      users.some(
        (u) => u.id !== editingUserId && u.username.toLowerCase() === normalized
      )
    ) {
      setUserError("Username already exists.");
      return;
    }
    const nextUsers = users.map((u) => {
      if (u.id !== editingUserId) return u;
      return {
        ...u,
        username,
        email,
        groupId: u.role === "standard" ? editUserGroupId.trim() : u.groupId,
      };
    });
    setStoredUsers(nextUsers);
    setEditingUserId("");
  }

  function handleRemoveGroup(groupId) {
    if (!groupId) return;
    if (!confirm(`Remove group ${groupId}?`)) return;
    const nextGroups = groups.filter((g) => g !== groupId);
    const fallback = nextGroups[0] || "default";
    const nextUsers = users.map((u) => {
      if (u.role === "standard" && u.groupId === groupId) {
        return { ...u, groupId: fallback };
      }
      return u;
    });
    const nextCompanyGroups = { ...companyGroups };
    Object.keys(nextCompanyGroups).forEach((slug) => {
      if (nextCompanyGroups[slug] === groupId) {
        nextCompanyGroups[slug] = fallback;
      }
    });
    setStoredGroups(nextGroups.length ? nextGroups : [fallback]);
    setStoredUsers(nextUsers);
    setStoredCompanyGroups(nextCompanyGroups);
  }

  function handleCompanyGroupChange(slug, nextGroupId) {
    if (!slug || !nextGroupId) return;
    const next = { ...companyGroups, [slug]: nextGroupId };
    setStoredCompanyGroups(next);
  }

  function exportArtifactsJson() {
    if (!artifacts) return;
    const payload = JSON.stringify(artifacts, null, 2);
    const blob = new Blob([payload], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const slug = activeCompany?.slug || "company";
    const scanNumber = activeScan?.company_scan_number ?? "scan";
    const link = document.createElement("a");
    link.href = url;
    link.download = `asm-artifacts-${slug}-${scanNumber}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }


  useEffect(() => {
    if (!authReady) return;
    runWithStatus(loadCompanies);
  }, [authReady, me.role, me.email]);

  useEffect(() => {
    if (!groups.length) {
      setStoredGroups(["default"]);
    }
  }, [groups]);

  useEffect(() => {
    if (!newUserGroupChoice) {
      setNewUserGroupChoice(groups[0] || NEW_GROUP_OPTION);
      return;
    }
    if (
      newUserGroupChoice !== NEW_GROUP_OPTION &&
      !groups.includes(newUserGroupChoice)
    ) {
      setNewUserGroupChoice(groups[0] || NEW_GROUP_OPTION);
    }
  }, [groups, newUserGroupChoice]);

  useEffect(() => {
    if (selectedCustomer !== ADD_CUSTOMER_OPTION) {
      if (!companies.some((c) => c.slug === selectedCustomer)) {
        const fallback = canCreateCompany
          ? ADD_CUSTOMER_OPTION
          : companies[0]?.slug || ADD_CUSTOMER_OPTION;
        setSelectedCustomer(fallback);
        setActiveCompany(null);
        setScans([]);
        setSelectedScanId(null);
        setArtifacts(null);
      }
      return;
    }
    if (!canCreateCompany && companies.length) {
      setSelectedCustomer(companies[0].slug);
    }
  }, [companies, selectedCustomer, canCreateCompany]);

  useEffect(() => {
    if (!userModalOpen) return;
    setSwitchUserId(activeUserId || "");
    setUserError("");
    setEditingUserId("");
  }, [userModalOpen, activeUserId]);

  useEffect(() => {
    if (!artifacts) {
      setShowSource(false);
      setSourceKey("");
      return;
    }
    if (!sourceKey) {
      setSourceKey(
        artifacts.whois ? "whois" : artifactKeys[0] || ""
      );
    }
  }, [artifacts, artifactKeys, sourceKey]);

  useEffect(() => {
    const nextTheme = getThemeForUser(activeUserId || "");
    setTheme(nextTheme);
  }, [activeUserId]);

  useEffect(() => {
    if (selectedCustomer === ADD_CUSTOMER_OPTION) {
      setActiveCompany(null);
      setScans([]);
      return;
    }
    runWithStatus(() => loadCompany(selectedCustomer));
  }, [selectedCustomer]);

  useEffect(() => {
    if (!userModalDragging && !userModalResizing) return;
    const onMove = (e) => {
      if (userModalDragging) {
        setUserModalRect((prev) => {
          const nextX = Math.max(12, e.clientX - userModalDragRef.current.x);
          const nextY = Math.max(12, e.clientY - userModalDragRef.current.y);
          return { ...prev, x: nextX, y: nextY };
        });
      } else if (userModalResizing) {
        const minWidth = 520;
        const minHeight = 360;
        const dx = e.clientX - userModalResizeRef.current.x;
        const dy = e.clientY - userModalResizeRef.current.y;
        setUserModalRect((prev) => ({
          ...prev,
          width: Math.max(minWidth, userModalResizeRef.current.width + dx),
          height: Math.max(minHeight, userModalResizeRef.current.height + dy),
        }));
      }
    };
    const onUp = () => {
      setUserModalDragging(false);
      setUserModalResizing(false);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [userModalDragging, userModalResizing]);

  useEffect(() => {
    if (!settingsOpen && !userModalOpen && !customerModalOpen) {
      return;
    }
    const onKeyDown = (event) => {
      if (event.key !== "Escape") return;
      setSettingsOpen(false);
      setUserModalOpen(false);
      setCustomerModalOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [settingsOpen, userModalOpen, customerModalOpen]);

  useEffect(() => {
    const slug = activeCompany?.slug;
    if (!slug || !hasRunningScan) {
      return undefined;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const nextScans = await api.listScans(slug);
        if (cancelled) return;
        setScans(nextScans);
        if (selectedScanId) {
          const selected = nextScans.find((s) => s.id === selectedScanId);
          if (selected && selected.status === "success") {
            const nextArtifacts = await api.getArtifacts(slug, selectedScanId);
            if (!cancelled) {
              setArtifacts(nextArtifacts);
            }
          }
        }
      } catch (_err) {
        // Keep polling silent; transient failures should not spam UI toasts.
      }
    };
    poll();
    const timer = setInterval(poll, 3000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [activeCompany?.slug, hasRunningScan, selectedScanId]);

  return (
    <div className={`app theme-${theme}`}>
      <header className="topbar">
        <div className="brand">
          <button
            className="logo-button"
            onClick={() => window.location.reload()}
            aria-label="Refresh home"
            type="button"
          >
            <span className="brand-logo">
              <img className="logo logo-light" src={logoLight} alt="ASM Notebook" />
              <img className="logo logo-dark" src={logoDark} alt="ASM Notebook" />
            </span>
          </button>
          <div className="brand-sub">
            Passive attack surface inventory and scan history
          </div>
        </div>
        <div className="header-controls">
          <label className="header-label">
            Customer
            <select
              value={selectedCustomer}
              onChange={(e) => handleSelectCustomer(e.target.value)}
            >
              {canCreateCompany ? (
                <option value={ADD_CUSTOMER_OPTION}>Add Customer</option>
              ) : null}
              {companies.map((c) => (
                <option key={c.slug} value={c.slug}>
                  {c.name} ({c.slug})
                </option>
              ))}
            </select>
          </label>
          <label className="header-label">
            View:
            <ViewModeSwitcher value={uiMode} onChange={persistUiMode} />
          </label>
          {selectedCustomer === ADD_CUSTOMER_OPTION && canCreateCompany ? (
            <div className="header-create">
              <label>
                Name
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
                className="header-action"
                onClick={() =>
                  runWithStatus(async () => {
                    const name = newCustomerName.trim();
                    const domain = normalizeDomain(newCustomerDomain);
                    if (!name) throw new Error("Customer name is required");
                    if (!domain) throw new Error("Domain is required");
                    const customer = deriveCustomerFromDomain(domain);
                    const existingSlugs = new Set(
                      allCompanies.map((c) => (c.slug || "").toLowerCase())
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
                    const assignedGroup =
                      activeUser?.role === "standard" && activeUser.groupId
                        ? activeUser.groupId
                        : groups[0] || "default";
                    setStoredCompanyGroups({
                      ...companyGroups,
                      [created.slug]: assignedGroup,
                    });
                    if (assignedGroup && !groups.includes(assignedGroup)) {
                      setStoredGroups([...groups, assignedGroup]);
                    }
                    setNewCustomerName("");
                    setNewCustomerDomain("");
                    await loadCompanies();
                    setSelectedCustomer(created.slug);
                  })
                }
              >
                Create
              </button>
            </div>
          ) : null}
          <button
            className="ghost header-action"
            onClick={() => runWithStatus(loadCompanies)}
          >
            Refresh
          </button>
          {activeCompany ? (
            <button
              className="ghost header-action"
              onClick={() => setCustomerModalOpen(true)}
              disabled={!canManageActiveCompany}
              title={canManageActiveCompany ? "Manage details" : "Read-only access"}
            >
              Manage details
            </button>
          ) : null}
          <div className="auth-controls">
            {authToken ? (
              <>
                <div className="muted auth-meta">
                  Signed in as {me.email || "user"}
                </div>
                <button className="ghost header-action" onClick={() => clearAuth()}>
                  Sign out
                </button>
              </>
            ) : googleClientId ? (
              <div ref={googleButtonRef} />
            ) : (
              <div className="muted auth-meta">Google auth not configured</div>
            )}
          </div>
        </div>
        <div className="status">
          <div className="status-line">
            <button className="ghost" onClick={() => setSettingsOpen(true)} aria-label="Open settings">
              ⚙
            </button>
            <span
              className={`dot ${isActive ? "active blink" : "idle"}`.trim()}
            />
            {isActive ? "Activity" : "Idle"}
          </div>
          <div className="status-user">
            <div className="muted user-meta">Role: {me.role}</div>
            {me.email ? <div className="muted user-meta">{me.email}</div> : null}
          </div>
        </div>
      </header>
      {me.role === "public" ? (
        <div className="public-banner">
          Public demo (read-only). Sign in for more access.
        </div>
      ) : null}

      <div className="layout">
        <main className="content">
          {selectedCustomer === ADD_CUSTOMER_OPTION ? (
            <div className="empty-state">
              <h2>Create a customer in the header</h2>
              <p>Use the header form to add a name and initial domain.</p>
            </div>
          ) : !activeCompany ? (
            <div className="empty-state">
              <h2>Add or select a customer</h2>
              <p>
                Choose an existing customer from the dropdown or create one with
                a domain.
              </p>
            </div>
          ) : (
            <>
              <>
                {uiMode === "executive" ? (
                  <ExecutiveDashboard
                    activeCompany={activeCompany}
                    activeScan={activeScan}
                    artifacts={artifacts}
                    scans={scans}
                    selectedScanId={selectedScanId}
                    hasRunningScan={hasRunningScan}
                    runningScan={runningScan}
                    scanProgress={scanProgress}
                    deepScan={deepScan}
                    minCveSeverity={minCveSeverity}
                    canManageCompany={canManageActiveCompany}
                    canStartScan={canScanActiveCompany}
                    canDeleteScan={canDeleteScan}
                    onToggleDeepScan={(next) => {
                      setDeepScan(next);
                      window.localStorage.setItem("asm.scan.deep", String(next));
                    }}
                    onManageDetails={() => setCustomerModalOpen(true)}
                    onLoadLatest={() =>
                      runWithStatus(async () => {
                        const latest = await api.latestScan(activeCompany.slug);
                        setSelectedScanId(latest.id);
                        await loadArtifacts(activeCompany.slug, latest.id);
                      })
                    }
                    onStartScan={() =>
                      runWithStatus(async () => {
                        await startScan(activeCompany.slug);
                      })
                    }
                    onSelectScan={(scanId) =>
                      runWithStatus(async () => {
                        if (!scanId) return;
                        setSelectedScanId(scanId);
                        await loadArtifacts(activeCompany.slug, scanId);
                      })
                    }
                    onDeleteScan={(scan) =>
                      runWithStatus(async () => {
                        if (!scan) return;
                        const label = scan?.company_scan_number
                          ? `scan #${scan.company_scan_number}`
                          : `scan id ${scan?.id ?? "-"}`;
                        const runningNotice =
                          (scan?.status || "").toLowerCase() === "running"
                            ? " This will cancel the running scan."
                            : "";
                        if (
                          !confirm(
                            `Delete ${label} for ${activeCompany.slug}?${runningNotice}`
                          )
                        ) {
                          return;
                        }
                        await api.deleteScan(activeCompany.slug, scan.id);
                        if (scan.id === selectedScanId) {
                          setSelectedScanId(null);
                          setArtifacts(null);
                        }
                        await loadCompany(activeCompany.slug);
                      })
                    }
                    onDeleteCompany={() =>
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
                    onExportArtifacts={exportArtifactsJson}
                    onOpenDetails={() => {
                      setScansSectionOpen(true);
                      window.localStorage.setItem("asm.scans.open", "true");
                      setTimeout(() => {
                        scansCardRef.current?.scrollIntoView({
                          behavior: "smooth",
                          block: "start",
                        });
                      }, 50);
                    }}
                    onChangeViewMode={persistUiMode}
                  />
                ) : null}
                {uiMode === "soc" ? (
                  <SocDashboard
                    activeCompany={activeCompany}
                    activeScan={activeScan}
                    artifacts={artifacts}
                    scans={scans}
                    selectedScanId={selectedScanId}
                    hasRunningScan={hasRunningScan}
                    runningScan={runningScan}
                    scanProgress={scanProgress}
                    deepScan={deepScan}
                    minCveSeverity={minCveSeverity}
                    canManageCompany={canManageActiveCompany}
                    canStartScan={canScanActiveCompany}
                    canDeleteScan={canDeleteScan}
                    onToggleDeepScan={(next) => {
                      setDeepScan(next);
                      window.localStorage.setItem("asm.scan.deep", String(next));
                    }}
                    onManageDetails={() => setCustomerModalOpen(true)}
                    onLoadLatest={() =>
                      runWithStatus(async () => {
                        const latest = await api.latestScan(activeCompany.slug);
                        setSelectedScanId(latest.id);
                        await loadArtifacts(activeCompany.slug, latest.id);
                      })
                    }
                    onStartScan={() =>
                      runWithStatus(async () => {
                        await startScan(activeCompany.slug);
                      })
                    }
                    onSelectScan={(scanId) =>
                      runWithStatus(async () => {
                        if (!scanId) return;
                        setSelectedScanId(scanId);
                        await loadArtifacts(activeCompany.slug, scanId);
                      })
                    }
                    onDeleteScan={(scan) =>
                      runWithStatus(async () => {
                        if (!scan) return;
                        const label = scan?.company_scan_number
                          ? `scan #${scan.company_scan_number}`
                          : `scan id ${scan?.id ?? "-"}`;
                        const runningNotice =
                          (scan?.status || "").toLowerCase() === "running"
                            ? " This will cancel the running scan."
                            : "";
                        if (
                          !confirm(
                            `Delete ${label} for ${activeCompany.slug}?${runningNotice}`
                          )
                        ) {
                          return;
                        }
                        await api.deleteScan(activeCompany.slug, scan.id);
                        if (scan.id === selectedScanId) {
                          setSelectedScanId(null);
                          setArtifacts(null);
                        }
                        await loadCompany(activeCompany.slug);
                      })
                    }
                    onDeleteCompany={() =>
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
                    onExportArtifacts={exportArtifactsJson}
                    onOpenDetails={() => {
                      setScansSectionOpen(true);
                      window.localStorage.setItem("asm.scans.open", "true");
                      setTimeout(() => {
                        scansCardRef.current?.scrollIntoView({
                          behavior: "smooth",
                          block: "start",
                        });
                      }, 50);
                    }}
                  />
                ) : null}
                <section
                  ref={customerCardRef}
                  className={`card ${customerSectionOpen ? "resizable-card" : "collapsed"}`}
                  style={
                    customerSectionOpen && customerHeight ? { height: customerHeight } : undefined
                  }
                onMouseUp={() => persistSectionHeight("customer", customerCardRef)}
                onTouchEnd={() => persistSectionHeight("customer", customerCardRef)}
              >
                <div className="card-header">
                  <div>
                    <h1>{activeCompany.name}</h1>
                    <div className="muted">
                      {activeCompany.slug} · {activeCompany.domains.length} domains
                    </div>
                  </div>
                  <div className="actions">
                    <button
                      className="ghost"
                      onClick={() => {
                        const next = !customerSectionOpen;
                        setCustomerSectionOpen(next);
                        window.localStorage.setItem("asm.customer.open", String(next));
                      }}
                    >
                      {customerSectionOpen ? "Minimize" : "Expand"}
                    </button>
                    <button
                      className="ghost"
                      onClick={() => setCustomerModalOpen(true)}
                      disabled={!canManageActiveCompany}
                    >
                      Manage details
                    </button>
                    <button
                      disabled={scanBlocked || !canScanActiveCompany}
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
                      disabled={!canManageActiveCompany}
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
                    <div className="scan-progress-title">
                      Scan in progress
                      {runningScan?.scan_mode
                        ? ` · ${formatScanMode(runningScan.scan_mode)}`
                        : ""}
                    </div>
                    <div className="scan-progress-bar">
                      <span
                        className={`scan-progress-fill ${
                          scanProgress?.indeterminate ? "indeterminate" : "determinate"
                        }`}
                        style={
                          scanProgress?.indeterminate
                            ? undefined
                            : { width: `${scanProgress?.percent ?? 0}%` }
                        }
                      />
                    </div>
                    <div className="scan-progress-message muted">
                      {scanProgress?.message || "Running scan..."}
                      {scanProgress?.indeterminate
                        ? ""
                        : ` (${scanProgress?.percent ?? 0}%)`}
                    </div>
                    <div className="muted">
                      Starting a new scan is disabled until completion.
                    </div>
                  </div>
                ) : null}

                {customerSectionOpen ? (
                  <div className="muted">
                    Use “Manage details” to rename the customer or edit domains.
                  </div>
                ) : null}
              </section>

              <section
                ref={scansCardRef}
                className={`card ${scansSectionOpen ? "resizable-card" : ""}`}
                style={
                  scansSectionOpen && scansHeight && !artifacts
                    ? { height: scansHeight }
                    : undefined
                }
                onMouseUp={() => persistSectionHeight("scans", scansCardRef)}
                onTouchEnd={() => persistSectionHeight("scans", scansCardRef)}
              >
                <div className="card-header">
                  <div>
                    <h2>Scans</h2>
                    <div className="muted">
                      {scans.length} total · newest first
                    </div>
                  </div>
                  <div className="actions">
                    <button
                      className="ghost"
                      onClick={() => {
                        const next = !scansSectionOpen;
                        setScansSectionOpen(next);
                        window.localStorage.setItem("asm.scans.open", String(next));
                      }}
                    >
                      {scansSectionOpen ? "Minimize" : "Expand"}
                    </button>
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

                {scansSectionOpen ? (
                  <div className={`scan-stack ${artifacts ? "with-artifacts" : ""}`.trim()}>
                    <div className={`scan-list ${artifacts ? "blurred" : ""}`}>
                      {scans.length === 0 ? (
                        <div className="empty empty-with-action">
                          <span>No scans yet</span>
                          <button
                            disabled={scanBlocked || !canScanActiveCompany}
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
                                #{scan.company_scan_number}
                              </div>
                              <div className="scan-meta">
                                {scan.status} · completed {formatDate(scan.completed_at)}
                                {scan.completed_at
                                  ? ` · duration ${formatDuration(
                                      scan.started_at,
                                      scan.completed_at
                                    )}`
                                  : ""}
                                {scan.scan_mode
                                  ? ` · ${formatScanMode(scan.scan_mode)}`
                                  : ""}
                                {scan.notes ? ` · ${scan.notes}` : ""}
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
                                disabled={!canDeleteScan}
                              >
                                Delete
                              </button>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                    {artifacts ? (
                      <div className="artifact-overlay">
                        <div className="artifact-header">
                          <div>
                            <h3>Artifacts</h3>
                            <div className="muted">
                              {activeScan
                                ? `Scan #${activeScan.company_scan_number}`
                                : "Selected scan"}
                            </div>
                            {artifacts.change_summary?.has_previous ? (
                              <div className="muted">
                                Changes: +{artifacts.change_summary.new_domains?.length ?? 0} / -
                                {artifacts.change_summary.removed_domains?.length ?? 0}
                              </div>
                            ) : null}
                            {artifacts.ct_enrichment?.suspicious_hostnames?.length ? (
                              <div className="muted">
                                CT suspicious hosts: {artifacts.ct_enrichment.suspicious_hostnames.length}
                              </div>
                            ) : null}
                          </div>
                          <div className="artifact-actions">
                            <button
                              className="ghost"
                              onClick={() => setShowSource((prev) => !prev)}
                              disabled={!artifactKeys.length}
                            >
                              {showSource ? "Hide source" : "Show source"}
                            </button>
                            <button
                              className="ghost"
                              onClick={() => {
                                setSelectedScanId(null);
                                setArtifacts(null);
                              }}
                            >
                              Close
                            </button>
                          </div>
                        </div>
                        {showSource ? (
                          <div className="artifact-source">
                            <div className="artifact-source-head">
                              <div className="muted">Artifact source</div>
                              <select
                                value={sourceKey}
                                onChange={(e) => setSourceKey(e.target.value)}
                              >
                                {artifactKeys.map((key) => (
                                  <option key={key} value={key}>
                                    {key}
                                  </option>
                                ))}
                              </select>
                            </div>
                            <pre className="code">
                              {sourceKey ? JSON.stringify(artifacts[sourceKey], null, 2) : ""}
                            </pre>
                          </div>
                        ) : null}
                        {whoisRoots.length ? (
                          <details className="graph-details" open>
                            <summary>WHOIS (roots)</summary>
                            <div className="whois-list">
                              {whoisRoots.map((entry) => (
                                <div key={entry.domain} className="whois-entry">
                                  <div className="whois-title">{entry.domain}</div>
                                  {entry.error ? (
                                    <div className="muted">Error: {entry.error}</div>
                                  ) : (
                                    <>
                                      <div className="graph-records">
                                        <div className="graph-record-row">
                                          <span>Registrar</span>
                                          <span>{entry.registrar || "-"}</span>
                                        </div>
                                        <div className="graph-record-row">
                                          <span>Status</span>
                                          <span>
                                            {(entry.status || []).length
                                              ? entry.status.join(", ")
                                              : "-"}
                                          </span>
                                        </div>
                                      </div>
                                      {(entry.events || []).length ? (
                                        <div className="whois-events">
                                          <div className="muted">Events</div>
                                          <div className="graph-records">
                                            {entry.events.map((ev, idx) => (
                                              <div
                                                key={`${entry.domain}-ev-${idx}`}
                                                className="graph-record-row"
                                              >
                                                <span>{ev.action || "Event"}</span>
                                                <span>
                                                  {ev.date ? formatDate(ev.date) : "-"}
                                                </span>
                                              </div>
                                            ))}
                                          </div>
                                        </div>
                                      ) : null}
                                      {(entry.nameservers || []).length ? (
                                        <div className="whois-nameservers">
                                          <div className="muted">Nameservers</div>
                                          <div className="graph-chip-list">
                                            {entry.nameservers.map((ns) => (
                                              <span
                                                key={`${entry.domain}-ns-${ns}`}
                                                className="graph-chip"
                                              >
                                                {ns}
                                              </span>
                                            ))}
                                          </div>
                                        </div>
                                      ) : null}
                                    </>
                                  )}
                                </div>
                              ))}
                            </div>
                          </details>
                        ) : null}
                        <DomainRelationshipGraph
                          artifacts={artifacts}
                          maxLabelCap={maxLabelCap}
                          minCveSeverity={minCveSeverity}
                        />
                        {artifacts.change_summary?.has_previous ? (
                          <details className="graph-details">
                            <summary>Change summary</summary>
                            <div className="graph-records">
                              <div className="graph-record-row">
                                <span>New domains</span>
                                <span>{artifacts.change_summary.new_domains?.length ?? 0}</span>
                              </div>
                              <div className="graph-record-row">
                                <span>Removed domains</span>
                                <span>{artifacts.change_summary.removed_domains?.length ?? 0}</span>
                              </div>
                              {artifacts.change_summary.provider_changes?.length ? (
                                <div className="graph-record-row">
                                  <span>Provider changes</span>
                                  <span>{artifacts.change_summary.provider_changes.length}</span>
                                </div>
                              ) : null}
                              {artifacts.change_summary.technology_changes?.length ? (
                                <div className="graph-record-row">
                                  <span>Technology changes</span>
                                  <span>{artifacts.change_summary.technology_changes.length}</span>
                                </div>
                              ) : null}
                              {artifacts.wildcard?.wildcard_roots?.length ? (
                                <div className="graph-record-row">
                                  <span>Wildcard roots</span>
                                  <span>{artifacts.wildcard.wildcard_roots.length}</span>
                                </div>
                              ) : null}
                              {artifacts.ct_enrichment?.suspicious_hostnames?.length ? (
                                <div className="graph-record-row">
                                  <span>CT suspicious hosts</span>
                                  <span>{artifacts.ct_enrichment.suspicious_hostnames.length}</span>
                                </div>
                              ) : null}
                            </div>
                          </details>
                        ) : null}
                        <details>
                          <summary className="muted">Raw JSON artifacts</summary>
                          <button className="ghost export-btn" onClick={exportArtifactsJson}>
                            Export
                          </button>
                          <pre className="code">
                            {JSON.stringify(artifacts, null, 2)}
                          </pre>
                        </details>
                      </div>
                    ) : null}
                  </div>
                ) : (
                  <div className="muted">Section minimized</div>
                )}
                  </section>
              </>
            </>
          )}

          {error ? <div className="toast">{error}</div> : null}
        </main>
      </div>
      {settingsOpen ? (
        <div className="settings-backdrop" onClick={() => setSettingsOpen(false)}>
          <div
            className={`settings-panel ${isAdmin ? "settings-panel--large" : ""}`.trim()}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="panel-header">
              <h2>Settings</h2>
              <button className="ghost" onClick={() => setSettingsOpen(false)}>
                Close
              </button>
            </div>
            <div className="settings-row">
              <div className="settings-toggle">
                <div>
                  <div className="settings-label">Theme</div>
                  <div className="muted">
                    {theme === "dark" ? "Dark mode" : "Light mode"}
                  </div>
                </div>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={theme === "dark"}
                    onChange={(e) => {
                      const nextTheme = e.target.checked ? "dark" : "light";
                      setTheme(nextTheme);
                      setThemeForUser(activeUserId || "", nextTheme);
                    }}
                  />
                  <span className="toggle-track">
                    <span className="toggle-thumb" />
                  </span>
                </label>
              </div>
            </div>
            <div className="settings-row">
              <label>
                Max graph labels ({maxLabelCap})
                <input
                  type="range"
                  min="12"
                  max="120"
                  step="4"
                  value={maxLabelCap}
                  onChange={(e) => setMaxLabelCap(Number(e.target.value))}
                />
              </label>
            </div>
            <div className="settings-row">
              <div className="settings-toggle">
                <div>
                  <div className="settings-label">Minimum CVE Severity</div>
                  <div className="muted">
                    Only CVEs at or above this severity level will be displayed.
                  </div>
                </div>
                <select
                  value={minCveSeverity}
                  onChange={(e) => {
                    const next = e.target.value;
                    setMinCveSeverity(next);
                    window.localStorage.setItem(MIN_CVE_SEVERITY_KEY, next);
                  }}
                >
                  {["Critical", "High", "Medium", "Low"].map((level) => (
                    <option key={level} value={level}>
                      {level}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            {isAdmin ? (
              <div className="settings-row">
                <div className="panel-header">
                  <h3>Manage companies</h3>
                </div>
                <div className="settings-company-list">
                  {allCompanies.length ? (
                    allCompanies.map((company) => (
                      <div key={company.slug} className="settings-company-row">
                        <div>
                          <div className="settings-company-name">{company.name}</div>
                          <div className="muted">{company.slug}</div>
                        </div>
                        <label className="settings-company-group">
                          Group ID
                          <select
                            value={companyGroups[company.slug] || groups[0] || ""}
                            onChange={(e) =>
                              handleCompanyGroupChange(company.slug, e.target.value)
                            }
                          >
                            {groups.map((groupId) => (
                              <option key={groupId} value={groupId}>
                                {groupId}
                              </option>
                            ))}
                          </select>
                        </label>
                      </div>
                    ))
                  ) : (
                    <div className="muted">No companies available.</div>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
      {userModalOpen ? (
        <div className="modal-backdrop" onClick={() => setUserModalOpen(false)}>
          <div
            className="user-modal-panel"
            onClick={(e) => e.stopPropagation()}
            style={{
              left: userModalRect.x,
              top: userModalRect.y,
              width: userModalRect.width,
              height: userModalRect.height,
            }}
          >
            <div className="panel-header user-modal-header" onMouseDown={startUserModalDrag}>
              <div>
                <h2>User Access</h2>
                <div className="muted">
                  Switch users, create new profiles, and manage groups.
                </div>
              </div>
              <button className="ghost" onClick={() => setUserModalOpen(false)}>
                Close
              </button>
            </div>
            {userError ? <div className="user-error">{userError}</div> : null}
            <div className="user-modal-grid">
              <section className="panel">
                <h3>Switch user</h3>
                <div className="row">
                  <select
                    value={switchUserId}
                    onChange={(e) => setSwitchUserId(e.target.value)}
                  >
                    <option value="">Select user</option>
                    {users.map((user) => (
                      <option key={user.id} value={user.id}>
                        {user.username} · {user.role}
                      </option>
                    ))}
                  </select>
                  <button disabled={!switchUserId} onClick={handleSwitchUser}>
                    Set active
                  </button>
                </div>
                <div className="muted">
                  Active: {activeUser ? activeUser.username : "None"}
                </div>
                <button className="ghost" onClick={() => setStoredActiveUser("")}>
                  Logout
                </button>
              </section>

              <section className="panel">
                <h3>Create user</h3>
                <label>
                  Username
                  <input
                    value={newUserName}
                    onChange={(e) => setNewUserName(e.target.value)}
                  />
                </label>
                <label>
                  Email
                  <input
                    value={newUserEmail}
                    onChange={(e) => setNewUserEmail(e.target.value)}
                  />
                </label>
                <label>
                  User type
                  <select
                    value={newUserRole}
                    onChange={(e) => setNewUserRole(e.target.value)}
                  >
                    <option value="admin">Admin</option>
                    <option value="standard">Standard</option>
                  </select>
                </label>
                <label>
                  Group ID
                  <select
                    value={newUserGroupChoice}
                    onChange={(e) => setNewUserGroupChoice(e.target.value)}
                    disabled={newUserRole === "admin"}
                  >
                    {groups.map((groupId) => (
                      <option key={groupId} value={groupId}>
                        {groupId}
                      </option>
                    ))}
                    <option value={NEW_GROUP_OPTION}>Create new group</option>
                  </select>
                </label>
                {newUserGroupChoice === NEW_GROUP_OPTION ? (
                  <label>
                    New group ID
                    <input
                      value={newUserGroupId}
                      onChange={(e) => setNewUserGroupId(e.target.value)}
                    />
                  </label>
                ) : null}
                <button onClick={handleCreateUser}>Create user</button>
              </section>
            </div>

            {isAdmin ? (
              <div className="user-admin-grid">
                <section className="panel">
                  <h3>User directory</h3>
                  <div className="user-list">
                    {users.length ? (
                      users.map((user) => (
                        <div key={user.id} className="user-row">
                          <div>
                            <div className="user-name">{user.username}</div>
                            <div className="muted">
                              {user.email} · {user.role}
                              {user.role === "standard"
                                ? ` · Group ${user.groupId || "-"}`
                                : ""}
                            </div>
                          </div>
                          <div className="row">
                            {user.role === "standard" ? (
                              <button
                                className="ghost"
                                onClick={() => startEditUser(user)}
                              >
                                Edit
                              </button>
                            ) : null}
                            <button
                              className="danger ghost"
                              onClick={() => handleRemoveUser(user.id)}
                            >
                              Remove
                            </button>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="muted">No users yet.</div>
                    )}
                  </div>
                </section>

                <section className="panel">
                  <h3>Groups</h3>
                  <div className="group-list">
                    {groups.map((groupId) => (
                      <div key={groupId} className="group-row">
                        <span>{groupId}</span>
                        <button
                          className="danger ghost"
                          onClick={() => handleRemoveGroup(groupId)}
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                </section>
              </div>
            ) : null}

            {isAdmin && editingUserId ? (
              <div className="panel">
                <div className="panel-header">
                  <h3>Edit standard user</h3>
                  <button className="ghost" onClick={() => setEditingUserId("")}>
                    Cancel
                  </button>
                </div>
                <label>
                  Username
                  <input
                    value={editUserName}
                    onChange={(e) => setEditUserName(e.target.value)}
                  />
                </label>
                <label>
                  Email
                  <input
                    value={editUserEmail}
                    onChange={(e) => setEditUserEmail(e.target.value)}
                  />
                </label>
                <label>
                  Group ID
                  <select
                    value={editUserGroupId}
                    onChange={(e) => setEditUserGroupId(e.target.value)}
                  >
                    {groups.map((groupId) => (
                      <option key={groupId} value={groupId}>
                        {groupId}
                      </option>
                    ))}
                  </select>
                </label>
                <button onClick={handleUpdateUser}>Save changes</button>
              </div>
            ) : null}
            <div
              className="user-modal-resize"
              onMouseDown={startUserModalResize}
            />
          </div>
        </div>
      ) : null}
      {customerModalOpen && activeCompany ? (
        <div className="modal-backdrop" onClick={() => setCustomerModalOpen(false)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
            <div className="panel-header">
              <div>
                <h2>Customer details</h2>
                <div className="muted">{activeCompany.slug}</div>
              </div>
              <button className="ghost" onClick={() => setCustomerModalOpen(false)}>
                Close
              </button>
            </div>
            <div className="manage-panels">
              <details className="panel mini" open>
                <summary>Rename customer</summary>
                <div className="row">
                  <input
                    value={renameInput}
                    onChange={(e) => setRenameInput(e.target.value)}
                    disabled={!canManageActiveCompany}
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
                    disabled={!canManageActiveCompany}
                  >
                    Save
                  </button>
                </div>
              </details>

              <details className="panel mini" open>
                <summary>Domains ({activeCompany.domains.length})</summary>
                <div className="domain-list">
                  {activeCompany.domains.map((domain) => (
                    <div key={domain} className="domain-item domain-row">
                      <span>{domain}</span>
                      <button
                        className="danger ghost domain-delete"
                        onClick={() =>
                          runWithStatus(async () => {
                            await removeDomainFromCompany(domain);
                          })
                        }
                        title={`Delete ${domain}`}
                        aria-label={`Delete ${domain}`}
                        disabled={!canManageActiveCompany}
                      >
                        🗑
                      </button>
                    </div>
                  ))}
                </div>
                <label>
                  Add domain
                  <input
                    value={addDomainInput}
                    onChange={(e) => setAddDomainInput(e.target.value)}
                    placeholder="new.example.com"
                    disabled={!canManageActiveCompany}
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
                  disabled={!canManageActiveCompany}
                >
                  Add domain
                </button>
              </details>
              {isAdmin ? (
                <details className="panel mini" open>
                  <summary>Group assignment</summary>
                  <label>
                    Group ID
                    <select
                      value={companyGroups[activeCompany.slug] || groups[0] || ""}
                      onChange={(e) =>
                        handleCompanyGroupChange(activeCompany.slug, e.target.value)
                      }
                    >
                      {groups.map((groupId) => (
                        <option key={groupId} value={groupId}>
                          {groupId}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="muted">
                    Standard users only see companies in their assigned group.
                  </div>
                </details>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
