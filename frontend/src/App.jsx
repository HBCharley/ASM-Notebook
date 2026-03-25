import React, { useEffect, useMemo, useRef, useState } from "react";
import { api, setAuthToken } from "./api.js";
import logoLight from "./assets/logo-light.png";
import logoDark from "./assets/logo-dark.png";
import ExecutiveDashboard from "./components/dashboard/ExecutiveDashboard.jsx";
import SocDashboard from "./components/dashboard/SocDashboard.jsx";
import MultiSelectDropdown from "./components/MultiSelectDropdown.jsx";
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
const USER_MIN_CVE_KEY = "asm.user.min_cve_severity";
const UI_MODE_KEY = "asm_ui_mode";
const NEW_GROUP_OPTION = "__new_group__";
const AUTH_TOKEN_KEY = "asm_auth_id_token";
const UNAUTH_GROUP = "Unauthenticated";
const ADMIN_DEFAULT_GROUP = "Default";
const UNAUTH_USER_ID = "user-unauthenticated";

function normalizeGroups(value) {
  const raw = Array.isArray(value) ? value : [];
  const cleaned = raw
    .map((g) => (typeof g === "string" ? g.trim() : ""))
    .filter((g) => g);
  const next = [];
  const pushUnique = (g) => {
    if (g && !next.includes(g)) next.push(g);
  };
  pushUnique(UNAUTH_GROUP);
  pushUnique(ADMIN_DEFAULT_GROUP);
  cleaned.forEach(pushUnique);
  return next;
}

function normalizeCompanyGroupEntry(value) {
  if (Array.isArray(value)) {
    return Array.from(
      new Set(
        value
          .map((g) => (typeof g === "string" ? g.trim() : ""))
          .filter((g) => g)
      )
    );
  }
  if (typeof value === "string" && value.trim()) {
    return [value.trim()];
  }
  return [];
}

function normalizeCompanyGroups(value) {
  if (!value || typeof value !== "object") return {};
  const next = {};
  Object.keys(value).forEach((slug) => {
    next[slug] = normalizeCompanyGroupEntry(value[slug]);
  });
  return next;
}

function normalizeUsers(value, groups) {
  const list = Array.isArray(value) ? value.filter(Boolean) : [];
  const normalizedGroups = normalizeGroups(groups);
  let changed = false;
  let hasUnauth = false;
  const nextUsers = list.map((user) => {
    if (!user || !user.id || !user.username) {
      changed = true;
      return null;
    }
    const isUnauth =
      user.id === UNAUTH_USER_ID || user.username === UNAUTH_GROUP;
    if (isUnauth) {
      hasUnauth = true;
      const next = {
        ...user,
        id: UNAUTH_USER_ID,
        username: UNAUTH_GROUP,
        role: "standard",
        groupId: UNAUTH_GROUP,
      };
      if (
        user.id !== next.id ||
        user.username !== next.username ||
        user.role !== next.role ||
        user.groupId !== next.groupId
      ) {
        changed = true;
      }
      return next;
    }
    if (user.role !== "admin") {
      const nextGroup = normalizedGroups.includes(user.groupId)
        ? user.groupId
        : UNAUTH_GROUP;
      if (nextGroup !== user.groupId) {
        changed = true;
        return { ...user, groupId: nextGroup };
      }
    }
    return user;
  });
  const filtered = nextUsers.filter(Boolean);
  if (!hasUnauth) {
    filtered.unshift({
      id: UNAUTH_USER_ID,
      username: UNAUTH_GROUP,
      email: "unauthenticated@local",
      role: "standard",
      groupId: UNAUTH_GROUP,
      createdAt: new Date().toISOString(),
    });
    changed = true;
  }
  return { users: filtered, changed };
}

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

function getMinCveSeverityForUser(userId) {
  const map = readStoredJson(USER_MIN_CVE_KEY, {});
  if (userId && map[userId]) return map[userId];
  return map.__guest || "High";
}

function setMinCveSeverityForUser(userId, severity) {
  const map = readStoredJson(USER_MIN_CVE_KEY, {});
  const key = userId || "__guest";
  const next = { ...map, [key]: severity };
  writeStoredJson(USER_MIN_CVE_KEY, next);
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

async function createCustomerFromHeader({
  newCustomerName,
  newCustomerDomain,
  allCompanies,
  setNewCustomerName,
  setNewCustomerDomain,
  loadCompanies,
  setSelectedCustomer,
}) {
  const name = newCustomerName.trim();
  const domain = normalizeDomain(newCustomerDomain);
  if (!name) throw new Error("Customer name is required");
  if (!domain) throw new Error("Domain is required");
  const customer = deriveCustomerFromDomain(domain);
  const existingSlugs = new Set(
    allCompanies.map((c) => (c.slug || "").toLowerCase())
  );
  const uniqueSlug = ensureUniqueSlug(customer.slugBase, existingSlugs);
  const created = await api.createCompany({
    slug: uniqueSlug,
    name,
    domains: [domain],
  });
  setNewCustomerName("");
  setNewCustomerDomain("");
  await loadCompanies();
  setSelectedCustomer(created.slug);
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

// buildNestedTree — builds a parent→children tree from a flat domain list
function buildNestedTree(root, subdomains) {
  const domainSet = new Set(subdomains);
  const childrenOf = new Map([[root, []]]);
  subdomains.forEach((d) => childrenOf.set(d, []));
  const sorted = [...subdomains].sort(
    (a, b) => a.split(".").length - b.split(".").length || a.localeCompare(b)
  );
  sorted.forEach((domain) => {
    const parts = domain.split(".");
    let parent = root;
    for (let i = 1; i < parts.length; i++) {
      const candidate = parts.slice(i).join(".");
      if (candidate === root) { parent = root; break; }
      if (domainSet.has(candidate)) { parent = candidate; break; }
    }
    childrenOf.get(parent).push(domain);
  });
  function buildNode(domain, parentDomain) {
    const label = domain.slice(0, domain.length - parentDomain.length - 1);
    return {
      domain,
      label,
      children: (childrenOf.get(domain) || [])
        .sort((a, b) => a.localeCompare(b))
        .map((c) => buildNode(c, domain)),
    };
  }
  return (childrenOf.get(root) || [])
    .sort((a, b) => a.localeCompare(b))
    .map((d) => buildNode(d, root));
}

function DomainRelationshipGraph({ artifacts, maxLabelCap = 36, minCveSeverity }) {
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [expandedNodes, setExpandedNodes] = useState({});
  const [domainFilter, setDomainFilter] = useState("");
  const [hideUnreachable, setHideUnreachable] = useState(false);

  const roots = useMemo(
    () => Array.from(new Set(artifacts?.domains?.roots || [])).sort(),
    [artifacts]
  );
  const allDomains = useMemo(
    () => Array.from(new Set([...(artifacts?.domains?.domains || []), ...roots])),
    [artifacts, roots]
  );
  const dnsIndex = useMemo(
    () => buildDnsIndex(artifacts?.dns?.records || []),
    [artifacts]
  );
  const riskByDomain = useMemo(() => {
    const map = new Map();
    for (const f of artifacts?.risk?.findings || []) {
      if (!map.has(f.domain)) map.set(f.domain, []);
      map.get(f.domain).push(f);
    }
    return map;
  }, [artifacts]);
  const idbByIp = useMemo(() => artifacts?.shodan_idb || {}, [artifacts]);

  // Expand roots by default
  useEffect(() => {
    setExpandedNodes((prev) => {
      const next = { ...prev };
      roots.forEach((r) => { if (!(r in next)) next[r] = true; });
      return next;
    });
  }, [roots.join(",")]); // eslint-disable-line react-hooks/exhaustive-deps

  const treeByRoot = useMemo(() => {
    const result = {};
    for (const root of roots) {
      const subs = allDomains.filter((d) => d !== root && isInRootScope(d, root));
      result[root] = buildNestedTree(root, subs);
    }
    return result;
  }, [roots, allDomains]);

  const totalDomains = allDomains.length - roots.length;
  const filterLower = domainFilter.toLowerCase().trim();

  const SEV = { critical: "var(--danger)", high: "#f59e0b", medium: "#3b82f6", low: "#6b7280" };

  function topSevColour(domain) {
    const ff = riskByDomain.get(domain) || [];
    for (const s of ["critical", "high", "medium", "low"]) {
      if (ff.some((f) => f.severity === s)) return SEV[s];
    }
    return null;
  }

  function dnsBadges(dns) {
    if (!dns) return [{ k: "no-dns" }];
    const out = [];
    if (dns.A?.length)     out.push({ k: "A:" + dns.A.length });
    if (dns.AAAA?.length)  out.push({ k: "AAAA:" + dns.AAAA.length });
    if (dns.CNAME?.length) out.push({ k: "CN:" + dns.CNAME.length });
    if (dns.MX?.length)    out.push({ k: "MX:" + dns.MX.length });
    return out.slice(0, 3);
  }

  function anyMatch(node) {
    if (!filterLower) return true;
    if (node.domain.includes(filterLower)) return true;
    return node.children.some(anyMatch);
  }

  function renderNode(node, depth) {
    if (!anyMatch(node)) return null;
    const { domain, label, children } = node;
    const dns = dnsIndex.get(domain);
    if (hideUnreachable && (!dns || (!dns.A?.length && !dns.AAAA?.length))) return null;
    const hasCh = children.length > 0;
    const expanded = !!expandedNodes[domain];
    const selected = selectedDomain === domain;
    const sev = topSevColour(domain);
    const firstIp = dns?.ips?.[0] || "";
    const badges = dnsBadges(dns);
    return (
      <div key={domain}>
        <button
          className={"tree-item tree-item-domain" + (selected ? " active" : "")}
          style={{ paddingLeft: 8 + depth * 16, gap: 5, width: "100%", display: "flex", alignItems: "center" }}
          onClick={() => {
            setSelectedDomain(selected ? null : domain);
            if (hasCh) setExpandedNodes((p) => ({ ...p, [domain]: !p[domain] }));
          }}
        >
          <span style={{ color: "var(--muted)", fontSize: 10, minWidth: 10, flexShrink: 0 }}>
            {hasCh ? (expanded ? "\u25be" : "\u25b8") : "\u00b7"}
          </span>
          {sev && <span style={{ width: 6, height: 6, borderRadius: "50%", background: sev, flexShrink: 0 }} />}
          <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", textAlign: "left" }}>
            <span style={{ fontWeight: 600 }}>{label}</span>
            <span className="muted" style={{ fontSize: 11 }}>{"." + domain.slice(label.length + 1)}</span>
          </span>
          {firstIp && <span className="muted" style={{ fontSize: 11, flexShrink: 0, marginRight: 4 }}>{firstIp}</span>}
          <span style={{ display: "flex", gap: 2, flexShrink: 0 }}>
            {badges.map((b) => <span key={b.k} className="graph-chip" style={{ fontSize: 10, padding: "1px 4px" }}>{b.k}</span>)}
          </span>
        </button>
        {hasCh && expanded && <div>{children.map((c) => renderNode(c, depth + 1))}</div>}
      </div>
    );
  }

  const selDns   = selectedDomain ? dnsIndex.get(selectedDomain) : null;
  const selRisk  = selectedDomain ? (riskByDomain.get(selectedDomain) || []) : [];
  const selIps   = selDns?.ips || [];
  const selIdb   = selIps.map((ip) => (idbByIp[ip] ? { ip, ...idbByIp[ip] } : null)).filter(Boolean);

  if (!roots.length) return <div className="empty">No domain artifacts for this scan.</div>;

  return (
    <div className="graph-wrap">
      <div className="graph-meta muted" style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", paddingBottom: 8 }}>
        <span>{roots.length} {roots.length === 1 ? "root" : "roots"} &middot; {totalDomains} domains</span>
        <input type="search" value={domainFilter} onChange={(e) => setDomainFilter(e.target.value)}
          placeholder="Filter domains..."
          style={{ fontSize: 12, padding: "2px 8px", background: "var(--card)", border: "1px solid var(--line)", borderRadius: 4, color: "var(--ink)", width: 200 }} />
        <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 12, cursor: "pointer" }}>
          <input type="checkbox" checked={hideUnreachable} onChange={(e) => setHideUnreachable(e.target.checked)} />
          Hide no-DNS
        </label>
      </div>

      <div style={{ display: "flex", height: "clamp(420px, 60vh, 780px)", border: "1px solid var(--line)", borderRadius: 6, overflow: "hidden" }}>
        <div className="panel"
          style={{ flex: selectedDomain ? "0 0 52%" : "1 1 100%", overflowY: "auto", borderRight: selectedDomain ? "1px solid var(--line)" : "none", padding: "6px 0" }}>
          {roots.map((root) => {
            const open = !!expandedNodes[root];
            const nodes = treeByRoot[root] || [];
            const cnt = allDomains.filter((d) => d !== root && isInRootScope(d, root)).length;
            const sev = topSevColour(root);
            if (filterLower && !root.includes(filterLower) && !nodes.some(anyMatch)) return null;
            return (
              <div key={root} className="tree-branch">
                <button
                  className={"tree-item tree-item-root" + (selectedDomain === root ? " active" : "")}
                  style={{ display: "flex", alignItems: "center", gap: 6, width: "100%", paddingLeft: 10 }}
                  onClick={() => {
                    setSelectedDomain(selectedDomain === root ? null : root);
                    setExpandedNodes((p) => ({ ...p, [root]: !p[root] }));
                  }}
                >
                  <span style={{ fontSize: 11, minWidth: 10, flexShrink: 0 }}>{open ? "\u25be" : "\u25b8"}</span>
                  {sev && <span style={{ width: 7, height: 7, borderRadius: "50%", background: sev, flexShrink: 0 }} />}
                  <span style={{ fontSize: 13 }}>{open ? "\uD83D\uDCC2" : "\uD83D\uDCC1"}</span>
                  <strong style={{ flex: 1, textAlign: "left" }}>{root}</strong>
                  <span className="tree-count">{cnt}</span>
                </button>
                {open && (
                  <div className="tree-children">
                    {nodes.length === 0
                      ? <div className="muted tree-empty" style={{ paddingLeft: 32 }}>No discovered subdomains</div>
                      : nodes.map((n) => renderNode(n, 1))}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {selectedDomain && (
          <div className="panel" style={{ flex: "0 0 48%", overflowY: "auto", padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10, gap: 8 }}>
              <span style={{ fontWeight: 700, wordBreak: "break-all", fontSize: 13 }}>{selectedDomain}</span>
              <button onClick={() => setSelectedDomain(null)}
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted)", fontSize: 18, lineHeight: 1, padding: 0, flexShrink: 0 }}>&times;</button>
            </div>

            {selRisk.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                {selRisk.map((f, i) => (
                  <div key={i} style={{ fontSize: 12, padding: "5px 8px", marginBottom: 4, borderRadius: 4,
                    background: (SEV[f.severity] || "var(--line)") + "22",
                    borderLeft: "3px solid " + (SEV[f.severity] || "var(--line)") }}>
                    <span style={{ fontWeight: 700, textTransform: "uppercase", fontSize: 10, marginRight: 6 }}>{f.severity}</span>
                    {f.detail}
                  </div>
                ))}
              </div>
            )}

            <div className="graph-kv">
              <span>DNS Records</span>
              <span>{selDns ? Object.entries(selDns).filter(([k,v])=>Array.isArray(v)&&v.length&&k!=="ips").reduce((s,[,v])=>s+v.length,0) : 0}</span>
            </div>
            {selDns ? (
              <div className="graph-records">
                {["A","AAAA","CNAME","MX","NS","TXT","SOA","CAA"].map((k) => {
                  const vals = selDns[k] || [];
                  if (!vals.length) return null;
                  return (
                    <div key={k}>
                      <div className="graph-record-row"><span>{k}</span><span>{vals.length}</span></div>
                      <div className="graph-chip-list" style={{ paddingLeft: 10, marginBottom: 3 }}>
                        {vals.slice(0,6).map((v) => <span key={v} className="graph-chip" style={{ fontSize: 11 }}>{v}</span>)}
                        {vals.length > 6 && <span className="muted" style={{ fontSize: 11 }}>+{vals.length-6} more</span>}
                      </div>
                    </div>
                  );
                })}
                {selIps.length > 0 && (
                  <div className="graph-list-block">
                    <div className="muted">IPs</div>
                    <div className="graph-chip-list">
                      {selIps.slice(0,8).map((ip) => <span key={ip} className="graph-chip" style={{ fontSize: 11 }}>{ip}</span>)}
                      {selIps.length > 8 && <span className="muted" style={{ fontSize: 11 }}>+{selIps.length-8} more</span>}
                    </div>
                  </div>
                )}
              </div>
            ) : <div className="muted" style={{ fontSize: 12 }}>No DNS data for this domain.</div>}

            {selIdb.length > 0 && (
              <details className="graph-details" open>
                <summary>Shodan InternetDB</summary>
                {selIdb.map(({ ip, ports, vulns, tags, cpes }) => (
                  <div key={ip} style={{ marginBottom: 8 }}>
                    <div className="graph-record-row"><span>IP</span><span>{ip}</span></div>
                    {ports?.length > 0 && <div className="graph-record-row"><span>Open ports</span><span style={{ fontSize: 11 }}>{ports.join(", ")}</span></div>}
                    {vulns?.length > 0 && <div className="graph-list-block"><div className="muted" style={{ fontSize: 11 }}>CVEs</div>
                      <div className="graph-chip-list">{vulns.map((v) => <span key={v} className="graph-chip" style={{ fontSize: 10, background: "rgba(201,61,47,0.18)" }}>{v}</span>)}</div></div>}
                    {tags?.length > 0 && <div className="graph-chip-list">{tags.map((t) => <span key={t} className="graph-chip" style={{ fontSize: 11 }}>{t}</span>)}</div>}
                    {cpes?.length > 0 && <div className="graph-list-block"><div className="muted" style={{ fontSize: 11 }}>CPEs</div>
                      <div className="graph-chip-list">{cpes.slice(0,4).map((c) => <span key={c} className="graph-chip" style={{ fontSize: 10 }}>{c}</span>)}
                      {cpes.length > 4 && <span className="muted" style={{ fontSize: 11 }}>+{cpes.length-4} more</span>}</div></div>}
                  </div>
                ))}
              </details>
            )}
          </div>
        )}
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
  const [artifactsScanId, setArtifactsScanId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [theme, setTheme] = useState(() => getThemeForUser(""));
  const [uiMode, setUiMode] = useState(() => {
    if (typeof window === "undefined") return "executive";
    const stored =
      window.localStorage.getItem(UI_MODE_KEY) ||
      window.localStorage.getItem("asm.ui.mode");
    return stored ? normalizeUiMode(stored) : "executive";
  });
  const [minCveSeverity, setMinCveSeverity] = useState(() =>
    getMinCveSeverityForUser("")
  );
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
  const scanPollRef = useRef({ slug: null, startedAtMs: null, timer: null });
  const scansRef = useRef(scans);
  const selectedScanIdRef = useRef(selectedScanId);
  const artifactsScanIdRef = useRef(artifactsScanId);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [customerModalOpen, setCustomerModalOpen] = useState(false);
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [manageCompaniesOpen, setManageCompaniesOpen] = useState(false);
  const [manageGroupsOpen, setManageGroupsOpen] = useState(false);
  const [maxLabelCap, setMaxLabelCap] = useState(36);
  const [newCustomerName, setNewCustomerName] = useState("");
  const [newCustomerDomain, setNewCustomerDomain] = useState("");
  const [adminCustomerName, setAdminCustomerName] = useState("");
  const [adminCustomerDomain, setAdminCustomerDomain] = useState("");
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
  const [groups, setGroups] = useState(() =>
    normalizeGroups(readStoredJson(GROUP_STORAGE_KEY, []))
  );
  const [users, setUsers] = useState(() => {
    const storedGroups = normalizeGroups(readStoredJson(GROUP_STORAGE_KEY, []));
    return normalizeUsers(readStoredJson(USER_STORAGE_KEY, []), storedGroups).users;
  });
  const [companyGroups, setCompanyGroups] = useState(() =>
    normalizeCompanyGroups(readStoredJson(COMPANY_GROUP_KEY, {}))
  );
  const [activeUserId, setActiveUserId] = useState(
    () => window.localStorage.getItem(ACTIVE_USER_KEY) || UNAUTH_USER_ID
  );
  const [userError, setUserError] = useState("");
  const [authAllowlist, setAuthAllowlist] = useState([]);
  const [authAllowEmail, setAuthAllowEmail] = useState("");
  const [authAllowRole, setAuthAllowRole] = useState("user");
  const [authAllowError, setAuthAllowError] = useState("");
  const [newUserName, setNewUserName] = useState("");
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserRole, setNewUserRole] = useState("standard");
  const [newUserGroupId, setNewUserGroupId] = useState("");
  const [newGroupName, setNewGroupName] = useState("");
  const [newUserGroupChoice, setNewUserGroupChoice] = useState(
    groups[0] || UNAUTH_GROUP
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
    if (!googleClientId || authToken) return;
    let cancelled = false;
    let attempts = 0;
    const tryRender = () => {
      if (cancelled) return;
      if (!window.google?.accounts?.id) {
        attempts += 1;
        if (attempts < 20) {
          setTimeout(tryRender, 250);
        }
        return;
      }
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
    };
    tryRender();
    return () => {
      cancelled = true;
    };
  }, [googleClientId, authToken, settingsOpen]);

  const activeUser = useMemo(
    () => users.find((u) => u.id === activeUserId) || null,
    [users, activeUserId]
  );
  useEffect(() => {
    if (!users.length) return;
    if (!activeUserId || !users.some((u) => u.id === activeUserId)) {
      setStoredActiveUser(UNAUTH_USER_ID);
      setSwitchUserId(UNAUTH_USER_ID);
    }
  }, [users, activeUserId]);
  const isAdmin = me.role === "admin";
  const publicSlugs = useMemo(
    () => new Set(me.public_company_slugs || []),
    [me.public_company_slugs]
  );
  const companies = useMemo(() => allCompanies, [allCompanies]);
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
    () => scans.some((s) => s.status === "running" || s.status === "queued"),
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
    const nextCompanyGroups = {};
    const nextGroups = new Set(normalizeGroups(groups));
    for (const company of data) {
      const assigned = normalizeCompanyGroupEntry(company.groups || []);
      nextCompanyGroups[company.slug] = assigned;
      assigned.forEach((groupId) => nextGroups.add(groupId));
    }
    const normalizedCompanyGroups = normalizeCompanyGroups(nextCompanyGroups);
    const normalizedGroups = normalizeGroups(Array.from(nextGroups));
    setCompanyGroups(normalizedCompanyGroups);
    writeStoredJson(COMPANY_GROUP_KEY, normalizedCompanyGroups);
    if (normalizedGroups.join("|") !== normalizeGroups(groups).join("|")) {
      setGroups(normalizedGroups);
      writeStoredJson(GROUP_STORAGE_KEY, normalizedGroups);
    }
  }

  async function loadGroups() {
    if (!isAdmin) return;
    const data = await api.listGroups();
    const normalized = normalizeGroups(Array.isArray(data) ? data : []);
    setGroups(normalized);
    writeStoredJson(GROUP_STORAGE_KEY, normalized);
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
      setArtifactsScanId(null);
    }
  }

  async function loadArtifacts(slug, scanId) {
    const data = await api.getArtifacts(slug, scanId);
    setArtifacts(data);
    setArtifactsScanId(scanId);
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
        setArtifactsScanId(null);
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
    setArtifactsScanId(null);
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
    const { users: normalized } = normalizeUsers(next, groups);
    setUsers(normalized);
    writeStoredJson(USER_STORAGE_KEY, normalized);
  }

  function setStoredGroups(next) {
    const normalized = normalizeGroups(next);
    setGroups(normalized);
    writeStoredJson(GROUP_STORAGE_KEY, normalized);
  }

  function setStoredActiveUser(nextId) {
    const next = nextId || UNAUTH_USER_ID;
    setActiveUserId(next);
    window.localStorage.setItem(ACTIVE_USER_KEY, next);
  }

  function resetUserForm() {
    setNewUserName("");
    setNewUserEmail("");
    setNewUserRole("standard");
    setNewUserGroupChoice(groups[0] || UNAUTH_GROUP);
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
    let nextGroups = normalizeGroups(groups);
    if (groupId && !nextGroups.includes(groupId)) {
      nextGroups.push(groupId);
    }
    if (role === "standard" && !groupId) {
      groupId = UNAUTH_GROUP;
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
    if (target.id === UNAUTH_USER_ID) {
      setUserError("The Unauthenticated user cannot be removed.");
      return;
    }
    if (!confirm(`Remove user ${target.username}?`)) return;
    const next = users.filter((u) => u.id !== userId);
    setStoredUsers(next);
    if (activeUserId === userId) {
      setStoredActiveUser(UNAUTH_USER_ID);
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
    const nextGroupId = editUserGroupId.trim();
    if (!nextGroupId) {
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
        groupId: u.role === "standard" ? nextGroupId : u.groupId,
      };
    });
    setStoredUsers(nextUsers);
    if (!groups.includes(nextGroupId)) {
      setStoredGroups([...groups, nextGroupId]);
    }
    setEditingUserId("");
  }

  async function handleRemoveGroup(groupId) {
    if (!groupId) return;
    if (groupId === UNAUTH_GROUP || groupId === ADMIN_DEFAULT_GROUP) {
      setUserError("Default groups cannot be removed.");
      return;
    }
    if (!confirm(`Remove group ${groupId}?`)) return;
    await api.deleteGroup(groupId);
    await loadGroups();
    await loadCompanies();
  }

  async function handleAddGroup() {
    const value = newGroupName.trim();
    if (!value) return;
    await api.createGroup({ name: value });
    setNewGroupName("");
    await loadGroups();
  }

  async function loadAuthAllowlist() {
    if (!isAdmin) return;
    setAuthAllowError("");
    try {
      const data = await api.listAuthAllowlist();
      setAuthAllowlist(Array.isArray(data) ? data : []);
    } catch (err) {
      setAuthAllowError(err?.message || "Failed to load allowlist.");
    }
  }

  async function handleAddAuthAllowlist() {
    if (!authAllowEmail.trim()) {
      setAuthAllowError("Email is required.");
      return;
    }
    setAuthAllowError("");
    try {
      const payload = {
        email: authAllowEmail.trim(),
        role: authAllowRole,
      };
      await api.addAuthAllowlist(payload);
      setAuthAllowEmail("");
      await loadAuthAllowlist();
    } catch (err) {
      setAuthAllowError(err?.message || "Failed to add email.");
    }
  }

  async function handleRemoveAuthAllowlist(email) {
    if (!confirm(`Remove ${email} from allowlist?`)) return;
    setAuthAllowError("");
    try {
      await api.deleteAuthAllowlist(email);
      await loadAuthAllowlist();
    } catch (err) {
      setAuthAllowError(err?.message || "Failed to remove email.");
    }
  }

  async function updateCompanyGroupSelection(slug, nextGroups) {
    if (!slug) return;
    const normalized = normalizeCompanyGroupEntry(nextGroups);
    const payload = normalized.length ? normalized : [ADMIN_DEFAULT_GROUP];
    const response = await api.updateCompanyGroups(slug, payload);
    const finalGroups = normalizeCompanyGroupEntry(response?.groups || payload);
    setCompanyGroups((current) => {
      const next = { ...current, [slug]: finalGroups };
      writeStoredJson(COMPANY_GROUP_KEY, normalizeCompanyGroups(next));
      return next;
    });
    if (finalGroups.length) {
      const merged = normalizeGroups([...groups, ...finalGroups]);
      if (merged.join("|") !== normalizeGroups(groups).join("|")) {
        setGroups(merged);
        writeStoredJson(GROUP_STORAGE_KEY, merged);
      }
    }
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
    runWithStatus(async () => {
      await loadCompanies();
      await loadGroups();
    });
  }, [authReady, isAdmin, me.role, me.email]);

  useEffect(() => {
    const normalized = normalizeGroups(groups);
    if (normalized.join("|") !== groups.join("|")) {
      setStoredGroups(normalized);
    }
  }, [groups]);

  useEffect(() => {
    scansRef.current = scans;
  }, [scans]);

  useEffect(() => {
    selectedScanIdRef.current = selectedScanId;
  }, [selectedScanId]);

  useEffect(() => {
    artifactsScanIdRef.current = artifactsScanId;
  }, [artifactsScanId]);

  useEffect(() => {
    const { users: normalized, changed } = normalizeUsers(users, groups);
    if (changed) {
      setUsers(normalized);
      writeStoredJson(USER_STORAGE_KEY, normalized);
    }
  }, [groups]);

  useEffect(() => {
    if (!newUserGroupChoice) {
      setNewUserGroupChoice(groups[0] || UNAUTH_GROUP);
      return;
    }
    if (
      newUserGroupChoice !== NEW_GROUP_OPTION &&
      !groups.includes(newUserGroupChoice)
    ) {
      setNewUserGroupChoice(groups[0] || UNAUTH_GROUP);
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
        setArtifactsScanId(null);
      }
      return;
    }
    if (!canCreateCompany && companies.length) {
      setSelectedCustomer(companies[0].slug);
    }
  }, [companies, selectedCustomer, canCreateCompany]);

  useEffect(() => {
    if (!userModalOpen) return;
    setSwitchUserId(activeUserId || UNAUTH_USER_ID);
    setUserError("");
    setEditingUserId("");
    setAuthAllowError("");
    if (isAdmin) {
      loadAuthAllowlist();
    }
  }, [userModalOpen, activeUserId, isAdmin]);

  useEffect(() => {
    if (!artifacts) {
      setShowSource(false);
      setSourceKey("");
      return;
    }
    if (!sourceKey) {
      setSourceKey(
        artifacts.dns_intel
          ? "dns_intel"
          : artifacts.domains
            ? "domains"
            : artifacts.dns
              ? "dns"
              : artifactKeys[0] || ""
      );
    }
  }, [artifacts, artifactKeys, sourceKey]);

  useEffect(() => {
    const nextTheme = getThemeForUser(activeUserId || "");
    setTheme(nextTheme);
  }, [activeUserId]);

  useEffect(() => {
    const nextMin = getMinCveSeverityForUser(activeUserId || "");
    setMinCveSeverity(nextMin);
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
    if (
      !settingsOpen &&
      !userModalOpen &&
      !customerModalOpen &&
      !manageCompaniesOpen &&
      !manageGroupsOpen
    ) {
      return;
    }
    const onKeyDown = (event) => {
      if (event.key !== "Escape") return;
      setSettingsOpen(false);
      setUserModalOpen(false);
      setCustomerModalOpen(false);
      setManageCompaniesOpen(false);
      setManageGroupsOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    settingsOpen,
    userModalOpen,
    customerModalOpen,
    manageCompaniesOpen,
    manageGroupsOpen,
  ]);

  useEffect(() => {
    const slug = activeCompany?.slug;
    if (!slug || !hasRunningScan) {
      if (scanPollRef.current.timer) {
        clearTimeout(scanPollRef.current.timer);
      }
      scanPollRef.current = { slug: null, startedAtMs: null, timer: null };
      return undefined;
    }

    if (scanPollRef.current.slug !== slug) {
      scanPollRef.current.slug = slug;
      scanPollRef.current.startedAtMs = Date.now();
    }
    if (!scanPollRef.current.startedAtMs) {
      scanPollRef.current.startedAtMs = Date.now();
    }

    let cancelled = false;

    const delayForElapsedMs = (elapsedMs) => {
      if (elapsedMs < 120_000) return 10_000; // 0–2 minutes
      if (elapsedMs < 300_000) return 20_000; // 2–5 minutes
      return 60_000; // 5+ minutes
    };

    const scheduleNext = () => {
      if (cancelled) return;
      const startedAt = scanPollRef.current.startedAtMs || Date.now();
      const elapsed = Date.now() - startedAt;
      const delay = delayForElapsedMs(elapsed);
      if (scanPollRef.current.timer) {
        clearTimeout(scanPollRef.current.timer);
      }
      scanPollRef.current.timer = setTimeout(poll, delay);
    };

    const poll = async () => {
      try {
        const scanResp = await api.listScansIfModified(slug);
        if (cancelled) return;
        const nextScans = scanResp.notModified
          ? scansRef.current
          : Array.isArray(scanResp.data)
            ? scanResp.data
            : [];
        if (!scanResp.notModified) {
          setScans(nextScans);
        }

        const currentSelectedScanId = selectedScanIdRef.current;
        if (currentSelectedScanId) {
          const selected = nextScans.find((s) => s.id === currentSelectedScanId);
          if (
            selected &&
            selected.status === "success" &&
            artifactsScanIdRef.current !== currentSelectedScanId
          ) {
            const artResp = await api.getArtifactsIfModified(
              slug,
              currentSelectedScanId
            );
            if (!cancelled && !artResp.notModified) {
              setArtifacts(artResp.data);
              setArtifactsScanId(currentSelectedScanId);
            }
          }
        }
      } catch (_err) {
        // Keep polling silent; transient failures should not spam UI toasts.
      } finally {
        scheduleNext();
      }
    };

    poll();
    return () => {
      cancelled = true;
      if (scanPollRef.current.timer) {
        clearTimeout(scanPollRef.current.timer);
      }
    };
  }, [activeCompany?.slug, hasRunningScan]);

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
                    await createCustomerFromHeader({
                      newCustomerName,
                      newCustomerDomain,
                      allCompanies,
                      setNewCustomerName,
                      setNewCustomerDomain,
                      loadCompanies,
                      setSelectedCustomer,
                    });
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
        </div>
        <div className="status">
          <div className="status-line">
            <button className="ghost" onClick={() => setSettingsOpen(true)} aria-label="Open settings">
              ⚙
            </button>
            <div className="status-view">
              <ViewModeSwitcher value={uiMode} onChange={persistUiMode} />
            </div>
            <span
              className={`dot ${isActive ? "active blink" : "idle"}`.trim()}
            />
            <span className="status-activity">
              {isActive ? "Activity" : "Idle"}
            </span>
          </div>
          <div className="status-user">
            <div className="muted user-meta">Role: {me.role}</div>
            {me.email ? <div className="muted user-meta">{me.email}</div> : null}
            <div className="auth-controls auth-controls--status">
              <button
                className="ghost header-action"
                type="button"
                onClick={() => setAboutOpen(true)}
              >
                About
              </button>
              {authToken ? (
                <button className="ghost header-action" onClick={() => clearAuth()}>
                  Sign out
                </button>
              ) : googleClientId ? (
                <div ref={googleButtonRef} />
              ) : (
                <div className="muted auth-meta">Google auth not configured</div>
              )}
            </div>
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
                          setArtifactsScanId(null);
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
                        setArtifactsScanId(null);
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
                          setArtifactsScanId(null);
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
                        setArtifactsScanId(null);
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
                          setArtifactsScanId(null);
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
                    <div className="muted">
                      This can take several minutes. Please Standby.
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
                                    setArtifactsScanId(null);
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
                                setArtifactsScanId(null);
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
                                      {entry.notice ? (
                                        <div className="muted">{entry.notice}</div>
                                      ) : null}
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
                    setMinCveSeverityForUser(activeUserId || "", next);
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
            <div className="settings-row settings-row--mobile">
              <div className="settings-toggle">
                <div>
                  <div className="settings-label">Account</div>
                  <div className="muted">
                    Role: {me.role}
                    {me.email ? ` · ${me.email}` : ""}
                  </div>
                </div>
                <div className="settings-actions">
                  {authToken ? (
                    <button className="ghost" onClick={() => clearAuth()}>
                      Sign out
                    </button>
                  ) : googleClientId ? (
                    <div ref={googleButtonRef} />
                  ) : (
                    <div className="muted auth-meta">Google auth not configured</div>
                  )}
                </div>
              </div>
            </div>
            <div className="settings-row settings-row--mobile">
              <div className="settings-toggle">
                <div>
                  <div className="settings-label">Actions</div>
                  <div className="muted">Quick access to common tasks.</div>
                </div>
                <div className="settings-actions">
                  <button
                    className="ghost"
                    onClick={() => runWithStatus(loadCompanies)}
                  >
                    Refresh
                  </button>
                  {activeCompany ? (
                    <button
                      className="ghost"
                      onClick={() => setCustomerModalOpen(true)}
                      disabled={!canManageActiveCompany}
                      title={canManageActiveCompany ? "Manage details" : "Read-only access"}
                    >
                      Manage details
                    </button>
                  ) : null}
                </div>
              </div>
            </div>
            {canCreateCompany ? (
              <div className="settings-row settings-row--mobile">
                <div className="settings-toggle">
                  <div>
                    <div className="settings-label">Create customer</div>
                    <div className="muted">Add a new customer from mobile.</div>
                  </div>
                </div>
                <div className="settings-actions">
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
                    onClick={() =>
                      runWithStatus(async () => {
                    await createCustomerFromHeader({
                      newCustomerName,
                      newCustomerDomain,
                      allCompanies,
                      setNewCustomerName,
                      setNewCustomerDomain,
                      loadCompanies,
                      setSelectedCustomer,
                    });
                      })
                    }
                  >
                    Create
                  </button>
                </div>
              </div>
            ) : null}
            {isAdmin ? (
              <div className="settings-row">
                <div className="settings-toggle">
                  <div>
                    <div className="settings-label">Admin tools</div>
                    <div className="muted">Manage companies and auth access.</div>
                  </div>
                  <div className="settings-actions">
                    <button className="ghost" onClick={() => setManageCompaniesOpen(true)}>
                      Manage companies
                    </button>
                    <button className="ghost" onClick={() => setManageGroupsOpen(true)}>
                      Manage groups
                    </button>
                    <button className="ghost" onClick={() => setUserModalOpen(true)}>
                      Manage users
                    </button>
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
      {aboutOpen ? (
        <div className="settings-backdrop" onClick={() => setAboutOpen(false)}>
          <div className="settings-panel" onClick={(e) => e.stopPropagation()}>
            <div className="panel-header">
              <h2>About</h2>
              <button className="ghost" onClick={() => setAboutOpen(false)}>
                Close
              </button>
            </div>
            <div className="settings-row">
              <div className="muted" style={{ whiteSpace: "pre-line" }}>
                {
                  "ASM Notebook is an experimental Attack Surface Management (ASM) platform that maps external infrastructure using passive OSINT signals.\n\nIt inventories domains, DNS records, HTTP metadata, and scan history to create a structured view of exposed assets. The system emphasizes lightweight architecture, operator-controlled deployment, and transparent infrastructure over opaque SaaS tooling.\n\nASM Notebook was built as a hands-on exploration of modern security tooling design, combining containerized services, task orchestration, and structured asset tracking into a simple deployable platform.\n\nCreated by Charley Thomas\nSolutions Engineering & Technical Strategy — Cloud and Security"
                }
              </div>
            </div>
            <div className="settings-row">
              <a className="ghost header-action" href="https://charleyt.net" target="_blank" rel="noreferrer">
                → Visit charleyt.net
              </a>
            </div>
          </div>
        </div>
      ) : null}
      {manageCompaniesOpen && isAdmin ? (
        <div className="modal-backdrop" onClick={() => setManageCompaniesOpen(false)}>
          <div
            className="modal-panel manage-companies-panel"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="panel-header">
              <div>
                <h2>Manage companies</h2>
                <div className="muted">Add new customers and assign groups.</div>
              </div>
              <button className="ghost" onClick={() => setManageCompaniesOpen(false)}>
                Close
              </button>
            </div>
            <div className="manage-companies-grid">
              <section className="panel">
                <h3>Add company</h3>
                <label>
                  Name
                  <input
                    value={adminCustomerName}
                    onChange={(e) => setAdminCustomerName(e.target.value)}
                    placeholder="Acme Corp"
                  />
                </label>
                <label>
                  Domain
                  <input
                    value={adminCustomerDomain}
                    onChange={(e) => setAdminCustomerDomain(e.target.value)}
                    placeholder="example.com"
                  />
                </label>
                <button
                  onClick={() =>
                    runWithStatus(async () => {
                      await createCustomerFromHeader({
                        newCustomerName: adminCustomerName,
                        newCustomerDomain: adminCustomerDomain,
                        allCompanies,
                        setNewCustomerName: setAdminCustomerName,
                        setNewCustomerDomain: setAdminCustomerDomain,
                        loadCompanies,
                        setSelectedCustomer,
                      });
                    })
                  }
                >
                  Create
                </button>
              </section>
              <section className="panel">
                <h3>Company groups</h3>
                <div className="settings-company-list">
                  {allCompanies.length ? (
                    allCompanies.map((company) => (
                      <div key={company.slug} className="settings-company-row">
                        <div>
                          <div className="settings-company-name">{company.name}</div>
                          <div className="muted">Slug: {company.slug}</div>
                        </div>
                        <div className="settings-company-group">
                          <MultiSelectDropdown
                            label="Groups"
                            options={groups}
                            value={normalizeCompanyGroupEntry(
                              companyGroups[company.slug]
                            )}
                            placeholder="Select groups"
                            onChange={(next) =>
                              runWithStatus(() =>
                                updateCompanyGroupSelection(company.slug, next)
                              )
                            }
                          />
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="muted">No companies available.</div>
                  )}
                </div>
              </section>
            </div>
          </div>
        </div>
      ) : null}
      {manageGroupsOpen && isAdmin ? (
        <div className="modal-backdrop" onClick={() => setManageGroupsOpen(false)}>
          <div
            className="modal-panel manage-companies-panel"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="panel-header">
              <div>
                <h2>Manage groups</h2>
                <div className="muted">Create groups and assign companies.</div>
              </div>
              <button className="ghost" onClick={() => setManageGroupsOpen(false)}>
                Close
              </button>
            </div>
            <div className="manage-companies-grid">
              <section className="panel">
                <h3>Create group</h3>
                <label>
                  Group ID
                  <input
                    value={newGroupName}
                    onChange={(e) => setNewGroupName(e.target.value)}
                    placeholder="engineering"
                  />
                </label>
                <button onClick={() => runWithStatus(handleAddGroup)}>Create</button>
                <h3 style={{ marginTop: "1.5rem" }}>Groups</h3>
                <div className="group-list">
                  {groups.map((groupId) => (
                    <div key={groupId} className="group-row">
                      <span>{groupId}</span>
                      <button
                        className="danger ghost"
                        onClick={() => runWithStatus(() => handleRemoveGroup(groupId))}
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                </div>
              </section>
              <section className="panel">
                <h3>Company groups</h3>
                <div className="settings-company-list">
                  {allCompanies.length ? (
                    allCompanies.map((company) => (
                      <div key={company.slug} className="settings-company-row">
                        <div>
                          <div className="settings-company-name">{company.name}</div>
                          <div className="muted">Slug: {company.slug}</div>
                        </div>
                        <div className="settings-company-group">
                          <MultiSelectDropdown
                            label="Groups"
                            options={groups}
                            value={normalizeCompanyGroupEntry(
                              companyGroups[company.slug]
                            )}
                            placeholder="Select groups"
                            onChange={(next) =>
                              runWithStatus(() =>
                                updateCompanyGroupSelection(company.slug, next)
                              )
                            }
                          />
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="muted">No companies available.</div>
                  )}
                </div>
              </section>
            </div>
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
                  <button
                    className="ghost"
                    onClick={() => setStoredActiveUser(UNAUTH_USER_ID)}
                  >
                    Switch to Unauthenticated
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
                  <h3>Authentication allowlist</h3>
                  <div className="muted">
                    Emails listed here can authenticate via Google. Env allowlists
                    still apply.
                  </div>
                  {authAllowError ? (
                    <div className="user-error">{authAllowError}</div>
                  ) : null}
                  <div className="row">
                    <input
                      value={authAllowEmail}
                      onChange={(e) => setAuthAllowEmail(e.target.value)}
                      placeholder="user@gmail.com"
                    />
                    <select
                      value={authAllowRole}
                      onChange={(e) => setAuthAllowRole(e.target.value)}
                    >
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                    </select>
                    <button onClick={handleAddAuthAllowlist}>Add</button>
                  </div>
                  <div className="user-list">
                    {authAllowlist.length ? (
                      authAllowlist.map((entry) => (
                        <div key={entry.email} className="user-row">
                          <div>
                            <div className="user-name">{entry.email}</div>
                            <div className="muted">{entry.role}</div>
                          </div>
                          <button
                            className="danger ghost"
                            onClick={() => handleRemoveAuthAllowlist(entry.email)}
                          >
                            Remove
                          </button>
                        </div>
                      ))
                    ) : (
                      <div className="muted">No allowlist entries yet.</div>
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
                    <div className="settings-company-group">
                      <MultiSelectDropdown
                        label="Groups"
                        options={groups}
                        value={normalizeCompanyGroupEntry(
                          companyGroups[activeCompany.slug]
                        )}
                        placeholder="Select groups"
                        onChange={(next) =>
                          runWithStatus(() =>
                            updateCompanyGroupSelection(activeCompany.slug, next)
                          )
                        }
                      />
                    </div>
                    <div className="muted">
                      Non-admin users only see companies in their assigned group.
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
