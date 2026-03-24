import React, { useEffect, useMemo, useRef, useState } from "react";
import { api, getAuthToken } from "../../api.js";

const PREF_KEY = "soc.filters.v1";
const LOCAL_KEY = "asm.soc.filters.v1";

function formatCount(value) {
  if (!Number.isFinite(value)) return "0";
  return value.toLocaleString();
}

function safeJsonParse(text, fallback) {
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}

function formatIso(value) {
  if (!value) return "";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return String(value);
  return dt.toLocaleString();
}

function computePollMs(elapsedMs) {
  if (elapsedMs < 2 * 60 * 1000) return 10_000;
  if (elapsedMs < 5 * 60 * 1000) return 20_000;
  return 60_000;
}

function findFirstBySeverity(counts) {
  if (!counts) return "";
  if (counts.critical) return "critical";
  if (counts.investigate) return "investigate";
  if (counts.watch) return "watch";
  if (counts.info) return "info";
  return "";
}

function SeverityBadge({ severity, value }) {
  if (!value) return null;
  const cls =
    severity === "critical"
      ? "soc2-badge soc2-critical"
      : severity === "investigate"
        ? "soc2-badge soc2-investigate"
        : severity === "watch"
          ? "soc2-badge soc2-watch"
          : "soc2-badge soc2-info";
  return <span className={cls}>{value}</span>;
}

function Tile({ label, value, accent, active, onClick, title }) {
  return (
    <button
      type="button"
      className={`soc2-tile ${accent || ""} ${active ? "active" : ""}`.trim()}
      onClick={onClick}
      title={title || ""}
    >
      <div className="soc2-tile-label">{label}</div>
      <div className="soc2-tile-value">{formatCount(value)}</div>
    </button>
  );
}

function DrawerSection({ title, children }) {
  return (
    <div className="soc2-drawer-section">
      <div className="soc2-drawer-section-title">{title}</div>
      {children}
    </div>
  );
}

function KeyValue({ label, value }) {
  if (value === null || typeof value === "undefined" || value === "") return null;
  return (
    <div className="soc2-kv">
      <div className="soc2-kv-label">{label}</div>
      <div className="soc2-kv-value">{String(value)}</div>
    </div>
  );
}

export default function SocDashboard(props) {
  const {
    activeCompany,
    activeScan,
    selectedScanId,
    hasRunningScan,
    deepScan,
    onToggleDeepScan,
    onManageDetails,
    onLoadLatest,
    onStartScan,
    onOpenDetails,
    onChangeViewMode,
    canManageCompany,
    canStartScan,
  } = props;

  const [soc, setSoc] = useState(null);
  const [socError, setSocError] = useState("");
  const [socLoading, setSocLoading] = useState(false);

  const [filters, setFilters] = useState(() => ({
    showUnresolved: false,
    showNonWeb: false,
    changedOnly: false,
    search: "",
    tileFilter: "",
    severities: { critical: true, investigate: true, watch: true, info: true },
    categories: [],
  }));

  const [sort, setSort] = useState({ key: "priority", dir: "asc" });
  const [selectedHost, setSelectedHost] = useState("");
  const [drawerTab, setDrawerTab] = useState("overview");
  const [assetDetail, setAssetDetail] = useState(null);
  const [assetDetailError, setAssetDetailError] = useState("");
  const [assetDetailLoading, setAssetDetailLoading] = useState(false);

  const pollStartRef = useRef(0);
  const pollTimerRef = useRef(null);
  const mountedRef = useRef(false);

  const scanId = selectedScanId || soc?.scan?.id || null;
  const scanLabel = soc?.scan?.company_scan_number
    ? `Scan #${soc.scan.company_scan_number}`
    : soc?.scan?.id
      ? `Scan ${soc.scan.id}`
      : "";

  async function loadFilters() {
    const local = safeJsonParse(
      typeof window !== "undefined" ? window.localStorage.getItem(LOCAL_KEY) : "",
      null
    );
    if (local) {
      setFilters((prev) => ({ ...prev, ...local }));
    }
    if (!getAuthToken()) return;
    try {
      const resp = await api.getPreference(PREF_KEY);
      if (resp?.value && typeof resp.value === "object") {
        setFilters((prev) => ({ ...prev, ...resp.value }));
      }
    } catch {
      // Public or auth unavailable: localStorage remains the source of truth.
    }
  }

  function persistFilters(next) {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(LOCAL_KEY, JSON.stringify(next));
    }
    if (getAuthToken()) {
      api.setPreference(PREF_KEY, next).catch(() => {});
    }
  }

  async function loadSocOverview({ ifModified = false } = {}) {
    if (!activeCompany?.slug) return;
    setSocError("");
    if (!ifModified) setSocLoading(true);
    try {
      if (ifModified) {
        const res = await api.getSocOverviewIfModified(activeCompany.slug, scanId);
        if (!res?.notModified && res?.data) setSoc(res.data);
      } else {
        const data = await api.getSocOverview(activeCompany.slug, scanId);
        setSoc(data);
      }
    } catch (err) {
      setSocError(err?.message || "Failed to load SOC view");
    } finally {
      if (!ifModified) setSocLoading(false);
    }
  }

  async function loadAssetDetail(hostname, { ifModified = false } = {}) {
    if (!activeCompany?.slug || !hostname) return;
    setAssetDetailError("");
    if (!ifModified) setAssetDetailLoading(true);
    try {
      if (ifModified) {
        const res = await api.getSocAssetDetailIfModified(
          activeCompany.slug,
          hostname,
          scanId
        );
        if (!res?.notModified && res?.data) setAssetDetail(res.data);
      } else {
        const data = await api.getSocAssetDetail(activeCompany.slug, hostname, scanId);
        setAssetDetail(data);
      }
    } catch (err) {
      setAssetDetailError(err?.message || "Failed to load asset details");
    } finally {
      if (!ifModified) setAssetDetailLoading(false);
    }
  }

  useEffect(() => {
    if (mountedRef.current) return;
    mountedRef.current = true;
    loadFilters();
  }, []);

  useEffect(() => {
    loadSocOverview();
  }, [activeCompany?.slug, selectedScanId]);

  useEffect(() => {
    if (!selectedHost) {
      setAssetDetail(null);
      setAssetDetailError("");
      return;
    }
    setDrawerTab("overview");
    loadAssetDetail(selectedHost);
  }, [selectedHost, activeCompany?.slug, selectedScanId]);

  useEffect(() => {
    if (pollTimerRef.current) {
      clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    const running = Boolean(hasRunningScan || (activeScan?.status || "") === "running");
    if (!running) return;

    pollStartRef.current = Date.now();
    const tick = async () => {
      const elapsed = Date.now() - pollStartRef.current;
      if (elapsed > 60 * 60 * 1000) {
        return;
      }
      await loadSocOverview({ ifModified: true });
      if (selectedHost) await loadAssetDetail(selectedHost, { ifModified: true });
      pollTimerRef.current = setTimeout(tick, computePollMs(elapsed));
    };
    pollTimerRef.current = setTimeout(tick, 5_000);
    return () => {
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    };
  }, [hasRunningScan, activeScan?.status, selectedHost, activeCompany?.slug, selectedScanId]);

  useEffect(() => {
    const id = setTimeout(() => {
      persistFilters(filters);
    }, 350);
    return () => clearTimeout(id);
  }, [filters]);

  const assets = soc?.assets || [];
  const findings = soc?.findings || [];

  function toggleTileFilter(key) {
    setFilters((prev) => ({
      ...prev,
      tileFilter: prev.tileFilter === key ? "" : key,
    }));
  }

  const effectiveVisibility = useMemo(() => {
    const tile = filters.tileFilter || "";
    if (!tile) return { showUnresolved: filters.showUnresolved, showNonWeb: filters.showNonWeb };

    // Tile filters should show exactly the set behind the metric.
    // That means temporarily overriding the default "hide unresolved/non-web" behavior.
    if (tile === "assets") return { showUnresolved: true, showNonWeb: true };
    if (tile === "live_web") return { showUnresolved: true, showNonWeb: true };
    if (tile === "unresolved") return { showUnresolved: true, showNonWeb: true };
    if (tile === "missing_hsts") return { showUnresolved: true, showNonWeb: true };
    if (tile === "changed") return { showUnresolved: true, showNonWeb: true };
    return { showUnresolved: filters.showUnresolved, showNonWeb: filters.showNonWeb };
  }, [filters.showUnresolved, filters.showNonWeb, filters.tileFilter]);

  const filteredAssets = useMemo(() => {
    let list = Array.isArray(assets) ? assets.slice() : [];
    if (!effectiveVisibility.showUnresolved) list = list.filter((a) => a?.resolves);
    if (!effectiveVisibility.showNonWeb) list = list.filter((a) => a?.web_reachable);

    const tile = filters.tileFilter || "";
    if (tile === "assets") {
      // no-op; visibility override already ensures "all assets"
    } else if (tile === "live_web") {
      list = list.filter((a) => a?.web_reachable);
    } else if (tile === "unresolved") {
      list = list.filter((a) => !a?.resolves);
    } else if (tile === "missing_hsts") {
      list = list.filter((a) => a?.tls_present && !a?.hsts_present);
    } else if (tile === "changed") {
      list = list.filter((a) => (a?.change?.state || "") !== "unchanged");
    }

    if (filters.changedOnly)
      list = list.filter((a) => (a?.change?.state || "") !== "unchanged");
    const q = (filters.search || "").trim().toLowerCase();
    if (q) {
      list = list.filter((a) => {
        const hay = [
          a?.hostname,
          a?.root_domain,
          a?.title,
          a?.final_url,
          a?.provider_hint,
          a?.edge_family,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return hay.includes(q);
      });
    }
    return list;
  }, [assets, effectiveVisibility.showNonWeb, effectiveVisibility.showUnresolved, filters]);

  const sortedAssets = useMemo(() => {
    const list = filteredAssets.slice();
    const dir = sort.dir === "desc" ? -1 : 1;
    const key = sort.key;
    list.sort((a, b) => {
      if (key === "hostname") return String(a.hostname).localeCompare(String(b.hostname)) * dir;
      if (key === "root_domain") return String(a.root_domain).localeCompare(String(b.root_domain)) * dir;
      if (key === "status_code") return (Number(a.status_code || 0) - Number(b.status_code || 0)) * dir;
      if (key === "ip_count") return (Number(a.ip_count || 0) - Number(b.ip_count || 0)) * dir;
      if (key === "changed") {
        const av = (a?.change?.state || "") === "unchanged" ? 0 : 1;
        const bv = (b?.change?.state || "") === "unchanged" ? 0 : 1;
        return (av - bv) * dir;
      }
      const aCounts = a?.finding_counts || {};
      const bCounts = b?.finding_counts || {};
      const aPriority =
        (aCounts.critical || 0) * 1000 +
        (aCounts.investigate || 0) * 100 +
        (aCounts.watch || 0) * 10 +
        (aCounts.info || 0);
      const bPriority =
        (bCounts.critical || 0) * 1000 +
        (bCounts.investigate || 0) * 100 +
        (bCounts.watch || 0) * 10 +
        (bCounts.info || 0);
      return (aPriority - bPriority) * dir;
    });
    return list;
  }, [filteredAssets, sort]);

  const visibleFindings = useMemo(() => {
    let list = Array.isArray(findings) ? findings.slice() : [];
    list = list.filter((f) => filters.severities?.[f.severity] !== false);
    if (filters.categories?.length) {
      const set = new Set(filters.categories);
      list = list.filter((f) => set.has(f.category));
    }
    return list;
  }, [findings, filters]);

  const findingCategories = useMemo(() => {
    const set = new Set();
    (findings || []).forEach((f) => {
      if (f?.category) set.add(f.category);
    });
    return Array.from(set).sort();
  }, [findings]);

  const summary = soc?.summary || {};
  const scanMeta = soc?.scan || null;
  const prevMeta = soc?.previous_scan || null;

  return (
    <div className="soc2">
      <div className="soc2-header">
        <div>
          <div className="soc2-title">SOC Analyst Workspace</div>
          <div className="soc2-subtitle">
            {activeCompany?.name || activeCompany?.slug || "No company selected"}
            {scanLabel ? ` · ${scanLabel}` : ""}
            {scanMeta?.status ? ` · ${scanMeta.status}` : ""}
            {prevMeta?.company_scan_number
              ? ` · Prev #${prevMeta.company_scan_number}`
              : ""}
          </div>
        </div>
        <div className="soc2-actions">
          <button className="btn" onClick={() => onChangeViewMode?.("exec")}>
            Executive
          </button>
          <button className="btn" onClick={onOpenDetails}>
            Scans
          </button>
          <button
            className="btn"
            onClick={onManageDetails}
            disabled={!canManageCompany}
          >
            Manage
          </button>
          <button className="btn" onClick={onLoadLatest}>
            Load latest
          </button>
          <button
            className="btn primary"
            onClick={onStartScan}
            disabled={!canStartScan}
          >
            Start scan
          </button>
          <label className="soc2-toggle">
            <input
              type="checkbox"
              checked={Boolean(deepScan)}
              onChange={(e) => onToggleDeepScan?.(e.target.checked)}
            />
            Deep scan
          </label>
        </div>
      </div>

      {socError ? <div className="soc2-error">{socError}</div> : null}

      <div className="soc2-tiles">
        <Tile
          label="Assets"
          value={summary.assets_discovered || 0}
          accent="soc2-accent-blue"
          active={filters.tileFilter === "assets"}
          onClick={() => toggleTileFilter("assets")}
          title="Filter: all assets (includes unresolved and non-web)"
        />
        <Tile
          label="Live web"
          value={summary.live_web_assets || 0}
          accent="soc2-accent-green"
          active={filters.tileFilter === "live_web"}
          onClick={() => toggleTileFilter("live_web")}
          title="Filter: web reachable assets"
        />
        <Tile
          label="Unresolved"
          value={summary.unresolved_assets || 0}
          accent="soc2-accent-orange"
          active={filters.tileFilter === "unresolved"}
          onClick={() => toggleTileFilter("unresolved")}
          title="Filter: unresolved assets"
        />
        <Tile
          label="Critical assets"
          value={summary.assets_with_critical_findings || 0}
          accent="soc2-accent-red"
        />
        <Tile
          label="Investigate assets"
          value={summary.assets_with_investigate_findings || 0}
          accent="soc2-accent-purple"
        />
        <Tile
          label="Missing HSTS"
          value={summary.missing_hsts_assets || 0}
          active={filters.tileFilter === "missing_hsts"}
          onClick={() => toggleTileFilter("missing_hsts")}
          title="Filter: TLS present but HSTS missing"
        />
        <Tile
          label="Changed"
          value={summary.assets_changed || 0}
          active={filters.tileFilter === "changed"}
          onClick={() => toggleTileFilter("changed")}
          title="Filter: assets that changed vs previous scan"
        />
        <Tile label="Removed" value={summary.removed_assets || 0} />
      </div>

      <div className="soc2-stack">
        <div className="soc2-panel soc2-panel-findings">
          <div className="soc2-panel-head">
            <div className="soc2-panel-title">Findings</div>
            <div className="soc2-panel-meta">
              {formatCount(visibleFindings.length)} shown
            </div>
          </div>

          <div className="soc2-findings-filters soc2-findings-filters-wide">
            <div className="soc2-sev-toggles">
              {["critical", "investigate", "watch", "info"].map((sev) => (
                <button
                  key={sev}
                  type="button"
                  className={`soc2-chip ${
                    filters.severities?.[sev] !== false ? "active" : ""
                  }`.trim()}
                  aria-pressed={filters.severities?.[sev] !== false}
                  onClick={() =>
                    setFilters((prev) => ({
                      ...prev,
                      severities: {
                        ...prev.severities,
                        [sev]: !(prev.severities?.[sev] !== false),
                      },
                    }))
                  }
                >
                  {sev}
                </button>
              ))}
            </div>
            <div className="soc2-cat-row">
              <div className="soc2-cat-label">Category</div>
              <select
                className="soc2-select"
                value={filters.categories?.[0] || ""}
                onChange={(e) =>
                  setFilters((prev) => ({
                    ...prev,
                    categories: e.target.value ? [e.target.value] : [],
                  }))
                }
              >
                <option value="">All</option>
                {findingCategories.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="soc2-findings-list soc2-findings-grid">
            {visibleFindings.map((f) => (
              <button
                key={f.id}
                type="button"
                className={`soc2-finding soc2-finding-${f.severity}`.trim()}
                onClick={() => {
                  setSelectedHost(f.asset_hostname);
                  setDrawerTab("findings");
                }}
              >
                <div className="soc2-finding-top">
                  <span className="soc2-finding-title">{f.title}</span>
                  <span className="soc2-finding-sev">{f.severity}</span>
                </div>
                <div className="soc2-finding-meta">
                  <span className="soc2-mono">{f.asset_hostname}</span>
                  <span className="soc2-muted">
                    {f.category}
                    {f.status ? ` · ${f.status}` : ""}
                  </span>
                </div>
              </button>
            ))}
            {!visibleFindings.length ? (
              <div className="soc2-empty">No findings in current filters.</div>
            ) : null}
          </div>
        </div>

        <div className="soc2-panel">
          <div className="soc2-panel-head">
            <div className="soc2-panel-title">Asset inventory</div>
            <div className="soc2-panel-meta">
              {socLoading ? "Loading…" : `${sortedAssets.length} shown`}
            </div>
          </div>

          <div className="soc2-filters">
            <label className="soc2-toggle">
              <input
                type="checkbox"
                checked={Boolean(filters.showUnresolved)}
                onChange={(e) =>
                  setFilters((prev) => ({
                    ...prev,
                    showUnresolved: e.target.checked,
                  }))
                }
              />
              Show unresolved
            </label>
            <label className="soc2-toggle">
              <input
                type="checkbox"
                checked={Boolean(filters.showNonWeb)}
                onChange={(e) =>
                  setFilters((prev) => ({
                    ...prev,
                    showNonWeb: e.target.checked,
                  }))
                }
              />
              Show non-web
            </label>
            <label className="soc2-toggle">
              <input
                type="checkbox"
                checked={Boolean(filters.changedOnly)}
                onChange={(e) =>
                  setFilters((prev) => ({
                    ...prev,
                    changedOnly: e.target.checked,
                  }))
                }
              />
              Changed only
            </label>
            <input
              className="soc2-search"
              placeholder="Search host, title, URL, provider…"
              value={filters.search}
              onChange={(e) =>
                setFilters((prev) => ({ ...prev, search: e.target.value }))
              }
            />
          </div>

          <div className="soc2-table-wrap soc2-table-wrap-tight">
            <table className="soc2-table soc2-table-tight">
              <colgroup>
                <col style={{ width: "20ch" }} />
                <col style={{ width: "18ch" }} />
                <col style={{ width: "8ch" }} />
                <col style={{ width: "5ch" }} />
                <col style={{ width: "5ch" }} />
                <col style={{ width: "6ch" }} />
                <col style={{ width: "22ch" }} />
                <col style={{ width: "14ch" }} />
                <col style={{ width: "14ch" }} />
                <col style={{ width: "4ch" }} />
                <col style={{ width: "3ch" }} />
                <col style={{ width: "3ch" }} />
                <col style={{ width: "4ch" }} />
                <col style={{ width: "10ch" }} />
                <col style={{ width: "9ch" }} />
                <col style={{ width: "16ch" }} />
              </colgroup>
              <thead>
                <tr>
                  <th
                    onClick={() =>
                      setSort({
                        key: "hostname",
                        dir: sort.dir === "asc" ? "desc" : "asc",
                      })
                    }
                  >
                    Hostname
                  </th>
                  <th
                    onClick={() =>
                      setSort({
                        key: "root_domain",
                        dir: sort.dir === "asc" ? "desc" : "asc",
                      })
                    }
                  >
                    Root
                  </th>
                  <th>Type</th>
                  <th>DNS</th>
                  <th>Web</th>
                  <th
                    onClick={() =>
                      setSort({
                        key: "status_code",
                        dir: sort.dir === "asc" ? "desc" : "asc",
                      })
                    }
                  >
                    Code
                  </th>
                  <th>Title</th>
                  <th>Platform</th>
                  <th>Edge</th>
                  <th
                    onClick={() =>
                      setSort({
                        key: "ip_count",
                        dir: sort.dir === "asc" ? "desc" : "asc",
                      })
                    }
                  >
                    IPs
                  </th>
                  <th>v6</th>
                  <th>TLS</th>
                  <th>HSTS</th>
                  <th>Findings</th>
                  <th
                    onClick={() =>
                      setSort({
                        key: "changed",
                        dir: sort.dir === "asc" ? "desc" : "asc",
                      })
                    }
                  >
                    Change
                  </th>
                  <th>Seen</th>
                </tr>
              </thead>
              <tbody>
                {sortedAssets.map((a) => {
                  const counts = a?.finding_counts || {};
                  const sev = findFirstBySeverity(counts);
                  const rowCls = [
                    "soc2-row",
                    selectedHost === a.hostname ? "active" : "",
                    sev ? `sev-${sev}` : "",
                  ]
                    .filter(Boolean)
                    .join(" ");
                  const changeState = a?.change?.state || "";
                  return (
                    <tr
                      key={a.hostname}
                      className={rowCls}
                      onClick={() => setSelectedHost(a.hostname)}
                      title={a?.final_url || ""}
                    >
                      <td className="soc2-mono soc2-ellipsis">{a.hostname}</td>
                      <td className="soc2-mono soc2-ellipsis">{a.root_domain || "-"}</td>
                      <td>{a.asset_type || "-"}</td>
                      <td>{a.resolves ? "Y" : "N"}</td>
                      <td>{a.web_reachable ? "Y" : "N"}</td>
                      <td>{a.status_code || "-"}</td>
                      <td className="soc2-ellipsis">{a.title || "-"}</td>
                      <td className="soc2-ellipsis">{a.provider_hint || "-"}</td>
                      <td className="soc2-ellipsis">{a.edge_family || "-"}</td>
                      <td>{a.ip_count || 0}</td>
                      <td>{a.ipv6_present ? "Y" : "N"}</td>
                      <td>{a.tls_present ? "Y" : "N"}</td>
                      <td>{a.hsts_present ? "Y" : "N"}</td>
                      <td>
                        <div className="soc2-findings-cell">
                          <SeverityBadge
                            severity="critical"
                            value={counts.critical}
                          />
                          <SeverityBadge
                            severity="investigate"
                            value={counts.investigate}
                          />
                          <SeverityBadge severity="watch" value={counts.watch} />
                          <SeverityBadge severity="info" value={counts.info} />
                        </div>
                      </td>
                      <td>
                        <span className={`soc2-change ${changeState}`.trim()}>
                          {changeState || "-"}
                        </span>
                      </td>
                      <td className="soc2-muted soc2-ellipsis">{formatIso(a.last_seen)}</td>
                    </tr>
                  );
                })}
                {!sortedAssets.length ? (
                  <tr>
                    <td colSpan={16} className="soc2-empty">
                      No assets to show (adjust filters).
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className={`soc2-drawer ${selectedHost ? "open" : ""}`.trim()}>
        <div className="soc2-drawer-head">
          <div>
            <div className="soc2-drawer-title">
              {selectedHost || "No asset selected"}
            </div>
            <div className="soc2-drawer-subtitle">
              {assetDetail?.asset?.web?.final_url
                ? assetDetail.asset.web.final_url
                : ""}
            </div>
          </div>
          <div className="soc2-drawer-actions">
            <button className="btn" onClick={() => setSelectedHost("")}>
              Close
            </button>
          </div>
        </div>

        {assetDetailError ? (
          <div className="soc2-error">{assetDetailError}</div>
        ) : null}

        <div className="soc2-drawer-tabs">
          {[
            ["overview", "Overview"],
            ["dns", "DNS"],
            ["web", "Web"],
            ["tls", "TLS"],
            ["findings", "Findings"],
            ["history", "History"],
            ["raw", "Raw JSON"],
          ].map(([key, label]) => (
            <button
              key={key}
              type="button"
              className={`soc2-tab ${drawerTab === key ? "active" : ""}`.trim()}
              onClick={() => setDrawerTab(key)}
              disabled={!selectedHost}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="soc2-drawer-body">
          {assetDetailLoading ? <div className="soc2-muted">Loading…</div> : null}
          {!assetDetailLoading && selectedHost && !assetDetail ? (
            <div className="soc2-muted">Select an asset to load details.</div>
          ) : null}

          {assetDetail?.asset ? (
            <>
              {drawerTab === "overview" ? (
                <>
                  <DrawerSection title="Investigation summary">
                    <div className="soc2-kv-grid">
                      <KeyValue label="Type" value={assetDetail.asset.asset_type} />
                      <KeyValue
                        label="Root domain"
                        value={assetDetail.asset.root_domain}
                      />
                      <KeyValue
                        label="Resolves"
                        value={assetDetail.asset.resolves ? "yes" : "no"}
                      />
                      <KeyValue
                        label="Web reachable"
                        value={assetDetail.asset.web?.reachable ? "yes" : "no"}
                      />
                      <KeyValue label="Status" value={assetDetail.asset.web?.status_code} />
                      <KeyValue label="Title" value={assetDetail.asset.web?.title} />
                      <KeyValue label="Edge/CDN" value={assetDetail.asset.edge_family} />
                      <KeyValue
                        label="IPv4"
                        value={assetDetail.asset.has_ipv4 ? "yes" : "no"}
                      />
                      <KeyValue
                        label="IPv6"
                        value={assetDetail.asset.has_ipv6 ? "yes" : "no"}
                      />
                    </div>
                  </DrawerSection>
                  <DrawerSection title="Quick findings">
                    {(assetDetail.asset.findings || []).slice(0, 8).map((f) => (
                      <div
                        key={f.id}
                        className={`soc2-mini-f soc2-mini-${f.severity}`}
                      >
                        <div className="soc2-mini-title">{f.title}</div>
                        <div className="soc2-mini-meta">
                          <span>{f.severity}</span>
                          <span className="soc2-muted">{f.category}</span>
                        </div>
                      </div>
                    ))}
                    {!assetDetail.asset.findings?.length ? (
                      <div className="soc2-muted">No findings for this asset.</div>
                    ) : null}
                  </DrawerSection>
                </>
              ) : null}

              {drawerTab === "dns" ? (
                <DrawerSection title="DNS evidence">
                  <div className="soc2-kv-grid">
                    <KeyValue label="IP count" value={assetDetail.asset.ip_count} />
                    <KeyValue
                      label="A/AAAA"
                      value={(assetDetail.asset.dns?.ips || []).join(", ")}
                    />
                    <KeyValue
                      label="CNAME"
                      value={(assetDetail.asset.dns?.CNAME || []).join(", ")}
                    />
                    <KeyValue
                      label="MX"
                      value={(assetDetail.asset.dns?.MX || []).join(", ")}
                    />
                    <KeyValue
                      label="NS"
                      value={(assetDetail.asset.dns?.NS || []).join(", ")}
                    />
                    <KeyValue
                      label="CAA"
                      value={(assetDetail.asset.dns?.CAA || []).join(", ")}
                    />
                  </div>
                  <details className="soc2-details">
                    <summary>Raw DNS JSON</summary>
                    <pre className="soc2-pre">
                      {JSON.stringify(assetDetail.asset.dns || {}, null, 2)}
                    </pre>
                  </details>
                </DrawerSection>
              ) : null}

              {drawerTab === "web" ? (
                <DrawerSection title="Web metadata">
                  <div className="soc2-kv-grid">
                    <KeyValue label="Final URL" value={assetDetail.asset.web?.final_url} />
                    <KeyValue
                      label="Status code"
                      value={assetDetail.asset.web?.status_code}
                    />
                    <KeyValue
                      label="Response ms"
                      value={assetDetail.asset.web?.response_time_ms}
                    />
                    <KeyValue label="Title" value={assetDetail.asset.web?.title} />
                    <KeyValue label="Server" value={assetDetail.asset.web?.server_header} />
                    <KeyValue
                      label="Technologies"
                      value={(assetDetail.asset.web?.technologies || []).join(", ")}
                    />
                    <KeyValue
                      label="Fingerprints"
                      value={(assetDetail.asset.web?.fingerprints || []).join(", ")}
                    />
                  </div>
                  <details className="soc2-details">
                    <summary>Security headers</summary>
                    <pre className="soc2-pre">
                      {JSON.stringify(
                        assetDetail.asset.web?.security_headers || {},
                        null,
                        2
                      )}
                    </pre>
                  </details>
                  <details className="soc2-details">
                    <summary>Deep scan aux</summary>
                    <pre className="soc2-pre">
                      {JSON.stringify(assetDetail.asset.web?.deep_scan || {}, null, 2)}
                    </pre>
                  </details>
                </DrawerSection>
              ) : null}

              {drawerTab === "tls" ? (
                <DrawerSection title="TLS details">
                  <div className="soc2-kv-grid">
                    <KeyValue
                      label="Not before"
                      value={assetDetail.asset.web?.tls?.not_before}
                    />
                    <KeyValue
                      label="Not after"
                      value={assetDetail.asset.web?.tls?.not_after}
                    />
                    <KeyValue
                      label="Issuer"
                      value={Array.isArray(assetDetail.asset.web?.tls?.issuer)
                        ? assetDetail.asset.web.tls.issuer
                            .map((x) => x.join("="))
                            .join(", ")
                        : ""}
                    />
                    <KeyValue
                      label="SAN"
                      value={Array.isArray(assetDetail.asset.web?.tls?.san)
                        ? assetDetail.asset.web.tls.san.join(", ")
                        : ""}
                    />
                    <KeyValue
                      label="HSTS"
                      value={assetDetail.asset.web?.hsts?.header || ""}
                    />
                  </div>
                  <details className="soc2-details">
                    <summary>Raw TLS JSON</summary>
                    <pre className="soc2-pre">
                      {JSON.stringify(assetDetail.asset.web?.tls || {}, null, 2)}
                    </pre>
                  </details>
                </DrawerSection>
              ) : null}

              {drawerTab === "findings" ? (
                <DrawerSection title="Findings">
                  {(assetDetail.asset.findings || []).map((f) => (
                    <div
                      key={f.id}
                      className={`soc2-finding-detail soc2-finding-${f.severity}`}
                    >
                      <div className="soc2-finding-top">
                        <span className="soc2-finding-title">{f.title}</span>
                        <span className="soc2-finding-sev">{f.severity}</span>
                      </div>
                      <div className="soc2-muted">{f.category}</div>
                      {f.explanation ? (
                        <div className="soc2-finding-expl">{f.explanation}</div>
                      ) : null}
                      {f.remediation ? (
                        <div className="soc2-finding-rem">
                          <div className="soc2-muted">Next step</div>
                          <div>{f.remediation}</div>
                        </div>
                      ) : null}
                      <details className="soc2-details">
                        <summary>Evidence</summary>
                        <pre className="soc2-pre">
                          {JSON.stringify(f.evidence || {}, null, 2)}
                        </pre>
                      </details>
                    </div>
                  ))}
                  {!assetDetail.asset.findings?.length ? (
                    <div className="soc2-muted">No findings for this asset.</div>
                  ) : null}
                </DrawerSection>
              ) : null}

              {drawerTab === "history" ? (
                <DrawerSection title="History / changes">
                  <div className="soc2-kv-grid">
                    <KeyValue label="Change state" value={assetDetail.asset.change?.state} />
                    <KeyValue
                      label="Change flags"
                      value={(assetDetail.asset.change?.flags || []).join(", ")}
                    />
                  </div>
                  <details className="soc2-details">
                    <summary>Previous snapshot</summary>
                    <pre className="soc2-pre">
                      {JSON.stringify(assetDetail.asset.change?.previous || {}, null, 2)}
                    </pre>
                  </details>
                </DrawerSection>
              ) : null}

              {drawerTab === "raw" ? (
                <DrawerSection title="Raw JSON">
                  <pre className="soc2-pre">
                    {JSON.stringify(assetDetail.asset.raw || {}, null, 2)}
                  </pre>
                </DrawerSection>
              ) : null}
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
}
