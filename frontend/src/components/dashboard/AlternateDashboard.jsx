import React, { useEffect, useMemo, useRef, useState } from "react";

const KPI_SPARKS = [
  [8, 11, 10, 14, 18, 16, 20, 22, 24],
  [4, 6, 9, 8, 12, 14, 16, 15, 17],
  [2, 3, 4, 6, 5, 7, 6, 8, 9],
  [15, 18, 16, 20, 22, 19, 24, 26, 28],
  [40, 42, 45, 48, 50, 47, 52, 55, 58],
];

const GEO_DOTS = [
  { left: "16%", top: "32%", size: 8 },
  { left: "28%", top: "45%", size: 6 },
  { left: "43%", top: "35%", size: 10 },
  { left: "52%", top: "58%", size: 7 },
  { left: "63%", top: "40%", size: 9 },
  { left: "72%", top: "30%", size: 6 },
  { left: "78%", top: "55%", size: 8 },
  { left: "84%", top: "42%", size: 7 },
];

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function formatCount(value, suffix = "") {
  if (typeof value === "string") return value;
  if (!Number.isFinite(value)) return "0";
  return `${value.toLocaleString()}${suffix}`;
}

function Sparkline({ points }) {
  const width = 90;
  const height = 30;
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const range = max - min || 1;
  const stepX = width / (points.length - 1 || 1);
  const normalized = points.map((p) => height - ((p - min) / range) * height);
  const d = normalized
    .map((y, i) => `${i === 0 ? "M" : "L"} ${i * stepX} ${y}`)
    .join(" ");
  return (
    <svg className="alt-sparkline" viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
      <path className="alt-sparkline-path" d={d} />
    </svg>
  );
}

function SeverityBadge({ level }) {
  return <span className={`alt-badge alt-badge--${level}`}>{level}</span>;
}

function Gauge({ value }) {
  const size = 150;
  const stroke = 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = clamp(value, 0, 100) / 100;
  const dash = circumference * pct;
  const color =
    value < 30 ? "#38c172" : value < 60 ? "#f2c94c" : "#ff5b4d";
  return (
    <div className="alt-gauge">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          className="alt-gauge-track"
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
        />
        <circle
          className="alt-gauge-progress"
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
          stroke={color}
          strokeDasharray={`${dash} ${circumference - dash}`}
        />
      </svg>
      <div className="alt-gauge-value">
        <div className="alt-gauge-score">{value}</div>
        <div className="alt-gauge-label">Exposure</div>
      </div>
    </div>
  );
}

export default function AlternateDashboard({
  activeCompany,
  activeScan,
  artifacts,
  scans,
  selectedScanId,
  hasRunningScan,
  runningScan,
  scanProgress,
  deepScan,
  onToggleDeepScan,
  onManageDetails,
  onLoadLatest,
  onStartScan,
  onSelectScan,
}) {
  const [artifactPanelOpen, setArtifactPanelOpen] = useState(false);
  const [drilldownOpen, setDrilldownOpen] = useState(false);
  const [drilldownKey, setDrilldownKey] = useState("domains");
  const didAutoOpen = useRef(false);
  const roots = artifacts?.domains?.roots || [];
  const allDomains = artifacts?.domains?.domains || [];
  const rootSet = useMemo(() => new Set(roots), [roots]);
  const discovered = allDomains.filter((d) => !rootSet.has(d));
  const domainsMonitored = roots.length + discovered.length;

  const dnsRecords = artifacts?.dns?.records || [];
  const uniqueIps = useMemo(() => {
    const set = new Set();
    dnsRecords.forEach((rec) => {
      (rec?.ips || []).forEach((ip) => set.add(ip));
    });
    return set;
  }, [dnsRecords]);
  const publicIps = uniqueIps.size || artifacts?.dns?.summary?.unique_ip_count || 0;

  const intelDomains = artifacts?.dns_intel?.domains || [];
  const criticalCves = intelDomains.reduce((sum, row) => {
    const findings = row?.cve_findings || [];
    return (
      sum +
      findings.filter((entry) => Number(entry?.score ?? 0) >= 9).length
    );
  }, 0);

  const exposureScoreAvg = artifacts?.dns_intel?.summary?.exposure_score_avg;
  const exposureScoreFallback = intelDomains.length
    ? intelDomains.reduce((sum, row) => sum + (row?.exposure_score || 0), 0) /
      intelDomains.length
    : 0;
  const exposureScore = clamp(
    Math.round(
      Number.isFinite(exposureScoreAvg) ? exposureScoreAvg : exposureScoreFallback
    ),
    0,
    100
  );

  const edgeDomains = intelDomains.filter((row) => {
    const provider = row?.web?.edge_provider?.provider;
    return provider && provider !== "none";
  }).length;
  const cdnCoverage = intelDomains.length
    ? Math.round((edgeDomains / intelDomains.length) * 100)
    : 0;

  const riskCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    intelDomains.forEach((row) => {
      const score = Number(row?.exposure_score ?? 0);
      if (score >= 80) counts.critical += 1;
      else if (score >= 60) counts.high += 1;
      else if (score >= 30) counts.medium += 1;
      else counts.low += 1;
    });
    return counts;
  }, [intelDomains]);

  const changeItems = useMemo(() => {
    const summary = artifacts?.change_summary;
    if (!summary?.has_previous) return [];
    const items = [];
    const addItem = (key, label, severity) => {
      const list = summary[key] || [];
      if (!list.length) return;
      items.push({
        id: key,
        label,
        severity,
        count: list.length,
        sample: list.slice(0, 3),
      });
    };
    addItem("new_domains", "New domains discovered", "medium");
    addItem("removed_domains", "Domains removed", "low");
    addItem("provider_changes", "Edge/provider shifts", "high");
    addItem("technology_changes", "Tech stack changes", "medium");
    return items;
  }, [artifacts]);

  const kpis = [
    {
      key: "domains",
      label: "Domains Monitored",
      value: domainsMonitored,
      spark: KPI_SPARKS[0],
    },
    {
      key: "ips",
      label: "Public IPs",
      value: publicIps,
      spark: KPI_SPARKS[1],
    },
    {
      key: "cves",
      label: "Critical CVEs",
      value: criticalCves,
      spark: KPI_SPARKS[2],
    },
    {
      key: "exposure",
      label: "Exposure Score",
      value: exposureScore,
      spark: KPI_SPARKS[3],
    },
    {
      key: "cdn",
      label: "CDN Coverage %",
      value: cdnCoverage,
      suffix: "%",
      spark: KPI_SPARKS[4],
    },
  ];

  const drilldownData = useMemo(() => {
    const domains = {
      title: "Domains Monitored",
      subtitle: `${domainsMonitored} total (${roots.length} roots, ${discovered.length} discovered)`,
      items: [
        ...roots.map((d) => ({ label: d, meta: "root" })),
        ...discovered.map((d) => ({ label: d, meta: "discovered" })),
      ],
    };
    const ips = {
      title: "Public IPs",
      subtitle: `${publicIps} unique IPs`,
      items: Array.from(uniqueIps).map((ip) => ({ label: ip, meta: "ip" })),
    };
    const cves = {
      title: "Critical CVEs",
      subtitle: `${criticalCves} findings with score ≥ 9`,
      items: intelDomains.flatMap((row) =>
        (row?.cve_findings || [])
          .filter((entry) => Number(entry?.score ?? 0) >= 9)
          .map((entry) => ({
            label: entry?.cve || "CVE",
            meta: `${entry?.component || "component"} · ${entry?.version || "?"} · ${
              entry?.score ?? "?"
            }`,
          }))
      ),
    };
    const exposure = {
      title: "Exposure Score",
      subtitle: `Average exposure score ${exposureScore}`,
      items: intelDomains
        .slice()
        .sort((a, b) => (b?.exposure_score || 0) - (a?.exposure_score || 0))
        .slice(0, 30)
        .map((row) => ({
          label: row?.domain || "domain",
          meta: `score ${row?.exposure_score ?? 0}`,
        })),
    };
    const cdn = {
      title: "CDN Coverage",
      subtitle: `${cdnCoverage}% of domains show edge/provider signals`,
      items: intelDomains
        .filter((row) => {
          const provider = row?.web?.edge_provider?.provider;
          return provider && provider !== "none";
        })
        .map((row) => ({
          label: row?.domain || "domain",
          meta: row?.web?.edge_provider?.provider || "edge",
        })),
    };
    return { domains, ips, cves, exposure, cdn };
  }, [
    domainsMonitored,
    roots,
    discovered,
    uniqueIps,
    publicIps,
    intelDomains,
    criticalCves,
    exposureScore,
    cdnCoverage,
  ]);

  useEffect(() => {
    if (!didAutoOpen.current && !artifacts) {
      setArtifactPanelOpen(true);
      didAutoOpen.current = true;
    }
  }, [artifacts]);

  return (
    <section className="alt-dashboard alt-fade-in">
      <div className="alt-header">
        <div>
          <div className="alt-title">Attack Surface Dashboard</div>
          <div className="alt-subtitle">
            {activeCompany?.name || "No active customer"}
            {activeScan?.company_scan_number
              ? ` · Scan #${activeScan.company_scan_number}`
              : ""}
          </div>
        </div>
        <div className="alt-header-actions">
          <label className="alt-toggle">
            <input
              type="checkbox"
              checked={!!deepScan}
              onChange={(e) => onToggleDeepScan?.(e.target.checked)}
            />
            <span>Deep scan</span>
          </label>
          <button className="ghost" onClick={onManageDetails}>
            Manage details
          </button>
          <button
            type="button"
            className="alt-chip alt-chip-button"
            onClick={() => setArtifactPanelOpen(true)}
          >
            {artifacts ? "Live artifacts loaded" : "Load artifacts"}
          </button>
        </div>
      </div>

      {hasRunningScan ? (
        <div className="alt-status">
          <div className="alt-status-title">
            Scan in progress{runningScan?.scan_mode ? ` · ${runningScan.scan_mode}` : ""}
          </div>
          <div className="alt-status-bar">
            <span
              className={`alt-status-fill ${
                scanProgress?.indeterminate ? "indeterminate" : "determinate"
              }`}
              style={
                scanProgress?.indeterminate
                  ? undefined
                  : { width: `${scanProgress?.percent ?? 0}%` }
              }
            />
          </div>
          <div className="alt-status-meta">
            {scanProgress?.message || "Running scan..."}
            {scanProgress?.indeterminate ? "" : ` (${scanProgress?.percent ?? 0}%)`}
          </div>
        </div>
      ) : null}

      {!artifacts ? (
        <div className="alt-inline-cta alt-fade-in">
          <div>
            <div className="alt-cta-title">No artifacts loaded</div>
            <div className="alt-cta-subtitle">
              Load the latest scan, start a new scan, or choose an older artifact.
            </div>
          </div>
          <div className="alt-cta-actions">
            <button onClick={onLoadLatest}>Load latest scan</button>
            <button className="ghost" onClick={onStartScan}>
              Start new scan
            </button>
            <button className="ghost" onClick={() => setArtifactPanelOpen(true)}>
              Choose artifact
            </button>
          </div>
        </div>
      ) : null}

      <div className="alt-kpi-grid">
        {kpis.map((kpi, idx) => (
          <div
            key={kpi.label}
            className="alt-card alt-kpi alt-fade-in alt-kpi-clickable"
            style={{ animationDelay: `${idx * 60}ms` }}
            role="button"
            tabIndex={0}
            onClick={() => {
              setDrilldownKey(kpi.key);
              setDrilldownOpen(true);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                setDrilldownKey(kpi.key);
                setDrilldownOpen(true);
              }
            }}
          >
            <div className="alt-kpi-label">{kpi.label}</div>
            <div className="alt-kpi-value">
              {formatCount(kpi.value, kpi.suffix)}
            </div>
            <Sparkline points={kpi.spark} />
          </div>
        ))}
      </div>

      <div className="alt-middle">
        <div className="alt-panel alt-map-panel alt-fade-in" style={{ animationDelay: "80ms" }}>
          <div className="alt-panel-header">
            <h3>Global Infrastructure Footprint</h3>
            <span className="alt-panel-meta">Geo heatmap</span>
          </div>
          <div className="alt-map">
            {GEO_DOTS.map((dot, idx) => (
              <span
                key={`geo-dot-${idx}`}
                className="alt-map-dot"
                style={{
                  left: dot.left,
                  top: dot.top,
                  width: `${dot.size}px`,
                  height: `${dot.size}px`,
                }}
              />
            ))}
            <div className="alt-map-grid" />
          </div>
        </div>

        <div className="alt-panel alt-changes-panel alt-fade-in" style={{ animationDelay: "140ms" }}>
          <div className="alt-panel-header">
            <h3>Recent Changes</h3>
            <span className="alt-panel-meta">change_summary</span>
          </div>
          <div className="alt-changes">
            {changeItems.length ? (
              changeItems.map((item) => (
                <div key={item.id} className="alt-change-row">
                  <div className="alt-change-icon" />
                  <div className="alt-change-body">
                    <div className="alt-change-title">{item.label}</div>
                    <div className="alt-change-desc">
                      {item.count} affected · {item.sample.join(", ")}
                      {item.count > item.sample.length ? "…" : ""}
                    </div>
                  </div>
                  <SeverityBadge level={item.severity} />
                </div>
              ))
            ) : (
              <div className="alt-empty">
                No prior scan change summary available.
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="alt-bottom">
        <div className="alt-panel alt-risk-panel alt-fade-in" style={{ animationDelay: "180ms" }}>
          <div className="alt-panel-header">
            <h3>Risk Breakdown</h3>
            <span className="alt-panel-meta">Exposure tiers</span>
          </div>
          <div className="alt-risk-list">
            {[
              { key: "critical", label: "Critical", color: "alt-risk-critical" },
              { key: "high", label: "High", color: "alt-risk-high" },
              { key: "medium", label: "Medium", color: "alt-risk-medium" },
              { key: "low", label: "Low", color: "alt-risk-low" },
            ].map((row) => {
              const max = Math.max(
                riskCounts.critical,
                riskCounts.high,
                riskCounts.medium,
                riskCounts.low,
                1
              );
              const value = riskCounts[row.key];
              const width = Math.round((value / max) * 100);
              return (
                <div key={row.key} className="alt-risk-row">
                  <div className="alt-risk-label">{row.label}</div>
                  <div className="alt-risk-bar">
                    <span
                      className={`alt-risk-fill ${row.color}`}
                      style={{ width: `${width}%` }}
                    />
                  </div>
                  <div className="alt-risk-value">{value}</div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="alt-panel alt-gauge-panel alt-fade-in" style={{ animationDelay: "220ms" }}>
          <div className="alt-panel-header">
            <h3>Exposure Score</h3>
            <span className="alt-panel-meta">0 - 100</span>
          </div>
          <Gauge value={exposureScore} />
        </div>
      </div>

      {artifactPanelOpen ? (
        <div className="alt-modal-backdrop" onClick={() => setArtifactPanelOpen(false)}>
          <div className="alt-modal-panel" onClick={(e) => e.stopPropagation()}>
            <div className="alt-panel-header">
              <h3>Artifact controls</h3>
              <button className="ghost" onClick={() => setArtifactPanelOpen(false)}>
                Close
              </button>
            </div>
            <div className="alt-modal-actions">
              <button onClick={onLoadLatest}>Load latest scan</button>
              <button className="ghost" onClick={onStartScan}>
                Start new scan
              </button>
            </div>
            <div className="alt-modal-section">
              <div className="alt-panel-meta">Switch artifact</div>
              <div className="alt-scan-list">
                {scans && scans.length ? (
                  scans.map((scan) => (
                    <button
                      key={scan.id}
                      className={`alt-scan-row ${
                        scan.id === selectedScanId ? "active" : ""
                      }`}
                      onClick={() => onSelectScan(scan.id)}
                    >
                      <div>
                        <div className="alt-scan-title">
                          Scan #{scan.company_scan_number}
                        </div>
                        <div className="alt-scan-meta">
                          {scan.status} · {scan.scan_mode || "standard"}
                        </div>
                      </div>
                      <span className="alt-badge alt-badge--medium">
                        {scan.id === selectedScanId ? "active" : "view"}
                      </span>
                    </button>
                  ))
                ) : (
                  <div className="alt-empty">No scans available yet.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {drilldownOpen ? (
        <div className="alt-modal-backdrop" onClick={() => setDrilldownOpen(false)}>
          <div className="alt-modal-panel alt-drilldown" onClick={(e) => e.stopPropagation()}>
            <div className="alt-panel-header">
              <div>
                <h3>{drilldownData[drilldownKey]?.title}</h3>
                <div className="alt-panel-meta">
                  {drilldownData[drilldownKey]?.subtitle}
                </div>
              </div>
              <button className="ghost" onClick={() => setDrilldownOpen(false)}>
                Close
              </button>
            </div>
            <div className="alt-drilldown-tabs">
              {[
                { key: "domains", label: "Domains" },
                { key: "ips", label: "Public IPs" },
                { key: "cves", label: "Critical CVEs" },
                { key: "exposure", label: "Exposure" },
                { key: "cdn", label: "CDN Coverage" },
              ].map((tab) => (
                <button
                  key={tab.key}
                  className={`alt-tab ${drilldownKey === tab.key ? "active" : ""}`}
                  onClick={() => setDrilldownKey(tab.key)}
                >
                  {tab.label}
                </button>
              ))}
            </div>
            <div className="alt-drilldown-list">
              {drilldownData[drilldownKey]?.items?.length ? (
                drilldownData[drilldownKey].items.map((item, idx) => (
                  <div key={`${item.label}-${idx}`} className="alt-drilldown-row">
                    <div className="alt-drilldown-label">{item.label}</div>
                    <div className="alt-drilldown-meta">{item.meta}</div>
                  </div>
                ))
              ) : (
                <div className="alt-empty">No data available.</div>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
