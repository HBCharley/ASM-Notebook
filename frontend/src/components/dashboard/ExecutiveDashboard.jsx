import React, { useMemo } from "react";
import { DrilldownModal, useDrilldown } from "../../lib/drilldown.jsx";

const KPI_SPARKS = [
  [6, 8, 9, 12, 11, 13, 15, 16, 18, 19],
  [4, 5, 6, 7, 6, 8, 9, 10, 11, 12],
  [2, 3, 4, 5, 6, 6, 7, 8, 9, 10],
  [20, 22, 21, 24, 26, 28, 27, 29, 30, 32],
  [30, 32, 35, 38, 40, 42, 41, 44, 46, 48],
  [40, 42, 43, 45, 47, 46, 48, 50, 52, 54],
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
  const width = 96;
  const height = 28;
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const range = max - min || 1;
  const stepX = width / (points.length - 1 || 1);
  const normalized = points.map((p) => height - ((p - min) / range) * height);
  const d = normalized
    .map((y, i) => `${i === 0 ? "M" : "L"} ${i * stepX} ${y}`)
    .join(" ");
  return (
    <svg className="exec-sparkline" viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
      <path className="exec-sparkline-path" d={d} />
    </svg>
  );
}

function SeverityBadge({ level }) {
  return <span className={`exec-badge exec-badge--${level}`}>{level}</span>;
}

function Gauge({ value }) {
  const size = 160;
  const stroke = 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = clamp(value, 0, 100) / 100;
  const dash = circumference * pct;
  const color =
    value < 30 ? "#34c38f" : value < 60 ? "#f2c94c" : "#ff5b4d";
  return (
    <div className="exec-gauge">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          className="exec-gauge-track"
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
        />
        <circle
          className="exec-gauge-progress"
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
          stroke={color}
          strokeDasharray={`${dash} ${circumference - dash}`}
        />
      </svg>
      <div className="exec-gauge-value">
        <div className="exec-gauge-score">{value}</div>
        <div className="exec-gauge-label">Exposure score</div>
      </div>
    </div>
  );
}

function daysUntil(dateValue) {
  if (!dateValue) return null;
  const dt = new Date(dateValue);
  if (Number.isNaN(dt.getTime())) return null;
  const diff = dt.getTime() - Date.now();
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

export default function ExecutiveDashboard({
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
  onDeleteScan,
  onDeleteCompany,
  onExportArtifacts,
  onOpenDetails,
}) {
  const roots = artifacts?.domains?.roots || [];
  const allDomains = artifacts?.domains?.domains || [];
  const rootSet = useMemo(() => new Set(roots), [roots]);
  const discovered = allDomains.filter((d) => !rootSet.has(d));
  const totalDomains = roots.length + discovered.length;

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
  const webHosts = intelDomains.filter(
    (row) => row?.web?.reachable || Number(row?.web?.status_code ?? 0) > 0
  ).length;
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

  const changeSummary = artifacts?.change_summary || null;
  const changeDelta = changeSummary?.has_previous
    ? {
        domains: `+${changeSummary.new_domains?.length ?? 0} / -${
          changeSummary.removed_domains?.length ?? 0
        }`,
        web: `${changeSummary.technology_changes?.length ?? 0} updates`,
        ips: `${changeSummary.provider_changes?.length ?? 0} shifts`,
        cves: `${changeSummary.technology_changes?.length ?? 0} updates`,
        exposure: `${changeSummary.provider_changes?.length ?? 0} signals`,
        cdn: `${changeSummary.provider_changes?.length ?? 0} changes`,
      }
    : null;

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

  const recentChanges = useMemo(() => {
    if (!changeSummary?.has_previous) return [];
    const items = [];
    const addItem = (key, label, severity) => {
      const list = changeSummary[key] || [];
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
    addItem("technology_changes", "Technology shifts detected", "medium");
    return items.slice(0, 8);
  }, [changeSummary]);

  const findings = useMemo(() => {
    const items = [];
    const noCdn = intelDomains.filter((row) => {
      const provider = row?.web?.edge_provider?.provider;
      return row?.web?.reachable && (!provider || provider === "none");
    }).length;
    if (noCdn) {
      items.push({
        id: "nocdn",
        label: `${noCdn} hosts expose origin directly (no CDN)`,
        severity: "high",
        action: "Review edge coverage",
      });
    }
    if (criticalCves) {
      items.push({
        id: "cves",
        label: `${criticalCves} critical CVEs observed in web exposure`,
        severity: "critical",
        action: "Open vulnerability list",
      });
    }
    const highExposure = intelDomains.filter(
      (row) => Number(row?.exposure_score ?? 0) >= 80
    ).length;
    if (highExposure) {
      items.push({
        id: "exposure",
        label: `${highExposure} domains with critical exposure scores`,
        severity: "high",
        action: "Review exposure factors",
      });
    }
    const unreachable = intelDomains.filter(
      (row) => row?.web?.reachable === false
    ).length;
    if (unreachable) {
      items.push({
        id: "unreachable",
        label: `${unreachable} domains unreachable over HTTP`,
        severity: "medium",
        action: "Check DNS reachability",
      });
    }
    const mailSummary = artifacts?.dns_intel?.summary || {};
    const missingDmarc =
      Number(mailSummary.mail_enabled_domains ?? 0) -
      Number(mailSummary.dmarc_domains ?? 0);
    if (missingDmarc > 0) {
      items.push({
        id: "dmarc",
        label: `${missingDmarc} domains missing DMARC coverage`,
        severity: "medium",
        action: "Inspect email posture",
      });
    }
    return items.slice(0, 8);
  }, [artifacts, intelDomains, criticalCves]);

  const mailSummary = artifacts?.dns_intel?.summary || {};
  const tlsSoonCount = intelDomains.reduce((sum, row) => {
    const cert =
      row?.web?.tls?.cert || row?.web?.tls?.certificate || row?.web?.tls || null;
    const exp =
      cert?.not_after ||
      cert?.notAfter ||
      cert?.valid_until ||
      cert?.validUntil ||
      "";
    const remaining = daysUntil(exp);
    if (remaining !== null && remaining <= 30) return sum + 1;
    return sum;
  }, 0);

  const kpis = [
    {
      key: "domains",
      label: "Total Domains",
      value: totalDomains,
      delta: changeDelta?.domains || null,
      spark: KPI_SPARKS[0],
      detailKey: "domains",
    },
    {
      key: "web",
      label: "Web-Responding Hosts",
      value: webHosts,
      delta: changeDelta?.web || null,
      spark: KPI_SPARKS[1],
      detailKey: "web",
    },
    {
      key: "ips",
      label: "Public IPs",
      value: publicIps,
      delta: changeDelta?.ips || null,
      spark: KPI_SPARKS[2],
      detailKey: "dns",
    },
    {
      key: "cves",
      label: "Critical CVEs",
      value: criticalCves,
      delta: changeDelta?.cves || null,
      spark: KPI_SPARKS[3],
      detailKey: "vulnerabilities",
    },
    {
      key: "exposure",
      label: "Exposure Score",
      value: exposureScore,
      delta: changeDelta?.exposure || null,
      spark: KPI_SPARKS[4],
      detailKey: "exposure",
    },
    {
      key: "cdn",
      label: "CDN Coverage %",
      value: cdnCoverage,
      delta: changeDelta?.cdn || null,
      spark: KPI_SPARKS[5],
      detailKey: "cdn",
    },
  ];

  const { detailOpen, detailContent, openDetail, closeDetail } = useDrilldown({
    artifacts,
    roots,
    discovered,
    totalDomains,
    webHosts,
    publicIps,
    uniqueIps,
    cdnCoverage,
    findings,
    recentChanges,
    mailSummary,
    tlsSoonCount,
    riskCounts,
  });

  return (
    <section className="exec-dashboard">
      <div className="exec-header">
        <div>
          <div className="exec-title">Executive Dashboard</div>
          <div className="exec-subtitle">
            {activeCompany?.name || "No active customer"}
            {activeScan?.company_scan_number
              ? ` · Scan #${activeScan.company_scan_number}`
              : ""}
          </div>
        </div>
        <div className="exec-actions">
          <label className="exec-toggle">
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
          <button onClick={onLoadLatest}>Load latest scan</button>
          <button className="ghost" onClick={onStartScan}>
            Start new scan
          </button>
        </div>
      </div>

      {hasRunningScan ? (
        <div className="exec-status">
          <div className="exec-status-title">
            Scan in progress{runningScan?.scan_mode ? ` · ${runningScan.scan_mode}` : ""}
          </div>
          <div className="exec-status-bar">
            <span
              className={`exec-status-fill ${
                scanProgress?.indeterminate ? "indeterminate" : "determinate"
              }`}
              style={
                scanProgress?.indeterminate
                  ? undefined
                  : { width: `${scanProgress?.percent ?? 0}%` }
              }
            />
          </div>
          <div className="exec-status-meta">
            {scanProgress?.message || "Running scan..."}
            {scanProgress?.indeterminate ? "" : ` (${scanProgress?.percent ?? 0}%)`}
          </div>
        </div>
      ) : null}

      <div className="exec-kpis">
        {kpis.map((kpi) => (
          <button
            key={kpi.key}
            className="exec-kpi-card"
            type="button"
            onClick={() => openDetail(kpi.detailKey)}
          >
            <div className="exec-kpi-value">{formatCount(kpi.value)}</div>
            <div className="exec-kpi-label">{kpi.label}</div>
            <div className="exec-kpi-footer">
              <span className="exec-kpi-delta">
                {changeSummary?.has_previous ? `Δ ${kpi.delta || "—"}` : "Δ —"}
              </span>
              <Sparkline points={kpi.spark} />
            </div>
          </button>
        ))}
      </div>

      <div className="exec-grid">
        <div className="exec-panel exec-risk">
          <div className="exec-panel-header">
            <h3>Risk Posture</h3>
            <span className="exec-panel-meta">Exposure overview</span>
            <button className="ghost" onClick={() => openDetail("risk")}>
              View details
            </button>
          </div>
          <div className="exec-risk-body">
            <Gauge value={exposureScore} />
            <div className="exec-risk-bars">
              {[
                { key: "critical", label: "Critical", color: "exec-risk-critical" },
                { key: "high", label: "High", color: "exec-risk-high" },
                { key: "medium", label: "Medium", color: "exec-risk-medium" },
                { key: "low", label: "Low", color: "exec-risk-low" },
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
                  <button
                    key={row.key}
                    className="exec-risk-row"
                    onClick={() => openDetail("risk")}
                    type="button"
                  >
                    <div className="exec-risk-label">{row.label}</div>
                    <div className="exec-risk-bar">
                      <span
                        className={`exec-risk-fill ${row.color}`}
                        style={{ width: `${width}%` }}
                      />
                    </div>
                    <div className="exec-risk-value">{value}</div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        <div className="exec-panel exec-findings">
          <div className="exec-panel-header">
            <h3>Top Findings</h3>
            <span className="exec-panel-meta">Highest priority signals</span>
            <button className="ghost" onClick={() => openDetail("findings")}>
              View details
            </button>
          </div>
          <div className="exec-findings-list">
            {findings.length ? (
              findings.map((item, idx) => (
                <div key={item.id} className="exec-finding">
                  <div>
                    <div className="exec-finding-title">
                      {idx + 1}. {item.label}
                    </div>
                    <div className="exec-finding-meta">{item.action}</div>
                  </div>
                  <div className="exec-finding-actions">
                    <SeverityBadge level={item.severity} />
                    <button
                      className="ghost"
                      type="button"
                      onClick={() => openDetail("findings")}
                    >
                      View details
                    </button>
                  </div>
                </div>
              ))
            ) : (
              <div className="exec-empty">No prioritized findings for this scan.</div>
            )}
          </div>
        </div>

        <div className="exec-panel exec-changes">
          <div className="exec-panel-header">
            <h3>Recent Changes</h3>
            <span className="exec-panel-meta">Delta from previous scan</span>
            <button className="ghost" onClick={() => openDetail("changes")}>
              View details
            </button>
          </div>
          <div className="exec-changes-list">
            {recentChanges.length ? (
              recentChanges.map((item) => (
                <button
                  key={item.id}
                  className="exec-change-row"
                  type="button"
                  onClick={() => openDetail("changes")}
                >
                  <div>
                    <div className="exec-change-title">{item.label}</div>
                    <div className="exec-change-meta">
                      {item.count} affected · {item.sample.join(", ")}
                      {item.count > item.sample.length ? "…" : ""}
                    </div>
                  </div>
                  <SeverityBadge level={item.severity} />
                </button>
              ))
            ) : (
              <div className="exec-empty">No prior scan change summary available.</div>
            )}
          </div>
        </div>

        <div className="exec-panel exec-coverage">
          <div className="exec-panel-header">
            <h3>Coverage & Hygiene</h3>
            <span className="exec-panel-meta">Email + TLS posture</span>
            <button className="ghost" onClick={() => openDetail("hygiene")}>
              View details
            </button>
          </div>
          <div className="exec-coverage-grid">
            <div className="exec-coverage-card">
              <div className="exec-coverage-title">Email posture</div>
              <div className="exec-coverage-pills">
                <span className="exec-pill">
                  SPF {mailSummary.spf_domains ?? 0}
                </span>
                <span className="exec-pill">
                  DMARC {mailSummary.dmarc_domains ?? 0}
                </span>
                <span className="exec-pill exec-pill-muted">MTA-STS N/A</span>
                <span className="exec-pill exec-pill-muted">BIMI N/A</span>
              </div>
            </div>
            <div className="exec-coverage-card">
              <div className="exec-coverage-title">TLS posture</div>
              <div className="exec-coverage-meta">
                {tlsSoonCount
                  ? `${tlsSoonCount} certs expiring within 30 days`
                  : "No imminent certificate expirations detected."}
              </div>
              <div className="exec-coverage-pills">
                <span className="exec-pill">
                  Coverage {intelDomains.length ? "Observed" : "Not collected"}
                </span>
                {!intelDomains.length ? (
                  <span className="exec-pill exec-pill-muted">
                    Not collected in standard scan
                  </span>
                ) : null}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="exec-panel exec-quick">
        <div className="exec-panel-header">
          <h3>Quick Actions</h3>
          <span className="exec-panel-meta">Operational controls</span>
        </div>
        <div className="exec-quick-grid">
          <div className="exec-quick-card">
            <div className="exec-quick-label">Scan selection</div>
            <select
              value={selectedScanId || ""}
              onChange={(e) => onSelectScan?.(Number(e.target.value))}
            >
              <option value="">Select scan</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  #{scan.company_scan_number} · {scan.status}
                </option>
              ))}
            </select>
            <div className="exec-quick-actions">
              <button className="ghost" onClick={onLoadLatest}>
                Load latest
              </button>
              <button
                className="ghost danger"
                onClick={() => onDeleteScan?.(activeScan)}
                disabled={!activeScan}
              >
                Delete scan
              </button>
            </div>
          </div>
          <div className="exec-quick-card">
            <div className="exec-quick-label">Artifacts</div>
            <div className="exec-quick-meta">
              {artifacts ? "Artifacts loaded" : "No artifacts loaded"}
            </div>
            <div className="exec-quick-actions">
              <button className="ghost" onClick={() => onOpenDetails?.("artifacts")}>
                Open artifacts
              </button>
              <button
                className="ghost"
                onClick={onExportArtifacts}
                disabled={!artifacts}
              >
                Export JSON
              </button>
            </div>
          </div>
          <div className="exec-quick-card">
            <div className="exec-quick-label">Company</div>
            <div className="exec-quick-meta">{activeCompany?.slug || "-"}</div>
            <div className="exec-quick-actions">
              <button className="ghost" onClick={onManageDetails}>
                Manage details
              </button>
              <button className="ghost danger" onClick={onDeleteCompany}>
                Delete company
              </button>
            </div>
          </div>
        </div>
      </div>

      <DrilldownModal open={detailOpen} content={detailContent} onClose={closeDetail} />
    </section>
  );
}
