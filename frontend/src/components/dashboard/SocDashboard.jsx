import React, { useMemo, useState } from "react";
import { DrilldownModal, useDrilldown } from "../../lib/drilldown.jsx";

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function formatCount(value) {
  if (!Number.isFinite(value)) return "0";
  return value.toLocaleString();
}

function daysUntil(dateValue) {
  if (!dateValue) return null;
  const dt = new Date(dateValue);
  if (Number.isNaN(dt.getTime())) return null;
  const diff = dt.getTime() - Date.now();
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

export default function SocDashboard({
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
  onChangeViewMode,
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

  const mailSummary = artifacts?.dns_intel?.summary || {};
  const missingDmarc =
    Number(mailSummary.mail_enabled_domains ?? 0) -
    Number(mailSummary.dmarc_domains ?? 0);

  const changeSummary = artifacts?.change_summary || null;
  const newDomains = changeSummary?.new_domains || [];
  const removedDomains = changeSummary?.removed_domains || [];
  const techChanges = changeSummary?.technology_changes || [];
  const providerChanges = changeSummary?.provider_changes || [];

  const originExposure = intelDomains.filter(
    (row) =>
      row?.web?.reachable &&
      (!row?.web?.edge_provider?.provider ||
        row?.web?.edge_provider?.provider === "none")
  ).length;

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

  const findings = useMemo(() => {
    const items = [];
    if (criticalCves) {
      items.push({
        id: "critical-cves",
        title: "Critical CVEs detected",
        severity: "critical",
        count: criticalCves,
        lastSeen: activeScan?.company_scan_number || "-",
        category: "vulns",
        action: "Review vulnerabilities",
      });
    }
    if (originExposure) {
      items.push({
        id: "origin-exposure",
        title: "Origin exposed (no CDN)",
        severity: "high",
        count: originExposure,
        lastSeen: activeScan?.company_scan_number || "-",
        category: "infra",
        action: "Inspect edge coverage",
      });
    }
    const adminHosts = allDomains.filter((d) =>
      /(admin|staging|dev|test)/i.test(d)
    );
    if (adminHosts.length) {
      items.push({
        id: "admin-hosts",
        title: "Admin / staging hostnames",
        severity: "high",
        count: adminHosts.length,
        lastSeen: activeScan?.company_scan_number || "-",
        category: "web",
        action: "Review risky hostnames",
      });
    }
    if (missingDmarc > 0) {
      items.push({
        id: "email-posture",
        title: "Email posture issues",
        severity: "medium",
        count: missingDmarc,
        lastSeen: activeScan?.company_scan_number || "-",
        category: "email",
        action: "Review DMARC coverage",
      });
    }
    if (newDomains.length || techChanges.length || providerChanges.length) {
      items.push({
        id: "major-changes",
        title: "Major changes detected",
        severity: "medium",
        count: newDomains.length + techChanges.length + providerChanges.length,
        lastSeen: activeScan?.company_scan_number || "-",
        category: "changes",
        action: "Review change summary",
      });
    }
    return items;
  }, [
    criticalCves,
    originExposure,
    allDomains,
    missingDmarc,
    newDomains.length,
    techChanges.length,
    providerChanges.length,
    activeScan?.company_scan_number,
  ]);

  const [queueFilter, setQueueFilter] = useState("all");
  const [queueSearch, setQueueSearch] = useState("");

  const queueItems = findings.filter((item) => {
    if (queueFilter === "all") return true;
    if (queueFilter === "critical") return item.severity === "critical";
    if (queueFilter === "high") return item.severity === "high";
    if (queueFilter === "changes") return item.category === "changes";
    if (queueFilter === "infra") return item.category === "infra";
    if (queueFilter === "web") return item.category === "web";
    if (queueFilter === "email") return item.category === "email";
    return true;
  }).filter((item) =>
    item.title.toLowerCase().includes(queueSearch.trim().toLowerCase())
  );

  const domainRows = allDomains.map((domain) => {
    const intel = intelDomains.find((row) => row.domain === domain);
    const provider = intel?.web?.edge_provider?.provider || "-";
    const status =
      newDomains.includes(domain)
        ? "new"
        : removedDomains.includes(domain)
          ? "removed"
          : "-";
    return {
      key: domain,
      domain,
      type: rootSet.has(domain) ? "root" : "sub",
      status,
      provider,
      responder: intel?.web?.reachable ? "yes" : "no",
    };
  });

  const ipRows = useMemo(() => {
    const map = new Map();
    dnsRecords.forEach((rec) => {
      (rec?.ips || []).forEach((ip) => {
        const next = map.get(ip) || { ip, domains: new Set(), asn: "-", country: "-" };
        if (rec?.domain) next.domains.add(rec.domain);
        map.set(ip, next);
      });
    });
    intelDomains.forEach((row) => {
      (row?.ip_asn || []).forEach((entry) => {
        if (!entry?.ip) return;
        const next = map.get(entry.ip) || {
          ip: entry.ip,
          domains: new Set(),
          asn: "-",
          country: "-",
        };
        next.asn = entry.asn_org || entry.asn || next.asn;
        next.country = entry.country || next.country;
        map.set(entry.ip, next);
      });
    });
    return Array.from(map.values()).map((row) => ({
      ip: row.ip,
      asn: row.asn,
      country: row.country,
      domainCount: row.domains.size,
      origin: "mixed",
    }));
  }, [dnsRecords, intelDomains]);

  const webRows = intelDomains.map((row) => {
    const tls = row?.web?.tls || {};
    const cert =
      tls?.cert || tls?.certificate || tls || {};
    const notAfter =
      cert?.not_after ||
      cert?.notAfter ||
      cert?.valid_until ||
      cert?.validUntil ||
      "";
    const tlsDays = daysUntil(notAfter);
    return {
      host: row.domain || "domain",
      status: row?.web?.status_code ?? "-",
      server:
        row?.web?.server ||
        (row?.web?.technologies || [])[0] ||
        "-",
      tlsDays: tlsDays !== null ? `${tlsDays}d` : "-",
      redirect:
        row?.web?.redirect_target ||
        row?.web?.redirects?.[0] ||
        "-",
    };
  });

  const vulnRows = intelDomains.map((row) => {
    const findings = row?.cve_findings || [];
    const top = findings[0] || {};
    return {
      host: row.domain || "domain",
      component: top.component || "-",
      version: top.version || "-",
      cvss: top.score ?? "-",
      count: findings.length,
    };
  });

  const [scopeTab, setScopeTab] = useState("domains");

  const timeline = scans.slice(0, 10);

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

  const { detailOpen, detailContent, openDetail, closeDetail } = useDrilldown({
    artifacts,
    roots,
    discovered,
    totalDomains,
    webHosts,
    publicIps,
    uniqueIps,
    cdnCoverage,
    findings: findings.map((item) => ({
      label: item.title,
      action: item.action,
    })),
    recentChanges: (changeSummary?.has_previous
      ? [
          { label: "New domains", count: newDomains.length, sample: newDomains.slice(0, 3) },
          { label: "Removed domains", count: removedDomains.length, sample: removedDomains.slice(0, 3) },
          { label: "Provider changes", count: providerChanges.length, sample: providerChanges.slice(0, 3) },
          { label: "Tech changes", count: techChanges.length, sample: techChanges.slice(0, 3) },
        ]
      : []),
    mailSummary,
    tlsSoonCount,
    riskCounts,
  });

  const triageItems = [
    {
      key: "domains_added",
      label: "New domains",
      value: newDomains.length,
      color: "soc-accent-purple",
      detailKey: "domains_added",
    },
    {
      key: "ips_new",
      label: "New public IPs",
      value: changeSummary?.new_ips?.length ?? 0,
      color: "soc-accent-blue",
      detailKey: "ips_new",
    },
    {
      key: "web_new",
      label: "New HTTP responders",
      value: changeSummary?.new_http?.length ?? 0,
      color: "soc-accent-green",
      detailKey: "web_new",
    },
    {
      key: "cves",
      label: "Critical CVEs",
      value: criticalCves,
      color: "soc-accent-red",
      detailKey: "vulnerabilities",
    },
    {
      key: "origin",
      label: "Origin exposure",
      value: originExposure,
      color: "soc-accent-orange",
      detailKey: "origin_exposure",
    },
    {
      key: "email",
      label: "Email posture",
      value: missingDmarc > 0 ? missingDmarc : 0,
      color: "soc-accent-yellow",
      detailKey: "email_issues",
    },
  ];

  const copySummary = () => {
    const summary = [
      `SOC summary for ${activeCompany?.slug || "-"}`,
      `Scan #${activeScan?.company_scan_number || "-"}`,
      `New domains: ${newDomains.length}`,
      `Critical CVEs: ${criticalCves}`,
      `Origin exposure: ${originExposure}`,
      `DMARC issues: ${missingDmarc > 0 ? missingDmarc : 0}`,
    ].join("\n");
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(summary);
    }
  };

  return (
    <section className="soc-dashboard">
      <div className="soc-header">
        <div>
          <div className="soc-title">SOC Analyst</div>
          <div className="soc-subtitle">
            {activeCompany?.name || "No active customer"}
            {activeScan?.company_scan_number
              ? ` · Scan #${activeScan.company_scan_number}`
              : ""}
          </div>
        </div>
        <div className="soc-actions">
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

      <div className="soc-triage">
        {triageItems.map((item) => (
          <button
            key={item.key}
            className={`soc-triage-item ${item.color}`}
            onClick={() => openDetail(item.detailKey)}
            type="button"
          >
            <span className="soc-triage-label">{item.label}</span>
            <span className="soc-triage-value">{formatCount(item.value)}</span>
          </button>
        ))}
      </div>

      <div className="soc-grid">
        <div className="soc-panel soc-queue">
          <div className="soc-panel-header">
            <h3>Findings Queue</h3>
            <span className="soc-panel-meta">{queueItems.length} items</span>
          </div>
          <div className="soc-queue-controls">
            <div className="soc-filters">
              {[
                ["all", "All"],
                ["critical", "Critical"],
                ["high", "High"],
                ["changes", "Changes"],
                ["infra", "Infra"],
                ["web", "Web"],
                ["email", "Email"],
              ].map(([key, label]) => (
                <button
                  key={key}
                  className={`soc-filter ${queueFilter === key ? "active" : ""}`}
                  onClick={() => setQueueFilter(key)}
                >
                  {label}
                </button>
              ))}
            </div>
            <input
              className="soc-search"
              placeholder="Search host…"
              value={queueSearch}
              onChange={(e) => setQueueSearch(e.target.value)}
            />
          </div>
          <div className="soc-queue-list">
            {queueItems.length ? (
              queueItems.map((item) => (
                <div key={item.id} className="soc-queue-row">
                  <span className={`soc-badge soc-${item.severity}`}>
                    {item.severity}
                  </span>
                  <div className="soc-queue-main">
                    <div className="soc-queue-title">{item.title}</div>
                    <div className="soc-queue-meta">
                      {item.count} affected · last scan #{item.lastSeen}
                    </div>
                  </div>
                  <button
                    className="ghost"
                    onClick={() => {
                      if (item.category === "changes") openDetail("changes");
                      else if (item.category === "email") openDetail("email_issues");
                      else if (item.category === "infra") openDetail("origin_exposure");
                      else if (item.category === "vulns") openDetail("vulnerabilities");
                      else openDetail("web");
                    }}
                  >
                    View
                  </button>
                </div>
              ))
            ) : (
              <div className="exec-empty">No findings match your filters.</div>
            )}
          </div>
        </div>

        <div className="soc-panel soc-scope">
          <div className="soc-panel-header">
            <h3>Scope Explorer</h3>
            <div className="soc-tabs">
              {["domains", "ips", "web", "vulns"].map((tab) => (
                <button
                  key={tab}
                  className={`soc-tab ${scopeTab === tab ? "active" : ""}`}
                  onClick={() => setScopeTab(tab)}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>
          <div className="soc-table">
            {scopeTab === "domains" ? (
              <div className="soc-table-body">
                {domainRows.slice(0, 120).map((row) => (
                  <button
                    key={row.key}
                    className="soc-table-row"
                    onClick={() => openDetail("domains")}
                  >
                    <span>{row.domain}</span>
                    <span className="soc-table-meta">
                      {row.type} · {row.status} · {row.provider} · {row.responder}
                    </span>
                  </button>
                ))}
              </div>
            ) : null}
            {scopeTab === "ips" ? (
              <div className="soc-table-body">
                {ipRows.slice(0, 120).map((row) => (
                  <button
                    key={row.ip}
                    className="soc-table-row"
                    onClick={() => openDetail("dns")}
                  >
                    <span>{row.ip}</span>
                    <span className="soc-table-meta">
                      {row.asn} · {row.country} · {row.domainCount} domains
                    </span>
                  </button>
                ))}
              </div>
            ) : null}
            {scopeTab === "web" ? (
              <div className="soc-table-body">
                {webRows.slice(0, 120).map((row) => (
                  <button
                    key={row.host}
                    className="soc-table-row"
                    onClick={() => openDetail("web")}
                  >
                    <span>{row.host}</span>
                    <span className="soc-table-meta">
                      {row.status} · {row.server} · TLS {row.tlsDays} · {row.redirect}
                    </span>
                  </button>
                ))}
              </div>
            ) : null}
            {scopeTab === "vulns" ? (
              <div className="soc-table-body">
                {vulnRows.slice(0, 120).map((row) => (
                  <button
                    key={`${row.host}-${row.component}`}
                    className="soc-table-row"
                    onClick={() => openDetail("vulnerabilities")}
                  >
                    <span>{row.host}</span>
                    <span className="soc-table-meta">
                      {row.component} {row.version} · CVSS {row.cvss} · {row.count} CVEs
                    </span>
                  </button>
                ))}
              </div>
            ) : null}
          </div>
        </div>

        <div className="soc-panel soc-changes">
          <div className="soc-panel-header">
            <h3>Change & Timeline</h3>
          </div>
          <div className="soc-change-stream">
            {changeSummary?.has_previous ? (
              <>
                <div className="soc-change-row" onClick={() => openDetail("changes")}>
                  <span>New domains</span>
                  <span className="soc-change-meta">{newDomains.length}</span>
                </div>
                <div className="soc-change-row" onClick={() => openDetail("changes")}>
                  <span>Removed domains</span>
                  <span className="soc-change-meta">{removedDomains.length}</span>
                </div>
                <div className="soc-change-row" onClick={() => openDetail("changes")}>
                  <span>Provider changes</span>
                  <span className="soc-change-meta">{providerChanges.length}</span>
                </div>
                <div className="soc-change-row" onClick={() => openDetail("changes")}>
                  <span>Tech changes</span>
                  <span className="soc-change-meta">{techChanges.length}</span>
                </div>
              </>
            ) : (
              <div className="exec-empty">No prior scan data.</div>
            )}
          </div>
          <div className="soc-timeline">
            <div className="soc-timeline-title">Scan Timeline</div>
            {timeline.map((scan) => (
              <button
                key={scan.id}
                className={`soc-timeline-row ${
                  scan.id === selectedScanId ? "active" : ""
                }`}
                onClick={() => onSelectScan?.(scan.id)}
              >
                <span>#{scan.company_scan_number}</span>
                <span className="soc-timeline-meta">
                  {scan.scan_mode || "standard"} · {scan.status}
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="soc-bottom">
        <div className="soc-bottom-actions">
          <button className="ghost" onClick={onOpenDetails}>
            View Artifacts JSON
          </button>
          <button className="ghost" onClick={onExportArtifacts} disabled={!artifacts}>
            Export Report
          </button>
          <button className="ghost" onClick={copySummary}>
            Copy Summary
          </button>
          <button className="ghost" onClick={() => onChangeViewMode?.("executive")}>
            Open in Executive view
          </button>
        </div>
        {!artifacts ? (
          <div className="soc-pill">
            Not collected in standard scan.{" "}
            <button className="ghost" onClick={() => onToggleDeepScan?.(true)}>
              Enable deep scan
            </button>
          </div>
        ) : null}
      </div>

      <DrilldownModal open={detailOpen} content={detailContent} onClose={closeDetail} />
    </section>
  );
}
