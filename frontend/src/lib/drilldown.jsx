import React, { useEffect, useMemo, useState } from "react";
import { classifySeverity, severityRank } from "./cveSeverity.js";

function daysUntil(dateValue) {
  if (!dateValue) return null;
  const dt = new Date(dateValue);
  if (Number.isNaN(dt.getTime())) return null;
  const diff = dt.getTime() - Date.now();
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

export function buildDrilldownPayload({
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
  minCveSeverity,
}) {
  const intelDomains = artifacts?.dns_intel?.domains || [];
  const changeSummary = artifacts?.change_summary || null;

  const minRank = severityRank(minCveSeverity);
  const cveRows = [];
  intelDomains.forEach((row) => {
    const rows = row?.cve_findings || [];
    rows.forEach((entry) => {
      const score = Number(entry?.score ?? 0);
      const severity = classifySeverity(score);
      if (severityRank(severity) < minRank) return;
      cveRows.push({
        title: `${entry.cve || "CVE"} · ${entry.component || "component"} ${
          entry.version || ""
        }`.trim(),
        meta: `${row.domain || "domain"} · ${severity} · score ${score}`,
        score,
      });
    });
  });

  const exposureRows = intelDomains
    .map((row) => ({
      title: row.domain || "domain",
      meta: `score ${Number(row?.exposure_score ?? 0)}`,
      score: Number(row?.exposure_score ?? 0),
      detail: {
        score: Number(row?.exposure_score ?? 0),
        factors: row?.exposure_factors || [],
      },
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 80);

  const riskBucketRows = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  intelDomains.forEach((row) => {
    const score = Number(row?.exposure_score ?? 0);
    const entry = {
      title: row.domain || "domain",
      meta: `score ${score}`,
      score,
      detail: {
        score,
        factors: row?.exposure_factors || [],
      },
    };
    if (score >= 80) riskBucketRows.critical.push(entry);
    else if (score >= 60) riskBucketRows.high.push(entry);
    else if (score >= 30) riskBucketRows.medium.push(entry);
    else riskBucketRows.low.push(entry);
  });

  const webRows = intelDomains
    .filter((row) => row?.web?.reachable || Number(row?.web?.status_code ?? 0) > 0)
    .map((row) => ({
      title: row.domain || "domain",
      meta: `HTTP ${row?.web?.status_code ?? "-"} · ${
        row?.web?.title ? row.web.title.slice(0, 44) : "reachable"
      }`,
    }))
    .slice(0, 120);

  const ipRows = Array.from(uniqueIps)
    .sort((a, b) => a.localeCompare(b))
    .map((ip) => ({ title: ip, meta: "Public IP" }))
    .slice(0, 200);

  const cdnRows = intelDomains
    .filter((row) => {
      const provider = row?.web?.edge_provider?.provider;
      return provider && provider !== "none";
    })
    .map((row) => ({
      title: row.domain || "domain",
      meta: row?.web?.edge_provider?.provider || "edge",
    }))
    .slice(0, 120);

  const noCdnRows = intelDomains
    .filter(
      (row) =>
        row?.web?.reachable &&
        (!row?.web?.edge_provider?.provider ||
          row?.web?.edge_provider?.provider === "none")
    )
    .map((row) => ({
      title: row.domain || "domain",
      meta: "no CDN detected",
    }))
    .slice(0, 80);

  const findingsRows = findings.map((item) => ({
    title: item.label,
    meta: item.action,
  }));

  const changesRows = recentChanges.map((item) => ({
    title: `${item.label} (${item.count})`,
    meta: item.sample.join(", "),
  }));

  const emailRows = [
    { title: "SPF coverage", meta: `${mailSummary.spf_domains ?? 0} domains` },
    { title: "DMARC coverage", meta: `${mailSummary.dmarc_domains ?? 0} domains` },
    { title: "Mail-enabled domains", meta: `${mailSummary.mail_enabled_domains ?? 0}` },
    { title: "MTA-STS", meta: "Not collected in standard scan" },
    { title: "BIMI", meta: "Not collected in standard scan" },
  ];

  const tlsRows = [
    {
      title: "Certificates expiring within 30 days",
      meta: `${tlsSoonCount} domains`,
    },
    {
      title: "TLS coverage",
      meta: intelDomains.length ? "Observed in current scan" : "Not collected",
    },
  ];

  const addedDomains = changeSummary?.new_domains || [];
  const newHttp = changeSummary?.new_http || [];
  const newIps = changeSummary?.new_ips || [];

  return {
    domains: {
      title: "Domains",
      subtitle: `${totalDomains} total · ${roots.length} roots · ${discovered.length} discovered`,
      sections: [
        { label: "Root domains", rows: roots.map((d) => ({ title: d, meta: "root" })) },
        { label: "Discovered domains", rows: discovered.map((d) => ({ title: d, meta: "discovered" })) },
      ],
    },
    domains_added: {
      title: "New Domains",
      subtitle: `${addedDomains.length} domains added in latest scan`,
      rows: addedDomains.map((d) => ({ title: d, meta: "added" })),
    },
    web: {
      title: "Web-Responding Hosts",
      subtitle: `${webHosts} hosts reporting HTTP`,
      rows: webRows,
    },
    web_new: {
      title: "New HTTP Responders",
      subtitle: newHttp.length
        ? `${newHttp.length} hosts responding in latest scan`
        : "No delta data available",
      rows: newHttp.map((d) => ({ title: d, meta: "new responder" })),
    },
    dns: {
      title: "Public IPs",
      subtitle: `${publicIps} unique IPs`,
      rows: ipRows,
    },
    ips_new: {
      title: "New Public IPs",
      subtitle: newIps.length
        ? `${newIps.length} new IPs detected`
        : "No delta data available",
      rows: newIps.map((ip) => ({ title: ip, meta: "new" })),
    },
    vulnerabilities: {
      title: "CVE Findings",
      subtitle: `${cveRows.length} findings at or above ${minCveSeverity}`,
      rows: cveRows
        .slice()
        .sort((a, b) => b.score - a.score)
        .map(({ score, ...row }) => row),
    },
    exposure: {
      title: "Exposure Scores",
      subtitle: `Top ${Math.min(exposureRows.length, 80)} domains by score`,
      rows: exposureRows,
    },
    cdn: {
      title: "CDN Coverage",
      subtitle: `${cdnCoverage}% coverage`,
      sections: [
        { label: "Edge/CDN detected", rows: cdnRows },
        { label: "No CDN detected", rows: noCdnRows },
      ],
    },
    origin_exposure: {
      title: "Origin Exposure (No CDN)",
      subtitle: `${noCdnRows.length} hosts expose origin directly`,
      rows: noCdnRows,
    },
    email_issues: {
      title: "Email Posture Issues",
      subtitle: "DMARC/SPF gaps and mail coverage",
      rows: emailRows,
    },
    risk: {
      title: "Risk Posture",
      subtitle: "Exposure score breakdown",
      sections: [
        {
          label: `Critical (${riskCounts.critical})`,
          rows: riskBucketRows.critical
            .sort((a, b) => b.score - a.score)
            .slice(0, 80),
        },
        {
          label: `High (${riskCounts.high})`,
          rows: riskBucketRows.high
            .sort((a, b) => b.score - a.score)
            .slice(0, 80),
        },
        {
          label: `Medium (${riskCounts.medium})`,
          rows: riskBucketRows.medium
            .sort((a, b) => b.score - a.score)
            .slice(0, 80),
        },
        {
          label: `Low (${riskCounts.low})`,
          rows: riskBucketRows.low
            .sort((a, b) => b.score - a.score)
            .slice(0, 80),
        },
      ],
    },
    findings: {
      title: "Top Findings",
      subtitle: `${findings.length} prioritized findings`,
      rows: findingsRows,
    },
    changes: {
      title: "Recent Changes",
      subtitle: changeSummary?.has_previous
        ? "Delta from previous scan"
        : "No prior scan data",
      rows: changesRows,
    },
    hygiene: {
      title: "Coverage & Hygiene",
      subtitle: "Email and TLS posture summary",
      sections: [
        { label: "Email posture", rows: emailRows },
        { label: "TLS posture", rows: tlsRows },
      ],
    },
  };
}

export function useDrilldown(data) {
  const [detailKey, setDetailKey] = useState(null);
  const detailOpen = !!detailKey;
  const payload = useMemo(() => buildDrilldownPayload(data), [data]);
  const detailContent = detailKey ? payload[detailKey] : null;

  useEffect(() => {
    if (!detailOpen) return;
    const onKeyDown = (event) => {
      if (event.key !== "Escape") return;
      setDetailKey(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [detailOpen]);

  return {
    detailKey,
    detailOpen,
    detailContent,
    openDetail: (key) => key && setDetailKey(key),
    closeDetail: () => setDetailKey(null),
  };
}

export function DrilldownModal({ open, content, onClose }) {
  const [expandedKey, setExpandedKey] = useState(null);
  if (!open || !content) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-panel exec-modal" onClick={(e) => e.stopPropagation()}>
        <div className="exec-modal-header">
          <div>
            <h3>{content.title}</h3>
            <div className="exec-modal-subtitle">{content.subtitle}</div>
          </div>
          <button className="ghost" onClick={onClose}>
            Close
          </button>
        </div>
        {content.sections ? (
          content.sections.map((section) => (
            <div key={section.label} className="exec-modal-section">
              <div className="exec-modal-section-title">{section.label}</div>
              <div className="exec-modal-list">
                {(section.rows || []).length ? (
                  section.rows.slice(0, 200).map((row, idx) => {
                    const key = `${section.label}-${idx}`;
                    const isOpen = expandedKey === key;
                    const detail = row.detail || { summary: row.meta };
                    return (
                      <div key={key}>
                        <button
                          className="exec-modal-row"
                          type="button"
                          onClick={() => setExpandedKey(isOpen ? null : key)}
                        >
                          <span>{row.title}</span>
                          <span className="exec-modal-meta">{row.meta}</span>
                        </button>
                        {isOpen ? (
                          <div className="exec-modal-detail">
                            {"score" in detail ? (
                              <div>Score: {detail.score ?? "-"}</div>
                            ) : null}
                            {"factors" in detail ? (
                              <div>
                                Factors:{" "}
                                {(detail.factors || []).length
                                  ? detail.factors.join(", ")
                                  : "None"}
                              </div>
                            ) : null}
                            {!("score" in detail) && !("factors" in detail) ? (
                              <div>Details: {detail.summary || "-"}</div>
                            ) : null}
                          </div>
                        ) : null}
                      </div>
                    );
                  })
                ) : (
                  <div className="exec-empty">No entries available.</div>
                )}
              </div>
            </div>
          ))
        ) : (
          <div className="exec-modal-list">
            {(content.rows || []).length ? (
              content.rows.map((row, idx) => {
                const key = `${content.title}-${idx}`;
                const isOpen = expandedKey === key;
                const detail = row.detail || { summary: row.meta };
                return (
                  <div key={key}>
                    <button
                      className="exec-modal-row"
                      type="button"
                      onClick={() => setExpandedKey(isOpen ? null : key)}
                    >
                      <span>{row.title}</span>
                      <span className="exec-modal-meta">{row.meta}</span>
                    </button>
                    {isOpen ? (
                      <div className="exec-modal-detail">
                        {"score" in detail ? (
                          <div>Score: {detail.score ?? "-"}</div>
                        ) : null}
                        {"factors" in detail ? (
                          <div>
                            Factors:{" "}
                            {(detail.factors || []).length
                              ? detail.factors.join(", ")
                              : "None"}
                          </div>
                        ) : null}
                        {!("score" in detail) && !("factors" in detail) ? (
                          <div>Details: {detail.summary || "-"}</div>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                );
              })
            ) : (
              <div className="exec-empty">No entries available.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
