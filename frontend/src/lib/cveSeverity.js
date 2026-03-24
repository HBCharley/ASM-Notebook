export function classifySeverity(score) {
  const value = Number(score);
  if (!Number.isFinite(value)) return "Low";
  if (value >= 9.0) return "Critical";
  if (value >= 7.0) return "High";
  if (value >= 4.0) return "Medium";
  return "Low";
}

export function severityRank(level) {
  const key = String(level || "").toLowerCase();
  if (key === "critical") return 4;
  if (key === "high") return 3;
  if (key === "medium") return 2;
  if (key === "low") return 1;
  return 0;
}

export function filterFindings(findings, minLevel) {
  const minRank = severityRank(minLevel);
  return (findings || []).filter((entry) => {
    const severity = classifySeverity(entry?.score);
    return severityRank(severity) >= minRank;
  });
}

export function countFindingsBySeverity(findings) {
  const counts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };
  (findings || []).forEach((entry) => {
    const severity = classifySeverity(entry?.score);
    counts[severity] = (counts[severity] || 0) + 1;
  });
  return {
    ...counts,
    Total: counts.Critical + counts.High + counts.Medium + counts.Low,
  };
}
