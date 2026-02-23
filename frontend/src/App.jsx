import React, { useEffect, useMemo, useState } from "react";
import { api } from "./api.js";

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function parseDomains(input) {
  return input
    .split(/[\n,]+/)
    .map((d) => d.trim())
    .filter(Boolean);
}

export default function App() {
  const [companies, setCompanies] = useState([]);
  const [activeSlug, setActiveSlug] = useState("");
  const [activeCompany, setActiveCompany] = useState(null);
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [artifacts, setArtifacts] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [newCompany, setNewCompany] = useState({
    slug: "",
    name: "",
    domains: "",
  });
  const [domainEditor, setDomainEditor] = useState("");
  const [renameInput, setRenameInput] = useState("");

  const activeScan = useMemo(
    () => scans.find((s) => s.id === selectedScanId),
    [scans, selectedScanId]
  );

  async function loadCompanies() {
    const data = await api.listCompanies();
    setCompanies(data);
    if (!activeSlug && data.length > 0) {
      setActiveSlug(data[0].slug);
    }
  }

  async function loadCompany(slug) {
    const [company, scanList] = await Promise.all([
      api.getCompany(slug),
      api.listScans(slug),
    ]);
    setActiveCompany(company);
    setScans(scanList);
    setDomainEditor(company.domains.join("\n"));
    setRenameInput(company.name);
  }

  async function loadArtifacts(slug, scanId) {
    const data = await api.getArtifacts(slug, scanId);
    setArtifacts(data);
  }

  async function startScan(slug) {
    const result = await api.runScan(slug);
    await loadCompany(slug);
    if (result?.scan_id) {
      setSelectedScanId(result.scan_id);
      await loadArtifacts(slug, result.scan_id);
    }
  }

  async function handleSelectCompany(slug) {
    setActiveSlug(slug);
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
    if (!activeSlug) return;
    runWithStatus(() => loadCompany(activeSlug));
  }, [activeSlug]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-title">ASM Notebook</div>
          <div className="brand-sub">
            Passive attack surface inventory and scan history
          </div>
        </div>
        <div className="status">
          <span className={loading ? "dot pulse" : "dot"} />
          {loading ? "Syncing" : "Idle"}
        </div>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <div className="panel-header">
            <h2>Companies</h2>
            <button
              className="ghost"
              onClick={() => runWithStatus(loadCompanies)}
            >
              Refresh
            </button>
          </div>

          <div className="company-list">
            {companies.length === 0 ? (
              <div className="empty">No companies yet</div>
            ) : (
              companies.map((c) => (
                <button
                  key={c.slug}
                  className={
                    c.slug === activeSlug ? "company active" : "company"
                  }
                  onClick={() => handleSelectCompany(c.slug)}
                >
                  <div className="company-name">{c.name}</div>
                  <div className="company-slug">{c.slug}</div>
                </button>
              ))
            )}
          </div>

          <div className="divider" />

          <div className="panel-header">
            <h2>Add company</h2>
          </div>
          <div className="form">
            <label>
              Slug
              <input
                value={newCompany.slug}
                onChange={(e) =>
                  setNewCompany({ ...newCompany, slug: e.target.value })
                }
                placeholder="deepgram"
              />
            </label>
            <label>
              Name
              <input
                value={newCompany.name}
                onChange={(e) =>
                  setNewCompany({ ...newCompany, name: e.target.value })
                }
                placeholder="Deepgram"
              />
            </label>
            <label>
              Domains
              <textarea
                rows={3}
                value={newCompany.domains}
                onChange={(e) =>
                  setNewCompany({ ...newCompany, domains: e.target.value })
                }
                placeholder="deepgram.com"
              />
            </label>
            <button
              onClick={() =>
                runWithStatus(async () => {
                  const domains = parseDomains(newCompany.domains);
                  await api.createCompany({
                    slug: newCompany.slug,
                    name: newCompany.name,
                    domains,
                  });
                  setNewCompany({ slug: "", name: "", domains: "" });
                  await loadCompanies();
                })
              }
            >
              Create
            </button>
          </div>
        </aside>

        <main className="content">
          {!activeCompany ? (
            <div className="empty-state">
              <h2>Select a company</h2>
              <p>Choose a company to view domains and scan history.</p>
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
                          setActiveSlug("");
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

                <div className="grid">
                  <div className="panel">
                    <h3>Rename company</h3>
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
                    <textarea
                      rows={4}
                      value={domainEditor}
                      onChange={(e) => setDomainEditor(e.target.value)}
                    />
                    <div className="row">
                      <button
                        onClick={() =>
                          runWithStatus(async () => {
                            const domains = parseDomains(domainEditor);
                            await api.replaceDomains(activeCompany.slug, domains);
                            await loadCompany(activeCompany.slug);
                          })
                        }
                      >
                        Replace domains
                      </button>
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
                  <pre className="code">
                    {JSON.stringify(artifacts, null, 2)}
                  </pre>
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
