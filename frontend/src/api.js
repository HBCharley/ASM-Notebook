const BASE = import.meta.env.VITE_API_BASE || "";
const API_PREFIX = import.meta.env.VITE_API_PREFIX || "/v1";
const BASIC_USER = import.meta.env.VITE_BASIC_AUTH_USER || "";
const BASIC_PASS = import.meta.env.VITE_BASIC_AUTH_PASS || "";
const BASIC_AUTH_HEADER =
  BASIC_USER || BASIC_PASS
    ? `Basic ${btoa(`${BASIC_USER}:${BASIC_PASS}`)}`
    : "";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${API_PREFIX}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(BASIC_AUTH_HEADER ? { Authorization: BASIC_AUTH_HEADER } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });
  if (res.status === 204) {
    return null;
  }
  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!res.ok) {
    const detail =
      (data && data.detail) ||
      (text && !data ? text : null) ||
      res.statusText ||
      "Request failed";
    throw new Error(detail);
  }
  return data;
}

export const api = {
  listCompanies: () => request("/companies"),
  getCompany: (slug) => request(`/companies/${slug}`),
  createCompany: (payload) =>
    request("/companies", { method: "POST", body: JSON.stringify(payload) }),
  updateCompany: (slug, payload) =>
    request(`/companies/${slug}`, { method: "PATCH", body: JSON.stringify(payload) }),
  replaceDomains: (slug, domains) =>
    request(`/companies/${slug}/domains`, {
      method: "PUT",
      body: JSON.stringify({ domains }),
    }),
  deleteCompany: (slug) => request(`/companies/${slug}`, { method: "DELETE" }),
  listScans: (slug) => request(`/companies/${slug}/scans`),
  latestScan: (slug) => request(`/companies/${slug}/scans/latest`),
  runScan: (slug, payload = {}) =>
    request(`/companies/${slug}/scans`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getScan: (slug, id) => request(`/companies/${slug}/scans/${id}`),
  getArtifacts: (slug, id) => request(`/companies/${slug}/scans/${id}/artifacts`),
  deleteScan: (slug, id) =>
    request(`/companies/${slug}/scans/${id}`, { method: "DELETE" }),
};
