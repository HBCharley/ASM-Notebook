const BASE = import.meta.env.VITE_API_BASE || "";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });
  if (res.status === 204) {
    return null;
  }
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const detail = data && data.detail ? data.detail : res.statusText;
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
  runScan: (slug) => request(`/companies/${slug}/scans`, { method: "POST" }),
  getScan: (slug, id) => request(`/companies/${slug}/scans/${id}`),
  getArtifacts: (slug, id) => request(`/companies/${slug}/scans/${id}/artifacts`),
  deleteScan: (slug, id) =>
    request(`/companies/${slug}/scans/${id}`, { method: "DELETE" }),
};
