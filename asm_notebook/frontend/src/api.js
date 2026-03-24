const BASE = import.meta.env.VITE_API_BASE || "";
const API_PREFIX = import.meta.env.VITE_API_PREFIX || "/api/v1";
const BASIC_USER = import.meta.env.VITE_BASIC_AUTH_USER || "";
const BASIC_PASS = import.meta.env.VITE_BASIC_AUTH_PASS || "";
const BASIC_AUTH_HEADER =
  BASIC_USER || BASIC_PASS
    ? `Basic ${btoa(`${BASIC_USER}:${BASIC_PASS}`)}`
    : "";
let AUTH_TOKEN = "";
const ETAG_CACHE = new Map();
const AUTH_TOKEN_STORAGE_KEY = "asm_auth_id_token";

export function setAuthToken(token) {
  AUTH_TOKEN = token || "";
}

export function getAuthToken() {
  return AUTH_TOKEN;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isIdempotentMethod(method) {
  const m = String(method || "GET").toUpperCase();
  return m === "GET" || m === "HEAD" || m === "OPTIONS";
}

function isRetryableStatus(status) {
  return status === 408 || status === 429 || status === 502 || status === 503 || status === 504;
}

function computeRetryDelayMs(attempt) {
  const base = 300;
  const max = 4000;
  const jitter = Math.floor(Math.random() * 120);
  const exp = Math.min(max, base * Math.pow(2, Math.max(0, attempt - 1)));
  return exp + jitter;
}

function maybeClearStoredAuthToken(status) {
  if (status !== 401) return;
  AUTH_TOKEN = "";
  ETAG_CACHE.clear();
  try {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
    }
  } catch {
    // ignore storage errors
  }
}

async function request(path, options = {}) {
  const { __retried, ...fetchOptions } = options || {};
  const attempt = Number.isFinite(fetchOptions.__attempt) ? fetchOptions.__attempt : 1;
  const maxAttempts = Number.isFinite(fetchOptions.__maxAttempts)
    ? fetchOptions.__maxAttempts
    : 3;
  delete fetchOptions.__attempt;
  delete fetchOptions.__maxAttempts;

  const method = String(fetchOptions.method || "GET").toUpperCase();
  const allowRetry = isIdempotentMethod(method);
  const hadBearer = !!AUTH_TOKEN;
  const authHeader = AUTH_TOKEN
    ? `Bearer ${AUTH_TOKEN}`
    : BASIC_AUTH_HEADER
      ? BASIC_AUTH_HEADER
      : "";
  let res;
  try {
    res = await fetch(`${BASE}${API_PREFIX}${path}`, {
      headers: {
        "Content-Type": "application/json",
        ...(authHeader ? { Authorization: authHeader } : {}),
        ...(fetchOptions.headers || {}),
      },
      ...fetchOptions,
    });
  } catch (err) {
    if (allowRetry && attempt < maxAttempts) {
      await sleep(computeRetryDelayMs(attempt));
      return request(path, { ...fetchOptions, __attempt: attempt + 1, __maxAttempts: maxAttempts });
    }
    throw err;
  }
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
    if (res.status === 401 && hadBearer && !__retried) {
      maybeClearStoredAuthToken(res.status);
      return request(path, { ...fetchOptions, __retried: true });
    }
    if (allowRetry && isRetryableStatus(res.status) && attempt < maxAttempts) {
      await sleep(computeRetryDelayMs(attempt));
      return request(path, { ...fetchOptions, __attempt: attempt + 1, __maxAttempts: maxAttempts });
    }
    maybeClearStoredAuthToken(res.status);
    const detail =
      (data && (data.message || data.detail)) ||
      (text && !data ? text : null) ||
      res.statusText ||
      "Request failed";
    const err = new Error(detail);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

async function requestIfModified(path, options = {}) {
  const { __retried, ...fetchOptions } = options || {};
  const attempt = Number.isFinite(fetchOptions.__attempt) ? fetchOptions.__attempt : 1;
  const maxAttempts = Number.isFinite(fetchOptions.__maxAttempts)
    ? fetchOptions.__maxAttempts
    : 3;
  delete fetchOptions.__attempt;
  delete fetchOptions.__maxAttempts;

  const method = String(fetchOptions.method || "GET").toUpperCase();
  const allowRetry = isIdempotentMethod(method);
  const hadBearer = !!AUTH_TOKEN;
  const authHeader = AUTH_TOKEN
    ? `Bearer ${AUTH_TOKEN}`
    : BASIC_AUTH_HEADER
      ? BASIC_AUTH_HEADER
      : "";
  const url = `${BASE}${API_PREFIX}${path}`;
  const cachedEtag = ETAG_CACHE.get(url) || "";
  let res;
  try {
    res = await fetch(url, {
      headers: {
        "Content-Type": "application/json",
        ...(authHeader ? { Authorization: authHeader } : {}),
        ...(cachedEtag ? { "If-None-Match": cachedEtag } : {}),
        ...(fetchOptions.headers || {}),
      },
      ...fetchOptions,
    });
  } catch (err) {
    if (allowRetry && attempt < maxAttempts) {
      await sleep(computeRetryDelayMs(attempt));
      return requestIfModified(path, {
        ...fetchOptions,
        __attempt: attempt + 1,
        __maxAttempts: maxAttempts,
      });
    }
    throw err;
  }
  if (res.status === 304) {
    return { notModified: true, data: null };
  }
  const nextEtag = res.headers.get("etag") || "";
  if (nextEtag) {
    ETAG_CACHE.set(url, nextEtag);
  }
  if (res.status === 204) {
    return { notModified: false, data: null };
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
    if (res.status === 401 && hadBearer && !__retried) {
      maybeClearStoredAuthToken(res.status);
      return requestIfModified(path, { ...fetchOptions, __retried: true });
    }
    if (allowRetry && isRetryableStatus(res.status) && attempt < maxAttempts) {
      await sleep(computeRetryDelayMs(attempt));
      return requestIfModified(path, {
        ...fetchOptions,
        __attempt: attempt + 1,
        __maxAttempts: maxAttempts,
      });
    }
    maybeClearStoredAuthToken(res.status);
    const detail =
      (data && (data.message || data.detail)) ||
      (text && !data ? text : null) ||
      res.statusText ||
      "Request failed";
    const err = new Error(detail);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return { notModified: false, data };
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
  listScansIfModified: (slug) => requestIfModified(`/companies/${slug}/scans`),
  latestScan: (slug) => request(`/companies/${slug}/scans/latest`),
  runScan: (slug, payload = {}) =>
    request(`/companies/${slug}/scans`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getScan: (slug, id) => request(`/companies/${slug}/scans/${id}`),
  getArtifacts: (slug, id) => request(`/companies/${slug}/scans/${id}/artifacts`),
  getArtifactsIfModified: (slug, id) =>
    requestIfModified(`/companies/${slug}/scans/${id}/artifacts`),
  getSocOverview: (slug, scanId = null) =>
    request(
      `/companies/${slug}/soc${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`
    ),
  getSocOverviewIfModified: (slug, scanId = null) =>
    requestIfModified(
      `/companies/${slug}/soc${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`
    ),
  getSocAssetDetail: (slug, hostname, scanId = null) =>
    request(
      `/companies/${slug}/soc/assets/${encodeURIComponent(hostname)}${
        scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""
      }`
    ),
  getSocAssetDetailIfModified: (slug, hostname, scanId = null) =>
    requestIfModified(
      `/companies/${slug}/soc/assets/${encodeURIComponent(hostname)}${
        scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""
      }`
    ),
  deleteScan: (slug, id) =>
    request(`/companies/${slug}/scans/${id}`, { method: "DELETE" }),
  getMe: () => request("/me"),
  getPreference: (key) =>
    request(`/me/preferences/${encodeURIComponent(key)}`),
  setPreference: (key, value) =>
    request(`/me/preferences/${encodeURIComponent(key)}`, {
      method: "PUT",
      body: JSON.stringify({ value }),
    }),
  listGroups: () => request("/admin/groups"),
  createGroup: (payload) =>
    request("/admin/groups", { method: "POST", body: JSON.stringify(payload) }),
  deleteGroup: (name) =>
    request(`/admin/groups/${encodeURIComponent(name)}`, { method: "DELETE" }),
  updateCompanyGroups: (slug, groups) =>
    request(`/admin/companies/${encodeURIComponent(slug)}/groups`, {
      method: "PUT",
      body: JSON.stringify({ groups }),
    }),
  listAuthAllowlist: () => request("/admin/auth-allowlist"),
  addAuthAllowlist: (payload) =>
    request("/admin/auth-allowlist", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteAuthAllowlist: (email) =>
    request(`/admin/auth-allowlist/${encodeURIComponent(email)}`, {
      method: "DELETE",
    }),
};
