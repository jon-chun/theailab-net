const crypto = require("node:crypto");

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const OAUTH_COOKIE = "iphs_oauth";
const OAUTH_COOKIE_PATH = "/.netlify/functions/google-callback";
const OAUTH_TTL_SECONDS = 600;
const CLOCK_SKEW_SECONDS = 60;
const FALLBACK_NEXT = "/index.html";
const ORIGINS = new Set([
  "https://theailab.net", "http://localhost:8888", "https://localhost:8888",
]);
const NEXT_PATHS = new Set([
  "/", "/index.html", "/account.html", "/admin",
  ...["about", "admin", "assignments", "policies", "schedule", "syllabus"]
    .map((name) => `/core/${name}.html`),
  ...Array.from({ length: 15 }, (_, i) => `/weeks/week-${String(i + 1).padStart(2, "0")}.html`),
]);
const URL_SAFE = /^[A-Za-z0-9_-]+$/;
const EMAIL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:gmail\.com|kenyon\.edu)$/;
const STATUS = new Set(["pending", "approved", "rejected"]);

class OAuthError extends Error {
  constructor(code) { super(code); this.code = code; }
}
function problem(code) { throw new OAuthError(code); }
function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function equal(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = Buffer.from(a); const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function randomUrlSafe(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}
function pkceChallenge(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}
function parseList(raw) {
  return [...new Set(String(raw || "").split(",")
    .map((part) => part.trim().toLowerCase()).filter(Boolean))];
}
function config(env = process.env) {
  if (env.GOOGLE_OAUTH_ENABLED !== "true") problem("disabled");
  const siteUrl = env.SITE_URL;
  if (!ORIGINS.has(siteUrl)) problem("configuration");
  if (typeof env.SESSION_SECRET !== "string" || !env.SESSION_SECRET ||
      typeof env.GOOGLE_CLIENT_ID !== "string" ||
      !/^[A-Za-z0-9._-]+\.apps\.googleusercontent\.com$/.test(env.GOOGLE_CLIENT_ID) ||
      typeof env.GOOGLE_CLIENT_SECRET !== "string" || !env.GOOGLE_CLIENT_SECRET ||
      /[\x00-\x20\x7f]/.test(env.GOOGLE_CLIENT_SECRET)) problem("configuration");
  const adminEmails = parseList(env.ADMIN_EMAILS);
  const autoApproveEmails = parseList(env.AUTO_APPROVE_EMAILS);
  const autoApproveDomains = parseList(env.AUTO_APPROVE_DOMAINS);
  if ([...adminEmails, ...autoApproveEmails].some((email) => !EMAIL.test(email)) ||
      autoApproveDomains.some((domain) => domain !== "kenyon.edu")) problem("configuration");
  const notifyEmail = String(env.ADMIN_NOTIFY_EMAIL || "").trim();
  if (notifyEmail && (notifyEmail.length > 254 ||
      !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(notifyEmail) ||
      /[\x00-\x1f\x7f]/.test(notifyEmail))) problem("configuration");
  return {
    siteUrl, clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET,
    sessionSecret: env.SESSION_SECRET,
    redirectUri: `${siteUrl}${OAUTH_COOKIE_PATH}`,
    adminEmails, autoApproveEmails, autoApproveDomains, notifyEmail,
  };
}
function safeNextPath(next) {
  if (typeof next !== "string" || next.length > 512 || !next.startsWith("/") ||
      next.startsWith("//") || /[\\\x00-\x20\x7f]/.test(next)) return FALLBACK_NEXT;
  try {
    const decoded = decodeURIComponent(next);
    if (/[\\\x00-\x1f\x7f]/.test(decoded)) return FALLBACK_NEXT;
    const url = new URL(next, "https://redirect.invalid");
    if (url.origin !== "https://redirect.invalid" || url.username || url.password ||
        url.pathname.includes("%") || !NEXT_PATHS.has(url.pathname)) return FALLBACK_NEXT;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch { return FALLBACK_NEXT; }
}
function queryValue(event, name, maxLength) {
  const many = event.multiValueQueryStringParameters || {};
  const one = event.queryStringParameters || {};
  let value;
  if (typeof event.rawQuery === "string") {
    const values = new URLSearchParams(event.rawQuery).getAll(name);
    if (values.length > 1) problem("query");
    value = values[0];
    if (Object.hasOwn(one, name) && one[name] !== value) problem("query");
  } else if (Object.hasOwn(many, name)) {
    if (!Array.isArray(many[name]) || many[name].length !== 1) problem("query");
    value = many[name][0];
    if (Object.hasOwn(one, name) && one[name] !== value) problem("query");
  } else { value = one[name]; }
  if (value == null) return undefined;
  if (typeof value !== "string" || !value || value.length > maxLength ||
      /[\x00-\x1f\x7f]/.test(value)) problem("query");
  return value;
}
function transactionCookieFromEvent(event) {
  const headers = event.headers || {};
  const header = headers.cookie || headers.Cookie || "";
  if (typeof header !== "string" || header.length > 16384) return null;
  const values = [];
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0 || part.slice(0, index).trim() !== OAUTH_COOKIE) continue;
    try { values.push(decodeURIComponent(part.slice(index + 1).trim())); }
    catch { return null; }
  }
  return values.length === 1 ? values[0] : null;
}
function oauthKey(secret) {
  if (typeof secret !== "string" || !secret) problem("configuration");
  return crypto.createHmac("sha256", secret).update("iphs-google-oauth-v2-key").digest();
}
function sealTransaction(transaction, secret) {
  const payload = Buffer.from(JSON.stringify(transaction)).toString("base64url");
  const signed = `oauth2.${payload}`;
  const signature = crypto.createHmac("sha256", oauthKey(secret)).update(signed).digest("base64url");
  return `${signed}.${signature}`;
}
function readTransaction(token, cfg, now = Math.floor(Date.now() / 1000)) {
  if (typeof token !== "string" || token.length > 3000) return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "oauth2" ||
      !URL_SAFE.test(parts[1]) || !URL_SAFE.test(parts[2])) return null;
  const expected = crypto.createHmac("sha256", oauthKey(cfg.sessionSecret))
    .update(`oauth2.${parts[1]}`).digest("base64url");
  if (!equal(parts[2], expected)) return null;
  try {
    const st = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (!object(st) || st.purpose !== "google-login-v2" ||
        !Number.isSafeInteger(st.iat) || !Number.isSafeInteger(st.exp) ||
        st.iat > now + CLOCK_SKEW_SECONDS || st.exp <= now ||
        st.exp !== st.iat + OAUTH_TTL_SECONDS ||
        st.clientId !== cfg.clientId || st.redirectUri !== cfg.redirectUri ||
        ![st.state, st.nonce].every((v) => typeof v === "string" && v.length === 43 && URL_SAFE.test(v)) ||
        typeof st.verifier !== "string" || st.verifier.length !== 64 || !URL_SAFE.test(st.verifier) ||
        typeof st.next !== "string" || st.next !== safeNextPath(st.next)) return null;
    return st;
  } catch { return null; }
}
function oauthCookie(value, maxAge) {
  if (typeof value !== "string" || /[^A-Za-z0-9_.-]/.test(value) ||
      ![0, OAUTH_TTL_SECONDS].includes(maxAge)) problem("cookie");
  return `${OAUTH_COOKIE}=${value}; Path=${OAUTH_COOKIE_PATH}; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function response(statusCode, body = "", extra = {}, cookies = []) {
  const result = {
    statusCode, body,
    headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", ...extra },
  };
  if (cookies.length) result.multiValueHeaders = { "Set-Cookie": cookies };
  return result;
}
function redirect(location, cookies = []) {
  if (typeof location !== "string" || /[\x00-\x20\x7f]/.test(location)) problem("redirect");
  return response(302, "", { Location: location }, cookies);
}
function buildAuthUrl({ clientId, redirectUri, state, nonce, codeChallenge }) {
  const params = new URLSearchParams({
    client_id: clientId, redirect_uri: redirectUri, response_type: "code",
    scope: "openid email profile", state, nonce,
    code_challenge: codeChallenge, code_challenge_method: "S256", prompt: "select_account",
  });
  return `${GOOGLE_AUTH_URL}?${params.toString()}`;
}
function decodeTokenEndpointIdToken(jwt) {
  if (typeof jwt !== "string" || jwt.length > 16384) return null;
  const parts = jwt.split(".");
  if (parts.length !== 3 || !parts.every((part) => URL_SAFE.test(part))) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    if (!object(header) || header.alg !== "RS256" || header.crit !== undefined) return null;
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return object(claims) ? claims : null;
  } catch { return null; }
}
function validateIdTokenClaims(claims, { clientId, nonce, now = Math.floor(Date.now() / 1000) }) {
  const bad = (error) => ({ ok: false, error });
  if (!object(claims)) return bad("claims");
  if (!["https://accounts.google.com", "accounts.google.com"].includes(claims.iss)) return bad("issuer");
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (aud.length !== 1 || aud[0] !== clientId ||
      (claims.azp !== undefined && claims.azp !== clientId)) return bad("audience");
  if (!Number.isSafeInteger(claims.exp) || !Number.isSafeInteger(claims.iat) ||
      claims.exp <= now - CLOCK_SKEW_SECONDS || claims.exp <= claims.iat ||
      claims.iat > now + CLOCK_SKEW_SECONDS || claims.iat < now - OAUTH_TTL_SECONDS - CLOCK_SKEW_SECONDS ||
      (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) ||
        claims.nbf > now + CLOCK_SKEW_SECONDS))) return bad("time");
  if (typeof nonce !== "string" || !nonce || !equal(claims.nonce, nonce)) return bad("nonce");
  if (typeof claims.sub !== "string" || claims.sub.length < 1 || claims.sub.length > 255 ||
      /[^\x21-\x7e]/.test(claims.sub)) return bad("subject");
  if (typeof claims.email !== "string" || claims.email.length > 254 || claims.email_verified !== true)
    return bad("email");
  const email = claims.email.toLowerCase();
  if (!EMAIL.test(email)) return bad("unsupported_account");
  if (email.endsWith("@kenyon.edu") && claims.hd !== "kenyon.edu") return bad("unsupported_account");
  if (claims.hd !== undefined && (typeof claims.hd !== "string" || claims.hd.length > 253 ||
      /[\x00-\x20\x7f]/.test(claims.hd))) return bad("claims");
  return { ok: true };
}
async function exchangeCode({ code, verifier, cfg, fetchImpl = fetch }) {
  const signal = AbortSignal.timeout(8000);
  const res = await fetchImpl(GOOGLE_TOKEN_URL, {
    method: "POST", redirect: "error", signal,
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({ code, client_id: cfg.clientId, client_secret: cfg.clientSecret,
      redirect_uri: cfg.redirectUri, grant_type: "authorization_code", code_verifier: verifier }),
  });
  if (!res.ok || !res.body) problem("token_exchange");
  const reader = res.body.getReader(); const chunks = []; let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 32768) { await reader.cancel(); problem("token_response"); }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  let tokens;
  try { tokens = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { problem("token_response"); }
  if (!object(tokens) || typeof tokens.id_token !== "string") problem("token_response");
  return tokens.id_token;
}
function displayName(value, fallback) {
  return typeof value === "string" && value.trim()
    ? value.replace(/[\x00-\x1f\x7f]/g, " ").trim().slice(0, 120) : fallback;
}
function decideAccount({ email, hd, existingUser, adminEmails = [], autoApproveEmails = [], autoApproveDomains = [] }) {
  const admin = adminEmails.includes(email);
  const role = admin ? "admin" : "student";
  if (existingUser && existingUser.status === "rejected") return { status: "rejected", role: "student" };
  const policyHit = admin || autoApproveEmails.includes(email) ||
    (hd === "kenyon.edu" && autoApproveDomains.includes(hd));
  const changedEmail = existingUser && existingUser.email !== email;
  const removedAdmin = existingUser && existingUser.role === "admin" && !admin;
  if (existingUser && existingUser.status === "approved" && !changedEmail && !removedAdmin)
    return { status: "approved", role };
  return { status: policyHit ? "approved" : "pending", role };
}
function provisionGoogle(users, claims, cfg, timestamp = new Date().toISOString()) {
  const email = claims.email.toLowerCase();
  const entries = Object.entries(users);
  const matches = entries.filter(([, user]) => object(user) && user.googleSub === claims.sub);
  if (matches.length > 1) problem("account_conflict");
  const match = matches[0];
  const existing = match ? match[1] : null;
  if (existing && (existing.provider !== "google" || existing.username !== match[0] ||
      typeof existing.email !== "string" || !STATUS.has(existing.status) ||
      !["student", "admin"].includes(existing.role) ||
      ["salt", "passwordHash", "resetToken", "resetTokenExpires"].some((key) => Object.hasOwn(existing, key))))
    problem("account_conflict");
  if (entries.some(([key, user]) => object(user) && user.googleSub &&
      key !== (match && match[0]) && typeof user.email === "string" && user.email.toLowerCase() === email))
    problem("account_conflict");
  const username = existing ? existing.username : email;
  if (!existing && Object.hasOwn(users, username)) problem("account_conflict");
  const decision = decideAccount({ email, hd: claims.hd, existingUser: existing, ...cfg });
  const user = {
    ...(existing || { username, createdAt: timestamp }),
    email, googleSub: claims.sub, provider: "google",
    name: existing ? displayName(existing.name, email) : displayName(claims.name, email),
    status: decision.status, role: decision.role, lastLoginAt: timestamp,
  };
  users[username] = user;
  return { changed: true, value: { user, isNew: !existing } };
}

module.exports = {
  GOOGLE_AUTH_URL, GOOGLE_TOKEN_URL, OAUTH_COOKIE, OAUTH_COOKIE_PATH, OAUTH_TTL_SECONDS,
  OAuthError, config, equal, randomUrlSafe, pkceChallenge, parseList, safeNextPath,
  queryValue, transactionCookieFromEvent, sealTransaction, readTransaction, oauthCookie,
  response, redirect, buildAuthUrl, decodeTokenEndpointIdToken, validateIdTokenClaims,
  exchangeCode, displayName, decideAccount, provisionGoogle,
};
