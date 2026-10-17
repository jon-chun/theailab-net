import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import crypto from "node:crypto";
import hostG from "../../netlify/functions/util/google-oauth.js";

// Handler regression matrix (spec v2 §8.3, start/callback rows). The real handler, helper,
// session (auth.js) and CAS repository sources run inside one vm context whose `fetch`,
// `console` and `process.env` are stubs, so nothing reaches Google, Netlify Blobs or mail.
// All secrets and identity values below are synthetic test fixtures.

const FUNCTIONS = new URL("../../netlify/functions/", import.meta.url);
const SECRET = "test-only-session-secret-placeholder";
const CLIENT_ID = "test-client.apps.googleusercontent.com";
const CLIENT_SECRET = "test-only-client-secret-placeholder";
const CODE = "synthetic-authorization-code-fixture";
const NAME = "Fixture Person Zed";
const NOTIFY = "notify@example.org";
const HOST = "theailab.net";
const BASE_ENV = {
  GOOGLE_OAUTH_ENABLED: "true", SITE_URL: "https://theailab.net",
  GOOGLE_CLIENT_ID: CLIENT_ID, GOOGLE_CLIENT_SECRET: CLIENT_SECRET, SESSION_SECRET: SECRET,
  ADMIN_EMAILS: "prof@gmail.com", AUTO_APPROVE_EMAILS: "roster@gmail.com",
  AUTO_APPROVE_DOMAINS: "", ADMIN_NOTIFY_EMAIL: NOTIFY,
};
const cfg = hostG.config(BASE_ENV);
const CLEAR_TX = "iphs_oauth=; Path=/.netlify/functions/google-callback; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
const CLEAR_SESSION = "iphs_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
const LOG_LINE = /^google-(start|callback): [a-z_]+$/;
const now = () => Math.floor(Date.now() / 1000);

// ---------------------------------------------------------------- in-memory Blobs store
function fakeStore(initial = null, script = {}) {
  let data = initial === null ? null : structuredClone(initial);
  let version = data ? 1 : 0;
  const stats = { reads: 0, setCalls: 0, writes: 0 };
  const store = {
    stats,
    snapshot: () => (data === null ? null : structuredClone(data)),
    // A concurrent writer (e.g. an admin decision) committing between our read and our CAS.
    externalWrite(next) { data = structuredClone(next); version++; },
    async getWithMetadata(key, options) {
      assert.equal(key, "users.json");
      assert.equal(options.consistency, "strong");
      stats.reads++;
      if (script.outage) throw new Error("synthetic store outage");
      return data === null ? null : { data: structuredClone(data), etag: String(version) };
    },
    async setJSON(key, next, condition) {
      assert.equal(key, "users.json");
      stats.setCalls++;
      if (script.beforeSet) script.beforeSet(stats.setCalls, store);
      if (script.alwaysConflict) return { modified: false };
      if ((condition.onlyIfNew && data !== null) ||
          (condition.onlyIfMatch && condition.onlyIfMatch !== String(version))) return { modified: false };
      data = structuredClone(next); version++; stats.writes++;
      return { modified: true, etag: String(version) };
    },
  };
  return store;
}

// ---------------------------------------------------------------- vm harness
function harness({ env = BASE_ENV, store = fakeStore(), fetchImpl, mailImpl } = {}) {
  const logs = []; const fetchCalls = []; const mailCalls = []; const storeCalls = [];
  const spy = (...args) => logs.push(args.map(String).join(" "));
  const context = vm.createContext({
    process: { env: { ...env } },
    console: { log: spy, info: spy, warn: spy, error: spy, debug: spy },
    fetch: async (url, init) => {
      fetchCalls.push({ url: String(url), init });
      if (!fetchImpl) throw new Error("unexpected network call");
      return fetchImpl(url, init);
    },
    AbortSignal, Buffer, URL, URLSearchParams, setTimeout, clearTimeout,
  });
  const modules = {};
  const resolve = (name) => {
    if (name === "crypto" || name === "node:crypto") return crypto;
    const base = name.replace(/^\.\/(util\/)?/, "");
    if (Object.hasOwn(modules, base)) return modules[base];
    throw new Error(`unexpected require: ${name}`);
  };
  const compile = (rel, req = resolve) => {
    const source = fs.readFileSync(new URL(rel, FUNCTIONS), "utf8");
    const module = { exports: {} };
    vm.runInContext(`(function(require, module, exports) {\n${source}\n})`, context,
      { filename: rel })(req, module, module.exports);
    return module.exports;
  };
  modules["google-oauth"] = compile("util/google-oauth.js");
  modules.auth = compile("util/auth.js");
  const realStore = compile("util/users-store.js", (name) => {
    if (name === "@netlify/blobs") {
      return { connectLambda() { throw new Error("SDK not used"); }, getStore() { throw new Error("SDK not used"); } };
    }
    return resolve(name);
  });
  modules["users-store"] = {
    ...realStore,
    usersStore(event) { storeCalls.push(event); return realStore.createRepository(store); },
  };
  modules.mail = {
    async sendMail(message) {
      mailCalls.push(message);
      return mailImpl ? mailImpl(message) : { skipped: true };
    },
  };
  const start = compile("google-start.js");
  const callback = compile("google-callback.js");
  return { start, callback, g: modules["google-oauth"], auth: modules.auth, store, logs, fetchCalls, mailCalls, storeCalls };
}

// ---------------------------------------------------------------- fixtures
function makeTx(over = {}) {
  const iat = now();
  return {
    purpose: "google-login-v2", clientId: cfg.clientId, redirectUri: cfg.redirectUri,
    state: hostG.randomUrlSafe(), nonce: hostG.randomUrlSafe(), verifier: hostG.randomUrlSafe(48),
    next: "/core/syllabus.html", iat, exp: iat + hostG.OAUTH_TTL_SECONDS, ...over,
  };
}
const seal = (tx, secret = SECRET) => hostG.sealTransaction(tx, secret);
function sessionToken(payload = { sub: "prior-user", role: "student", exp: now() + 3600 }) {
  const b64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${b64}.${crypto.createHmac("sha256", SECRET).update(b64).digest("base64url")}`;
}
const PRIOR_SESSION = sessionToken();
const jwt = (claims, header = { alg: "RS256", typ: "JWT" }) =>
  `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.c3ludGhldGljLXNpZ25hdHVyZQ`;
function claimsFor(tx, over = {}) {
  const t = now();
  return {
    iss: "https://accounts.google.com", aud: CLIENT_ID, azp: CLIENT_ID,
    sub: "google-sub-fixture-001", email: "new@gmail.com", email_verified: true,
    name: NAME, nonce: tx.nonce, iat: t - 5, exp: t + 3600, ...over,
  };
}
const tokenResponse = (idToken, status = 200) =>
  new Response(JSON.stringify({ id_token: idToken, access_token: "synthetic-access-token-fixture" }),
    { status, headers: { "content-type": "application/json" } });

function event({ method = "GET", host = HOST, query, rawQuery, cookie, multi } = {}) {
  const headers = { host };
  if (cookie !== undefined) headers.cookie = cookie;
  const ev = { httpMethod: method, headers };
  if (multi) {
    ev.multiValueQueryStringParameters = multi;
    ev.queryStringParameters = Object.fromEntries(Object.entries(multi).map(([k, v]) => [k, v.at(-1)]));
    return ev;
  }
  const raw = rawQuery ?? new URLSearchParams(query || {}).toString();
  ev.rawQuery = raw;
  ev.queryStringParameters = Object.fromEntries(new URLSearchParams(raw));
  return ev;
}
const cookieHeader = (tx, { session = PRIOR_SESSION, sealed } = {}) =>
  [session ? `iphs_session=${session}` : null, `iphs_oauth=${sealed ?? seal(tx)}`].filter(Boolean).join("; ");

// Copy into a host-realm array: arrays built inside the vm have another Array.prototype.
const setCookies = (res) => [...((res.multiValueHeaders && res.multiValueHeaders["Set-Cookie"]) || [])];
const sessionSetCookies = (res) => setCookies(res).filter((c) => c.startsWith("iphs_session="));
const cookieValue = (setCookie) => setCookie.slice(setCookie.indexOf("=") + 1, setCookie.indexOf(";"));

function assertOAuthHeaders(res) {
  assert.equal(res.headers["Cache-Control"], "no-store");
  assert.equal(res.headers["Referrer-Policy"], "no-referrer");
}
function assertCleanLogs(h, forbidden = []) {
  for (const line of h.logs) {
    assert.match(line, LOG_LINE, "only fixed reason strings may be logged");
    for (const secret of [CODE, NAME, CLIENT_SECRET, SECRET, PRIOR_SESSION, "synthetic-access-token-fixture", ...forbidden]) {
      assert.equal(line.includes(secret), false, "log line leaked a fixture value");
    }
  }
}
// Every terminal failure path: fixed error redirect, transaction cleared, pre-existing
// session neither reissued nor cleared, no Google exchange and no store access.
function assertFailClosed(h, res, marker = "google", { exchanged = false } = {}) {
  assertOAuthHeaders(res);
  assert.equal(res.statusCode, 302);
  assert.equal(res.headers.Location, `/login.html?error=${marker}`);
  assert.deepEqual(setCookies(res), [CLEAR_TX]);
  assert.equal(sessionSetCookies(res).length, 0);
  if (!exchanged) assert.equal(h.fetchCalls.length, 0);
  assert.equal(h.storeCalls.length, 0);
  assert.equal(h.store.stats.setCalls, 0);
}

// Run one complete, valid-state callback with the given Google identity and store.
async function login({ claims = {}, users = null, store, env, mailImpl, tx = makeTx(), idToken, session = PRIOR_SESSION, fetchImpl } = {}) {
  const s = store || fakeStore(users);
  const token = idToken ?? jwt(claimsFor(tx, claims));
  const h = harness({ env, store: s, mailImpl, fetchImpl: fetchImpl || (async () => tokenResponse(token)) });
  const res = await h.callback.handler(event({
    query: { state: tx.state, code: CODE }, cookie: cookieHeader(tx, { session }),
  }));
  assertOAuthHeaders(res);
  return { h, res, tx, store: s, token };
}
function assertApproved({ h, res, tx }, username, role) {
  assert.equal(res.statusCode, 302);
  assert.equal(res.headers.Location, tx.next);
  const cookies = setCookies(res);
  assert.equal(cookies.length, 2);
  assert.equal(cookies[1], CLEAR_TX);
  assert.match(cookies[0], /^iphs_session=[^;]+; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=\d+$/);
  const payload = h.auth.verify(cookieValue(cookies[0]));
  assert.equal(payload.sub, username);
  assert.equal(payload.role, role);
}
function assertNoSessionMinted(res) {
  assert.equal(setCookies(res).some((c) => /^iphs_session=[^;]/.test(c)), false, "no session may be minted");
}
const googleRecord = (email, over = {}) => ({
  username: email, name: "Stored Name", email, googleSub: `sub-of-${email}`, provider: "google",
  status: "approved", role: "student", createdAt: "2026-10-01T00:00:00.000Z",
  lastLoginAt: "2026-10-01T00:00:00.000Z", ...over,
});
const PASSWORD_FIELDS = ["salt", "passwordHash", "resetToken", "resetTokenExpires"];

// ================================================================ method gate
for (const method of ["POST", "PUT"]) {
  test(`${method} to start and callback: 405 Allow GET, no token or store action`, async () => {
    const h = harness();
    const tx = makeTx();
    for (const fn of [h.start, h.callback]) {
      const res = await fn.handler(event({ method, query: { state: tx.state, code: CODE, next: "/" }, cookie: cookieHeader(tx) }));
      assert.equal(res.statusCode, 405);
      assert.equal(res.headers.Allow, "GET");
      assertOAuthHeaders(res);
      assert.equal(setCookies(res).length, 0);
    }
    assert.equal(h.fetchCalls.length, 0);
    assert.equal(h.storeCalls.length, 0);
    assert.equal(h.mailCalls.length, 0);
  });
}

// ================================================================ configuration
const BAD_CONFIGS = {
  "disabled flag": { GOOGLE_OAUTH_ENABLED: "false" },
  "missing enable flag": { GOOGLE_OAUTH_ENABLED: undefined },
  "missing client secret": { GOOGLE_CLIENT_SECRET: undefined },
  "missing session secret": { SESSION_SECRET: undefined },
  "malformed client id": { GOOGLE_CLIENT_ID: "not-a-google-client" },
  "malformed site url": { SITE_URL: "https://evil.example" },
  "malformed admin list": { ADMIN_EMAILS: "someone@other.example" },
};
for (const [label, patch] of Object.entries(BAD_CONFIGS)) {
  test(`config ${label}: start 503 without cookie; callback 503, never exchanges or writes`, async () => {
    const env = { ...BASE_ENV, ...patch };
    for (const key of Object.keys(patch)) if (patch[key] === undefined) delete env[key];
    const h = harness({ env, store: fakeStore({}), fetchImpl: async () => tokenResponse(jwt({})) });
    const s = await h.start.handler(event({ query: { next: "/core/syllabus.html" } }));
    assert.equal(s.statusCode, 503);
    assertOAuthHeaders(s);
    assert.equal(setCookies(s).length, 0);
    const tx = makeTx();
    const c = await h.callback.handler(event({ query: { state: tx.state, code: CODE }, cookie: cookieHeader(tx) }));
    assert.equal(c.statusCode, 503);
    assertOAuthHeaders(c);
    assert.deepEqual(setCookies(c), [CLEAR_TX]);
    assert.equal(h.fetchCalls.length, 0);
    assert.equal(h.storeCalls.length, 0);
    assert.equal(h.store.stats.reads + h.store.stats.setCalls, 0);
    assertCleanLogs(h);
  });
}

// ================================================================ start
test("start on canonical host: only the transaction cookie and a Google 302 with state, nonce and PKCE", async () => {
  const h = harness();
  const res = await h.start.handler(event({ query: { next: "/core/syllabus.html" }, cookie: `iphs_session=${PRIOR_SESSION}` }));
  assertOAuthHeaders(res);
  assert.equal(res.statusCode, 302);
  const cookies = setCookies(res);
  assert.equal(cookies.length, 1, "start sets exactly one cookie");
  assert.match(cookies[0], /^iphs_oauth=[A-Za-z0-9_.-]+; Path=\/\.netlify\/functions\/google-callback; HttpOnly; Secure; SameSite=Lax; Max-Age=600$/);
  assert.equal(cookies[0].includes("Domain="), false, "host-only cookie");
  const st = hostG.readTransaction(cookieValue(cookies[0]), cfg);
  assert.ok(st, "cookie holds a valid sealed transaction");
  assert.equal(st.next, "/core/syllabus.html");
  const url = new URL(res.headers.Location);
  assert.equal(url.origin + url.pathname, hostG.GOOGLE_AUTH_URL);
  assert.equal(url.searchParams.get("client_id"), CLIENT_ID);
  assert.equal(url.searchParams.get("redirect_uri"), "https://theailab.net/.netlify/functions/google-callback");
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("state"), st.state);
  assert.equal(url.searchParams.get("nonce"), st.nonce);
  assert.equal(url.searchParams.get("code_challenge"), hostG.pkceChallenge(st.verifier));
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.has("code_verifier"), false, "verifier never leaves in the URL");
  assert.equal(res.headers.Location.includes(st.verifier), false);
  assert.equal(h.storeCalls.length, 0, "start never touches users");
  assert.equal(h.fetchCalls.length, 0);
  assert.equal(h.logs.length, 0);
  // Two starts produce independent random material.
  const again = await h.start.handler(event({ query: { next: "/" } }));
  const st2 = hostG.readTransaction(cookieValue(setCookies(again)[0]), cfg);
  assert.notEqual(st2.state, st.state);
  assert.notEqual(st2.verifier, st.verifier);
});

test("start sanitizes next and rejects duplicate next with 400 and no cookie", async () => {
  const h = harness();
  const res = await h.start.handler(event({ query: { next: "https://evil.example/" } }));
  assert.equal(hostG.readTransaction(cookieValue(setCookies(res)[0]), cfg).next, "/index.html");
  const dup = await h.start.handler(event({ rawQuery: "next=%2F&next=%2Fcore%2Fsyllabus.html" }));
  assert.equal(dup.statusCode, 400);
  assertOAuthHeaders(dup);
  assert.equal(setCookies(dup).length, 0);
  assert.equal(h.storeCalls.length, 0);
});

test("start on an alias host redirects to the configured login page with no cookie", async () => {
  const h = harness();
  const res = await h.start.handler(event({ host: "www.theailab.net", query: { next: "/core/syllabus.html" } }));
  assertOAuthHeaders(res);
  assert.equal(res.statusCode, 302);
  assert.equal(res.headers.Location, "https://theailab.net/login.html?next=%2Fcore%2Fsyllabus.html");
  assert.equal(setCookies(res).length, 0);
  assert.equal(h.storeCalls.length, 0);
});

// ================================================================ callback: transaction / query failures
const tx0 = makeTx();
const FAILURES = {
  "missing transaction cookie": () => ({ query: { state: tx0.state, code: CODE }, cookie: `iphs_session=${PRIOR_SESSION}` }),
  "expired transaction": () => {
    const iat = now() - 700; const tx = makeTx({ iat, exp: iat + 600 });
    return { query: { state: tx.state, code: CODE }, cookie: cookieHeader(tx) };
  },
  "tampered transaction signature": () => {
    const sealed = seal(tx0); const flipped = sealed.slice(0, -2) + (sealed.at(-2) === "A" ? "B" : "A") + sealed.at(-1);
    return { query: { state: tx0.state, code: CODE }, cookie: cookieHeader(tx0, { sealed: flipped }) };
  },
  "transaction sealed with another secret": () => ({ query: { state: tx0.state, code: CODE }, cookie: cookieHeader(tx0, { sealed: seal(tx0, "other-test-secret") }) }),
  "malformed transaction": () => ({ query: { state: tx0.state, code: CODE }, cookie: cookieHeader(tx0, { sealed: "not.a-valid.token!" }) }),
  "transaction bound to another redirect uri": () => {
    const tx = makeTx({ redirectUri: "http://localhost:8888/.netlify/functions/google-callback" });
    return { query: { state: tx.state, code: CODE }, cookie: cookieHeader(tx) };
  },
  "two transaction cookies": () => ({ query: { state: tx0.state, code: CODE }, cookie: `${cookieHeader(tx0)}; iphs_oauth=${seal(tx0)}` }),
  "mismatched state": () => ({ query: { state: hostG.randomUrlSafe(), code: CODE }, cookie: cookieHeader(tx0) }),
  "missing state": () => ({ query: { code: CODE }, cookie: cookieHeader(tx0) }),
  "duplicate state (rawQuery)": () => ({ rawQuery: `state=${tx0.state}&state=${tx0.state}&code=${CODE}`, cookie: cookieHeader(tx0) }),
  "duplicate state (multiValue)": () => ({ multi: { state: [tx0.state, tx0.state], code: [CODE] }, cookie: cookieHeader(tx0) }),
  "duplicate code": () => ({ rawQuery: `state=${tx0.state}&code=${CODE}&code=${CODE}`, cookie: cookieHeader(tx0) }),
  "duplicate error": () => ({ rawQuery: `state=${tx0.state}&error=access_denied&error=access_denied`, cookie: cookieHeader(tx0) }),
  "missing code": () => ({ query: { state: tx0.state }, cookie: cookieHeader(tx0) }),
  "code together with error": () => ({ query: { state: tx0.state, code: CODE, error: "access_denied" }, cookie: cookieHeader(tx0) }),
  "callback on alias host": () => ({ host: "www.theailab.net", query: { state: tx0.state, code: CODE }, cookie: cookieHeader(tx0) }),
  "session token substituted as transaction": () => ({ query: { state: tx0.state, code: CODE }, cookie: cookieHeader(tx0, { sealed: PRIOR_SESSION }) }),
};
for (const [label, build] of Object.entries(FAILURES)) {
  test(`callback ${label}: fixed error redirect, transaction cleared, no exchange/write, prior session untouched`, async () => {
    const h = harness({ store: fakeStore({}), fetchImpl: async () => tokenResponse(jwt(claimsFor(tx0))) });
    const res = await h.callback.handler(event(build()));
    assertFailClosed(h, res);
    assertCleanLogs(h, [tx0.state, tx0.verifier, seal(tx0)]);
    assert.equal(h.logs.length, 1);
  });
}

test("valid state plus error=access_denied: cancellation redirect, no exchange or write", async () => {
  const tx = makeTx();
  const h = harness({ store: fakeStore({}) });
  const res = await h.callback.handler(event({ query: { state: tx.state, error: "access_denied" }, cookie: cookieHeader(tx) }));
  assertOAuthHeaders(res);
  assert.equal(res.statusCode, 302);
  assert.equal(res.headers.Location, "/login.html?cancelled=1");
  assert.deepEqual(setCookies(res), [CLEAR_TX]);
  assert.equal(h.fetchCalls.length, 0);
  assert.equal(h.storeCalls.length, 0);
});

test("provider error without a valid state fails as state and never logs provider text", async () => {
  const providerText = "synthetic_provider_text_marker";
  for (const ev of [
    { query: { state: hostG.randomUrlSafe(), error: providerText } },
    { query: { state: tx0.state, error: "access_denied" } }, // no transaction cookie
    { query: { state: hostG.randomUrlSafe(), error: "access_denied" }, cookie: cookieHeader(tx0) },
  ]) {
    const h = harness();
    const res = await h.callback.handler(event(ev));
    assertFailClosed(h, res);
    assert.deepEqual(h.logs, ["google-callback: state"]);
  }
  // With a valid state, a non-cancellation provider error is a fixed generic failure.
  const tx = makeTx();
  const h = harness();
  const res = await h.callback.handler(event({ query: { state: tx.state, error: providerText }, cookie: cookieHeader(tx) }));
  assertFailClosed(h, res);
  assert.deepEqual(h.logs, ["google-callback: provider"]);
  assertCleanLogs(h, [providerText]);
});

// ================================================================ callback: token exchange / claims failures
test("token exchange posts code, verifier and exact redirect to the fixed endpoint without following redirects", async () => {
  const r = await login({ claims: { email: "roster@gmail.com" } });
  assert.equal(r.h.fetchCalls.length, 1);
  const { url, init } = r.h.fetchCalls[0];
  assert.equal(url, hostG.GOOGLE_TOKEN_URL);
  assert.equal(init.method, "POST");
  assert.equal(init.redirect, "error");
  assert.ok(init.signal, "bounded by a timeout signal");
  const body = new URLSearchParams(init.body);
  assert.equal(body.get("code"), CODE);
  assert.equal(body.get("code_verifier"), r.tx.verifier);
  assert.equal(body.get("redirect_uri"), cfg.redirectUri);
  assert.equal(body.get("client_id"), CLIENT_ID);
  assert.equal(body.get("grant_type"), "authorization_code");
  assert.equal(body.get("client_secret") === CLIENT_SECRET, true);
});

const EXCHANGE_FAILURES = {
  timeout: { fetchImpl: async () => { throw new DOMException("The operation was aborted due to timeout", "TimeoutError"); }, marker: "google", log: "unavailable" },
  "non-2xx": { fetchImpl: async (u, init, tok) => tokenResponse(tok, 400), marker: "google", log: "unavailable" },
  "redirect refused": {
    fetchImpl: async (u, init) => { assert.equal(init.redirect, "error"); throw new TypeError("fetch failed"); },
    marker: "google", log: "unavailable",
  },
  "oversize response": {
    fetchImpl: async (u, init, tok) => new Response(JSON.stringify({ id_token: tok, pad: "x".repeat(40000) }), { status: 200 }),
    marker: "google", log: "unavailable",
  },
  "non-JSON response": { fetchImpl: async () => new Response("<html>synthetic</html>", { status: 200 }), marker: "google", log: "unavailable" },
  "missing id_token": { fetchImpl: async () => new Response(JSON.stringify({ access_token: "synthetic-access-token-fixture" }), { status: 200 }), marker: "google", log: "unavailable" },
  "unsigned alg=none token": { token: (tx) => jwt(claimsFor(tx), { alg: "none" }), marker: "google", log: "claims" },
  "wrong nonce": { claims: { nonce: hostG.randomUrlSafe() }, marker: "google", log: "claims" },
  "wrong audience": { claims: { aud: "other.apps.googleusercontent.com" }, marker: "google", log: "claims" },
  "multi-audience": { claims: { aud: [CLIENT_ID, "other.apps.googleusercontent.com"] }, marker: "google", log: "claims" },
  "unverified email": { claims: { email_verified: false }, marker: "google", log: "claims" },
  "expired token": { claims: { iat: now() - 7200, exp: now() - 3600 }, marker: "google", log: "claims" },
  "unsupported email domain": { claims: { email: "someone@yahoo.com" }, marker: "account", log: "account" },
  "kenyon email without hd": { claims: { email: "student@kenyon.edu" }, marker: "account", log: "account" },
};
for (const [label, spec] of Object.entries(EXCHANGE_FAILURES)) {
  test(`token/claims failure (${label}): no persistence, no session, fixed log reason only`, async () => {
    const tx = makeTx();
    const token = spec.token ? spec.token(tx) : jwt(claimsFor(tx, spec.claims || {}));
    const fetchImpl = spec.fetchImpl ? (u, init) => spec.fetchImpl(u, init, token) : async () => tokenResponse(token);
    const r = await login({ tx, users: {}, idToken: token, fetchImpl });
    assertFailClosed(r.h, r.res, spec.marker, { exchanged: true });
    assert.equal(r.h.fetchCalls.length, 1);
    assert.deepEqual(r.h.logs, [`google-callback: ${spec.log}`]);
    assertCleanLogs(r.h, [token, tx.verifier, tx.nonce, "new@gmail.com", "someone@yahoo.com", "student@kenyon.edu"]);
    assert.deepEqual(r.store.snapshot(), {});
  });
}

// ================================================================ callback: account policy outcomes
test("new roster account: approved student record saved, session minted, redirect to next", async () => {
  const r = await login({ users: {}, claims: { email: "Roster@Gmail.com", sub: "sub-roster" } });
  assertApproved(r, "roster@gmail.com", "student");
  const rec = r.store.snapshot()["roster@gmail.com"];
  assert.equal(rec.username, "roster@gmail.com");
  assert.equal(rec.email, "roster@gmail.com");
  assert.equal(rec.googleSub, "sub-roster");
  assert.equal(rec.provider, "google");
  assert.equal(rec.status, "approved");
  assert.equal(rec.role, "student");
  assert.equal(rec.name, NAME);
  for (const key of PASSWORD_FIELDS) assert.equal(Object.hasOwn(rec, key), false);
  assert.equal(r.h.mailCalls.length, 0);
  assert.equal(r.h.logs.length, 0);
});

test("new admin account: approved admin record and admin session", async () => {
  const r = await login({ users: {}, claims: { email: "prof@gmail.com", sub: "sub-prof" } });
  assertApproved(r, "prof@gmail.com", "admin");
  assert.equal(r.store.snapshot()["prof@gmail.com"].role, "admin");
  assert.equal(r.h.mailCalls.length, 0);
});

test("existing approved Google account stays approved after leaving the roster; session minted", async () => {
  const users = { "former@gmail.com": googleRecord("former@gmail.com") };
  const r = await login({ users, claims: { email: "former@gmail.com", sub: "sub-of-former@gmail.com" } });
  assertApproved(r, "former@gmail.com", "student");
  const rec = r.store.snapshot()["former@gmail.com"];
  assert.equal(rec.status, "approved");
  assert.equal(rec.createdAt, "2026-10-01T00:00:00.000Z");
  assert.notEqual(rec.lastLoginAt, "2026-10-01T00:00:00.000Z");
  assert.equal(rec.name, "Stored Name", "stored name is kept");
});

test("new non-policy account: pending record, no session, transaction and old session cleared, one notification", async () => {
  const r = await login({ users: {}, claims: { email: "new@gmail.com" } });
  assert.equal(r.res.statusCode, 302);
  assert.equal(r.res.headers.Location, "/login.html?pending=1");
  assert.deepEqual(setCookies(r.res), [CLEAR_TX, CLEAR_SESSION]);
  assertNoSessionMinted(r.res);
  const rec = r.store.snapshot()["new@gmail.com"];
  assert.equal(rec.status, "pending");
  assert.equal(rec.role, "student");
  assert.equal(r.h.mailCalls.length, 1);
  assert.equal(r.h.mailCalls[0].to, NOTIFY);
  assert.equal(r.h.mailCalls[0].subject, "Course account pending approval");
  assert.equal(typeof r.h.mailCalls[0].text, "string");
  assert.equal(r.h.mailCalls[0].html, undefined, "plain text only");
  assert.equal(r.h.logs.length, 0);
});

test("existing pending account: stays pending, clears old session, does not resend the notification", async () => {
  const users = { "new@gmail.com": googleRecord("new@gmail.com", { status: "pending", googleSub: "google-sub-fixture-001" }) };
  const r = await login({ users });
  assert.equal(r.res.headers.Location, "/login.html?pending=1");
  assert.deepEqual(setCookies(r.res), [CLEAR_TX, CLEAR_SESSION]);
  assert.equal(r.store.snapshot()["new@gmail.com"].status, "pending");
  assert.equal(r.h.mailCalls.length, 0);
});

test("existing rejected account stays rejected even on the admin list; no session, old session cleared", async () => {
  const users = { "prof@gmail.com": googleRecord("prof@gmail.com", { status: "rejected", googleSub: "sub-prof" }) };
  const r = await login({ users, claims: { email: "prof@gmail.com", sub: "sub-prof" } });
  assert.equal(r.res.headers.Location, "/login.html?rejected=1");
  assert.deepEqual(setCookies(r.res), [CLEAR_TX, CLEAR_SESSION]);
  assertNoSessionMinted(r.res);
  const rec = r.store.snapshot()["prof@gmail.com"];
  assert.equal(rec.status, "rejected");
  assert.equal(rec.role, "student");
  assert.equal(r.h.mailCalls.length, 0);
});

test("password record whose .email equals the admin's Google email is untouched; a separate Google record is created", async () => {
  const passwordRecord = {
    username: "profpw", email: "prof@gmail.com", salt: "00ff", passwordHash: "abcdef0123",
    role: "student", status: "approved", createdAt: "2026-09-01T00:00:00.000Z",
    resetToken: "synthetic-reset-fixture", resetTokenExpires: 1,
  };
  const r = await login({ users: { profpw: passwordRecord }, claims: { email: "prof@gmail.com", sub: "sub-prof" } });
  assertApproved(r, "prof@gmail.com", "admin");
  const after = r.store.snapshot();
  assert.deepEqual(after.profpw, passwordRecord);
  const rec = after["prof@gmail.com"];
  assert.equal(rec.provider, "google");
  assert.equal(rec.role, "admin");
  for (const key of PASSWORD_FIELDS) assert.equal(Object.hasOwn(rec, key), false);
});

// ================================================================ callback: account conflicts
const CONFLICTS = {
  "duplicate Google subject": {
    a: googleRecord("a@gmail.com", { googleSub: "google-sub-fixture-001" }),
    b: googleRecord("b@gmail.com", { googleSub: "google-sub-fixture-001" }),
  },
  "occupied username key": {
    "new@gmail.com": { username: "new@gmail.com", email: "new@gmail.com", salt: "00", passwordHash: "11", role: "student", status: "approved" },
  },
  "mixed-credential Google record": {
    "new@gmail.com": googleRecord("new@gmail.com", { googleSub: "google-sub-fixture-001", passwordHash: "11", salt: "00" }),
  },
  "different Google subject sharing the email": {
    "other-key": googleRecord("new@gmail.com", { username: "other-key", googleSub: "different-sub" }),
  },
};
for (const [label, users] of Object.entries(CONFLICTS)) {
  test(`account conflict (${label}): generic conflict, no mutation, no mint`, async () => {
    const r = await login({ users, claims: { email: "new@gmail.com", sub: "google-sub-fixture-001" } });
    assert.equal(r.res.statusCode, 302);
    assert.equal(r.res.headers.Location, "/login.html?error=account-conflict");
    assert.deepEqual(setCookies(r.res), [CLEAR_TX]);
    assert.equal(r.store.stats.setCalls, 0);
    assert.deepEqual(r.store.snapshot(), users);
    assert.deepEqual(r.h.logs, ["google-callback: conflict"]);
    assert.equal(r.h.mailCalls.length, 0);
  });
}

// ================================================================ callback: store failures and races
test("store outage: generic error, no session minted, prior session untouched", async () => {
  const r = await login({ store: fakeStore({}, { outage: true }), claims: { email: "roster@gmail.com" } });
  assert.equal(r.res.headers.Location, "/login.html?error=google");
  assert.deepEqual(setCookies(r.res), [CLEAR_TX]);
  assert.deepEqual(r.h.logs, ["google-callback: unavailable"]);
  assert.equal(r.h.mailCalls.length, 0);
});

test("CAS retry exhaustion: generic error, no write, no session, no notification", async () => {
  const r = await login({ store: fakeStore({}, { alwaysConflict: true }), claims: { email: "roster@gmail.com" } });
  assert.equal(r.res.headers.Location, "/login.html?error=google");
  assert.deepEqual(setCookies(r.res), [CLEAR_TX]);
  assert.equal(r.store.stats.setCalls, 5);
  assert.equal(r.store.stats.writes, 0);
  assert.deepEqual(r.store.snapshot(), {});
  assert.equal(r.h.mailCalls.length, 0);
});

test("rejection committed before a successful CAS wins: rejected outcome, no approved mint from the stale snapshot", async () => {
  const users = { "roster@gmail.com": googleRecord("roster@gmail.com", { googleSub: "sub-roster" }) };
  const store = fakeStore(users, {
    beforeSet(attempt, s) {
      if (attempt !== 1) return;
      const data = s.snapshot();
      data["roster@gmail.com"].status = "rejected";
      s.externalWrite(data);
    },
  });
  const r = await login({ store, claims: { email: "roster@gmail.com", sub: "sub-roster" } });
  assert.equal(r.store.stats.setCalls, 2);
  assert.equal(r.res.headers.Location, "/login.html?rejected=1");
  assert.deepEqual(setCookies(r.res), [CLEAR_TX, CLEAR_SESSION]);
  assertNoSessionMinted(r.res);
  assert.equal(r.store.snapshot()["roster@gmail.com"].status, "rejected");
});

// ================================================================ callback: pending notification
test("pending notification after a CAS retry is sent once, after the commit, and the concurrent write is kept", async () => {
  const store = fakeStore({}, {
    beforeSet(attempt, s) {
      if (attempt === 1) s.externalWrite({ ...s.snapshot(), "someone@gmail.com": googleRecord("someone@gmail.com") });
    },
  });
  const r = await login({ store, claims: { email: "new@gmail.com" } });
  assert.equal(r.store.stats.setCalls, 2);
  assert.equal(r.res.headers.Location, "/login.html?pending=1");
  assert.equal(r.h.mailCalls.length, 1);
  const after = r.store.snapshot();
  assert.equal(after["new@gmail.com"].status, "pending");
  assert.ok(after["someone@gmail.com"]);
});

test("pending with no notify address configured: record persisted, no mail, no session", async () => {
  const env = { ...BASE_ENV }; delete env.ADMIN_NOTIFY_EMAIL;
  const r = await login({ env, users: {}, claims: { email: "new@gmail.com" } });
  assert.equal(r.res.headers.Location, "/login.html?pending=1");
  assertNoSessionMinted(r.res);
  assert.equal(r.store.snapshot()["new@gmail.com"].status, "pending");
  assert.equal(r.h.mailCalls.length, 0);
});

test("pending when mail reports failure or is unconfigured: record persisted, no session, attempted once", async () => {
  for (const mailImpl of [() => ({ skipped: true }), () => ({ skipped: false, ok: false, status: 500 })]) {
    const r = await login({ users: {}, mailImpl, claims: { email: "new@gmail.com" } });
    assert.equal(r.res.headers.Location, "/login.html?pending=1");
    assert.deepEqual(setCookies(r.res), [CLEAR_TX, CLEAR_SESSION]);
    assert.equal(r.store.snapshot()["new@gmail.com"].status, "pending");
    assert.equal(r.h.mailCalls.length, 1);
  }
});

test("pending when mail throws: record persisted, no session, one attempt; a later pending login does not resend", async () => {
  const store = fakeStore({});
  const r = await login({ store, mailImpl: () => { throw new Error("synthetic mail failure"); }, claims: { email: "new@gmail.com" } });
  assertNoSessionMinted(r.res);
  assert.equal(r.res.statusCode, 302);
  assert.equal(r.store.snapshot()["new@gmail.com"].status, "pending");
  assert.equal(r.h.mailCalls.length, 1);
  assertCleanLogs(r.h, ["new@gmail.com", "synthetic mail failure"]);
  const again = await login({ store, claims: { email: "new@gmail.com" } });
  assert.equal(again.res.headers.Location, "/login.html?pending=1");
  assert.equal(again.h.mailCalls.length, 0);
  assert.equal(Object.keys(again.store.snapshot()).length, 1);
});

// ================================================================ token substitution
test("session/transaction token substitution fails in both directions with the real readers", async () => {
  const r = await login({ users: {}, claims: { email: "roster@gmail.com" } });
  const mintedSession = cookieValue(setCookies(r.res)[0]);
  const tx = makeTx(); const sealed = seal(tx);
  // Real auth.verify() on the OAuth transaction token.
  assert.equal(r.h.auth.verify(sealed), null);
  assert.equal(r.h.auth.getSessionFromEvent({ headers: { cookie: `iphs_session=${sealed}` } }), null);
  // Real OAuth reader on a real session token (and on the session-shaped fixture).
  assert.ok(r.h.auth.verify(mintedSession), "control: the minted session is valid for auth.verify");
  assert.equal(r.h.g.readTransaction(mintedSession, cfg), null);
  assert.equal(r.h.g.readTransaction(PRIOR_SESSION, cfg), null);
  assert.ok(r.h.g.readTransaction(sealed, cfg), "control: the sealed transaction is valid for its own reader");
  // A transaction payload signed with the session key/format is not a transaction either.
  const b64 = Buffer.from(JSON.stringify(tx)).toString("base64url");
  const sessionSigned = `oauth2.${b64}.${crypto.createHmac("sha256", SECRET).update(`oauth2.${b64}`).digest("base64url")}`;
  assert.equal(r.h.g.readTransaction(sessionSigned, cfg), null);
});
