import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import g from "../../netlify/functions/util/google-oauth.js";

const NOW = 1_800_000_000;
const ENV = {
  GOOGLE_OAUTH_ENABLED: "true", SITE_URL: "https://theailab.net",
  GOOGLE_CLIENT_ID: "test-client.apps.googleusercontent.com",
  GOOGLE_CLIENT_SECRET: "test-only-placeholder", SESSION_SECRET: "test-only-placeholder-secret",
  ADMIN_EMAILS: "prof@gmail.com", AUTO_APPROVE_EMAILS: "roster@gmail.com",
  AUTO_APPROVE_DOMAINS: "kenyon.edu",
};
const cfg = g.config(ENV);
const good = () => ({
  iss: "https://accounts.google.com", aud: cfg.clientId, azp: cfg.clientId,
  sub: "subject-placeholder", email: "student@kenyon.edu", email_verified: true,
  hd: "kenyon.edu", nonce: "nonce-placeholder", iat: NOW - 10, exp: NOW + 3600,
});
const validate = (claims) => g.validateIdTokenClaims(claims, { clientId: cfg.clientId, nonce: "nonce-placeholder", now: NOW });
const transaction = () => ({
  purpose: "google-login-v2", clientId: cfg.clientId, redirectUri: cfg.redirectUri,
  state: g.randomUrlSafe(), nonce: g.randomUrlSafe(), verifier: g.randomUrlSafe(48),
  next: "/core/syllabus.html", iat: NOW, exp: NOW + g.OAUTH_TTL_SECONDS,
});
const jwt = (claims, header = { alg: "RS256" }) =>
  `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.synthetic`;
const signLikeSession = (payload) => {
  const b64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${b64}.${crypto.createHmac("sha256", cfg.sessionSecret).update(b64).digest("base64url")}`;
};

test("PKCE matches RFC 7636 Appendix B", () => {
  assert.equal(g.pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
});
test("random material and authorization parameters", () => {
  assert.match(g.randomUrlSafe(), /^[A-Za-z0-9_-]{43}$/);
  assert.match(g.randomUrlSafe(48), /^[A-Za-z0-9_-]{64}$/);
  const u = new URL(g.buildAuthUrl({ ...cfg, state: "state", nonce: "nonce", codeChallenge: "challenge" }));
  assert.equal(u.origin + u.pathname, g.GOOGLE_AUTH_URL);
  for (const [key, value] of Object.entries({ client_id: cfg.clientId, redirect_uri: cfg.redirectUri,
    response_type: "code", scope: "openid email profile", state: "state", nonce: "nonce",
    code_challenge: "challenge", code_challenge_method: "S256", prompt: "select_account" }))
    assert.equal(u.searchParams.get(key), value);
  assert.equal(u.searchParams.has("access_type"), false);
  assert.equal(u.searchParams.has("hd"), false);
});
test("configuration validates origin, explicit enable flag and policy lists", () => {
  assert.equal(cfg.redirectUri, "https://theailab.net/.netlify/functions/google-callback");
  assert.equal(g.config({ ...ENV, SITE_URL: "http://localhost:8888" }).siteUrl, "http://localhost:8888");
  for (const patch of [
    { GOOGLE_OAUTH_ENABLED: "false" }, { GOOGLE_OAUTH_ENABLED: undefined },
    { SESSION_SECRET: "" }, { GOOGLE_CLIENT_SECRET: "" }, { GOOGLE_CLIENT_ID: "invalid" },
    { SITE_URL: "https://theailab.net/" }, { SITE_URL: "https://evil.example" },
    { SITE_URL: "https://theailab.net?x=1" }, { AUTO_APPROVE_DOMAINS: "gmail.com" },
    { ADMIN_EMAILS: "student@other.example" }, { ADMIN_NOTIFY_EMAIL: "x\r\n@example.com" },
  ]) assert.throws(() => g.config({ ...ENV, ...patch }), g.OAuthError);
  assert.deepEqual(g.parseList(" A@GMAIL.COM, ,a@gmail.com,b@kenyon.edu "), ["a@gmail.com", "b@kenyon.edu"]);
});
test("transactions have separate key/format and exact expiry", () => {
  const st = transaction();
  const token = g.sealTransaction(st, cfg.sessionSecret);
  assert.deepEqual(g.readTransaction(token, cfg, NOW), st);
  assert.equal(g.readTransaction(token, cfg, st.exp), null);
  assert.equal(g.readTransaction(`${token}x`, cfg, NOW), null);
  assert.equal(g.readTransaction(signLikeSession(st), cfg, NOW), null);
  const [prefix, payload, signature] = token.split(".");
  assert.equal(prefix, "oauth2");
  assert.notEqual(signature, crypto.createHmac("sha256", cfg.sessionSecret).update(payload).digest("base64url"));
  assert.notEqual(payload, crypto.createHmac("sha256", cfg.sessionSecret).update(prefix).digest("base64url"));
  const wrongKeySig = crypto.createHmac("sha256", cfg.sessionSecret).update(`oauth2.${payload}`).digest("base64url");
  assert.equal(g.readTransaction(`oauth2.${payload}.${wrongKeySig}`, cfg, NOW), null);
  assert.equal(g.readTransaction(token, { ...cfg, clientId: "changed" }, NOW), null);
  assert.equal(g.readTransaction(token, { ...cfg, redirectUri: "https://theailab.net/changed" }, NOW), null);
});
for (const [name, patch] of [
  ["missing purpose", { purpose: undefined }], ["missing expiry", { exp: undefined }],
  ["incorrect lifetime", { exp: NOW + 9999 }], ["future issue", { iat: NOW + 1000, exp: NOW + 1600 }],
  ["short state", { state: "short" }], ["missing nonce", { nonce: undefined }],
  ["short verifier", { verifier: "short" }], ["offsite next", { next: "//evil.example" }],
]) test(`signed malformed transaction: ${name}`, () => {
  assert.equal(g.readTransaction(g.sealTransaction({ ...transaction(), ...patch }, cfg.sessionSecret), cfg, NOW), null);
});
test("cookie attributes and legacy multi-cookie response", () => {
  const cookie = g.oauthCookie("oauth2.payload.signature", 600);
  for (const text of ["Path=/.netlify/functions/google-callback", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age=600"])
    assert.ok(cookie.includes(text));
  assert.equal(cookie.includes("Domain="), false);
  assert.ok(g.oauthCookie("", 0).includes("Max-Age=0"));
  assert.throws(() => g.oauthCookie("x; injected=yes", 600));
  const response = g.redirect("/index.html", ["session=placeholder", g.oauthCookie("", 0)]);
  assert.equal(response.statusCode, 302);
  assert.equal(response.body, "");
  assert.equal(response.headers["Cache-Control"], "no-store");
  assert.equal(response.headers["Referrer-Policy"], "no-referrer");
  assert.equal(response.headers["Set-Cookie"], undefined);
  assert.equal(response.multiValueHeaders["Set-Cookie"].length, 2);
});
test("cookie parsing ignores unrelated malformed cookies and rejects ambiguous own cookies", () => {
  assert.equal(g.transactionCookieFromEvent({ headers: { Cookie: "other=%ZZ; iphs_oauth=abc" } }), "abc");
  assert.equal(g.transactionCookieFromEvent({ headers: { cookie: "iphs_oauth=%ZZ" } }), null);
  assert.equal(g.transactionCookieFromEvent({ headers: { cookie: "iphs_oauth=a; iphs_oauth=b" } }), null);
  assert.equal(g.transactionCookieFromEvent({}), null);
});
test("query parsing handles absent fields and rejects duplicates/control characters", () => {
  assert.equal(g.queryValue({}, "code", 100), undefined);
  assert.equal(g.queryValue({ queryStringParameters: { code: "ok" } }, "code", 100), "ok");
  for (const event of [
    { rawQuery: "code=a&code=b", queryStringParameters: { code: "a" } },
    { multiValueQueryStringParameters: { code: ["a", "b"] } },
    { multiValueQueryStringParameters: { code: ["a"] }, queryStringParameters: { code: "b" } },
    { queryStringParameters: { code: "a\r\n" } }, { queryStringParameters: { code: ["a"] } },
  ]) assert.throws(() => g.queryValue(event, "code", 100), g.OAuthError);
});
test("allowlisted next retains harmless query/hash and rejects redirect tricks", () => {
  assert.equal(g.safeNextPath("/core/syllabus.html?q=1#part"), "/core/syllabus.html?q=1#part");
  assert.equal(g.safeNextPath("/weeks/week-15.html"), "/weeks/week-15.html");
  for (const bad of [undefined, "https://evil.example", "//evil.example", "/\\evil.example", "/x\\y",
    "/a/..//evil.example", "/%2f%2fevil.example", "/core/%73yllabus.html", "/core/syllabus.html?x=%0d%0a",
    "/core/syllabus.html?x=%ZZ", "/.netlify/functions/google-start", "/login.html", "/unknown", "/weeks/week-16.html"])
    assert.equal(g.safeNextPath(bad), "/index.html", String(bad));
});
test("valid claims, Gmail and single-element audience arrays", () => {
  assert.deepEqual(validate(good()), { ok: true });
  assert.deepEqual(validate({ ...good(), aud: [cfg.clientId] }), { ok: true });
  assert.deepEqual(validate({ ...good(), iss: "accounts.google.com", email: "STUDENT@gmail.com", hd: undefined }), { ok: true });
});
for (const [name, patch, error] of [
  ["issuer", { iss: "https://evil.example" }, "issuer"],
  ["audience", { aud: "other" }, "audience"], ["untrusted audience", { aud: [cfg.clientId, "other"] }, "audience"],
  ["azp", { azp: "other" }, "audience"], ["expired", { exp: NOW - 60 }, "time"],
  ["exp type", { exp: "1800003600" }, "time"], ["nonfinite exp", { exp: Infinity }, "time"],
  ["missing iat", { iat: undefined }, "time"], ["future iat", { iat: NOW + 61 }, "time"],
  ["old iat", { iat: NOW - 661 }, "time"], ["future nbf", { nbf: NOW + 61 }, "time"],
  ["nonce", { nonce: "wrong" }, "nonce"], ["subject type", { sub: 123 }, "subject"],
  ["subject controls", { sub: "subject\n" }, "subject"], ["email type", { email: {} }, "email"],
  ["unverified", { email_verified: false }, "email"], ["string verified", { email_verified: "true" }, "email"],
  ["third-party email", { email: "student@other.example" }, "unsupported_account"],
  ["missing hd", { hd: undefined }, "unsupported_account"], ["wrong hd", { hd: "other.example" }, "unsupported_account"],
]) test(`rejects claims: ${name}`, () => assert.equal(validate({ ...good(), ...patch }).error, error));
test("decoder is bounded, rejects alg none/HS256, and does not validate signatures", () => {
  assert.deepEqual(g.decodeTokenEndpointIdToken(jwt(good())), good());
  for (const token of ["junk", jwt(good(), { alg: "none" }), jwt(good(), { alg: "HS256" }),
    jwt(good(), { alg: "RS256", crit: ["unknown"] }), "a".repeat(20000)])
    assert.equal(g.decodeTokenEndpointIdToken(token), null);
});
test("policy recomputes admin, keeps rejection and resets changed identities/removals", () => {
  const decide = (email, existingUser, hd) => g.decideAccount({ ...cfg, email, hd, existingUser });
  assert.deepEqual(decide("prof@gmail.com"), { status: "approved", role: "admin" });
  assert.deepEqual(decide("student@kenyon.edu", null, "kenyon.edu"), { status: "approved", role: "student" });
  assert.deepEqual(decide("student@kenyon.edu"), { status: "pending", role: "student" });
  assert.deepEqual(decide("other@gmail.com"), { status: "pending", role: "student" });
  assert.equal(decide("roster@gmail.com").status, "approved");
  assert.deepEqual(decide("prof@gmail.com", { email: "prof@gmail.com", status: "rejected", role: "admin" }),
    { status: "rejected", role: "student" });
  assert.equal(decide("other@gmail.com", { email: "other@gmail.com", status: "approved", role: "student" }).status, "approved");
  assert.equal(decide("other@gmail.com", { email: "old@gmail.com", status: "approved", role: "student" }).status, "pending");
  assert.deepEqual(decide("former@gmail.com", { email: "former@gmail.com", status: "approved", role: "admin" }),
    { status: "pending", role: "student" });
});
test("unverified local email does not link, transfer credentials or promote password record", () => {
  const password = { username: "localuser", email: "prof@gmail.com", status: "approved", role: "student",
    salt: "placeholder", passwordHash: "attacker-chosen-placeholder" };
  const users = { localuser: { ...password } };
  const result = g.provisionGoogle(users, { ...good(), email: "prof@gmail.com" }, cfg);
  assert.deepEqual(users.localuser, password);
  assert.equal(result.value.user.username, "prof@gmail.com");
  assert.equal(result.value.user.role, "admin");
  assert.equal(Object.hasOwn(result.value.user, "passwordHash"), false);
  assert.equal(Object.hasOwn(result.value.user, "salt"), false);
});
test("subject is immutable; username stays stable after verified email change", () => {
  const users = {};
  const created = g.provisionGoogle(users, good(), cfg).value.user;
  const updated = g.provisionGoogle(users, { ...good(), email: "new@gmail.com", hd: undefined }, cfg).value.user;
  assert.equal(updated.username, created.username);
  assert.equal(updated.email, "new@gmail.com");
  assert.equal(updated.googleSub, created.googleSub);
  assert.equal(updated.status, "pending");
});
test("collisions and mixed credentials fail before any mutation", () => {
  const record = g.provisionGoogle({}, good(), cfg).value.user;
  for (const users of [
    { [record.email]: { ...record, googleSub: "different" } },
    { occupied: { ...record, username: "occupied", googleSub: "different" } },
    { [record.email]: { ...record }, duplicate: { ...record, username: "duplicate" } },
    { [record.email]: { ...record, passwordHash: "placeholder" } },
    { [record.email]: { ...record, provider: "password+google" } },
    { [record.email]: { username: record.email } },
  ]) {
    const before = JSON.stringify(users);
    assert.throws(() => g.provisionGoogle(users, good(), cfg), g.OAuthError);
    assert.equal(JSON.stringify(users), before);
  }
});
test("token exchange uses exact fixed endpoint, client authentication, verifier and no redirect", async () => {
  let request;
  const token = await g.exchangeCode({ code: "code-placeholder", verifier: "verifier-placeholder", cfg,
    fetchImpl: async (url, options) => { request = { url, options }; return new Response(JSON.stringify({ id_token: "synthetic" })); } });
  assert.equal(token, "synthetic");
  assert.equal(request.url, g.GOOGLE_TOKEN_URL);
  assert.equal(request.options.redirect, "error");
  assert.ok(request.options.signal instanceof AbortSignal);
  for (const [key, value] of Object.entries({ code: "code-placeholder", code_verifier: "verifier-placeholder",
    grant_type: "authorization_code", client_id: cfg.clientId, client_secret: cfg.clientSecret, redirect_uri: cfg.redirectUri }))
    assert.equal(request.options.body.get(key), value);
});
test("token exchange rejects failure, malformed JSON, missing token, oversized response and network error", async () => {
  for (const makeResponse of [
    () => new Response("failure", { status: 400 }), () => new Response("{broken"),
    () => new Response("{}"), () => new Response("x".repeat(32769)),
  ]) await assert.rejects(g.exchangeCode({ code: "placeholder", verifier: "placeholder", cfg,
    fetchImpl: async () => makeResponse() }));
  await assert.rejects(g.exchangeCode({ code: "placeholder", verifier: "placeholder", cfg,
    fetchImpl: async () => { throw new Error("synthetic network failure"); } }));
});

// ---------------------------------------------------------------------------
// Additional coverage (W1 brief): items named in the dispatch brief that the
// §8.1 list covers only indirectly. Fixtures are synthetic placeholders.
// ---------------------------------------------------------------------------

test("module exports exactly the §7.1 interface", () => {
  assert.deepEqual(Object.keys(g).sort(), [
    "GOOGLE_AUTH_URL", "GOOGLE_TOKEN_URL", "OAUTH_COOKIE", "OAUTH_COOKIE_PATH", "OAUTH_TTL_SECONDS",
    "OAuthError", "config", "equal", "randomUrlSafe", "pkceChallenge", "parseList", "safeNextPath",
    "queryValue", "transactionCookieFromEvent", "sealTransaction", "readTransaction", "oauthCookie",
    "response", "redirect", "buildAuthUrl", "decodeTokenEndpointIdToken", "validateIdTokenClaims",
    "exchangeCode", "displayName", "decideAccount", "provisionGoogle",
  ].sort());
  assert.equal(g.GOOGLE_AUTH_URL, "https://accounts.google.com/o/oauth2/v2/auth");
  assert.equal(g.GOOGLE_TOKEN_URL, "https://oauth2.googleapis.com/token");
  assert.equal(g.OAUTH_COOKIE, "iphs_oauth");
  assert.equal(g.OAUTH_COOKIE_PATH, "/.netlify/functions/google-callback");
  assert.equal(g.OAUTH_TTL_SECONDS, 600);
});

test("kill switch: anything other than the exact string \"true\" is disabled", () => {
  for (const value of ["TRUE", "True", " true", "true ", "1", "yes", "on", "", true, undefined]) {
    assert.throws(() => g.config({ ...ENV, GOOGLE_OAUTH_ENABLED: value }),
      (error) => error instanceof g.OAuthError && error.code === "disabled", String(value));
  }
  // The kill switch is checked first: a disabled service reports "disabled", not a configuration error.
  assert.throws(() => g.config({ GOOGLE_OAUTH_ENABLED: "false" }), (error) => error.code === "disabled");
  assert.throws(() => g.config({ ...ENV, SITE_URL: undefined }), (error) => error.code === "configuration");
});

test("SITE_URL accepts only the three exact origins", () => {
  assert.equal(g.config({ ...ENV, SITE_URL: "https://localhost:8888" }).redirectUri,
    "https://localhost:8888/.netlify/functions/google-callback");
  for (const siteUrl of ["http://theailab.net", "https://www.theailab.net", "https://theailab.net/path",
    "https://user:pw@theailab.net", "https://theailab.net#frag", "https://THEAILAB.NET",
    "http://localhost:8888/", "http://localhost:3000", "http://127.0.0.1:8888", " https://theailab.net", ""])
    assert.throws(() => g.config({ ...ENV, SITE_URL: siteUrl }), (error) => error.code === "configuration", siteUrl);
});

test("configuration returns parsed policy lists and rejects malformed secrets/notify address", () => {
  const parsed = g.config({ ...ENV, ADMIN_EMAILS: "Prof@Gmail.com, prof@gmail.com", ADMIN_NOTIFY_EMAIL: " notify@example.org " });
  assert.deepEqual(parsed.adminEmails, ["prof@gmail.com"]);
  assert.deepEqual(parsed.autoApproveEmails, ["roster@gmail.com"]);
  assert.deepEqual(parsed.autoApproveDomains, ["kenyon.edu"]);
  assert.equal(parsed.notifyEmail, "notify@example.org");
  assert.deepEqual(g.config({ ...ENV, ADMIN_EMAILS: undefined, AUTO_APPROVE_DOMAINS: "" }).adminEmails, []);
  assert.deepEqual(g.config({ ...ENV, AUTO_APPROVE_DOMAINS: undefined }).autoApproveDomains, []);
  for (const patch of [
    { GOOGLE_CLIENT_SECRET: "has space" }, { GOOGLE_CLIENT_SECRET: "tab\there" }, { SESSION_SECRET: undefined },
    { GOOGLE_CLIENT_ID: "x.apps.googleusercontent.com.evil" }, { ADMIN_EMAILS: "@gmail.com" }, { ADMIN_EMAILS: "gmail.com" },
    { AUTO_APPROVE_EMAILS: "someone@kenyon.edu.evil" }, { AUTO_APPROVE_DOMAINS: "kenyon.edu,gmail.com" },
    { ADMIN_NOTIFY_EMAIL: "not-an-email" }, { ADMIN_NOTIFY_EMAIL: `${"a".repeat(250)}@example.org` },
  ]) assert.throws(() => g.config({ ...ENV, ...patch }), g.OAuthError, JSON.stringify(Object.keys(patch)));

  // A list entry is an exact address, never a pattern: "*@gmail.com" matches only that literal string.
  const literal = g.config({ ...ENV, ADMIN_EMAILS: "*@gmail.com" });
  assert.equal(g.decideAccount({ ...literal, email: "other@gmail.com", existingUser: null }).role, "student");
});

test("state comparison is timing-safe and fails closed on type or length mismatch", () => {
  const original = crypto.timingSafeEqual;
  let calls = 0;
  crypto.timingSafeEqual = (a, b) => { calls += 1; return original(a, b); };
  try {
    const state = g.randomUrlSafe();
    assert.equal(g.equal(state, state), true);
    assert.ok(calls >= 1, "equal() must use crypto.timingSafeEqual");
    assert.equal(g.equal(state, `${state.slice(0, -1)}A` === state ? `${state.slice(0, -1)}B` : `${state.slice(0, -1)}A`), false);
  } finally { crypto.timingSafeEqual = original; }
  assert.equal(g.equal("abc", "abcd"), false);
  assert.equal(g.equal(undefined, undefined), false);
  assert.equal(g.equal(null, "x"), false);
  assert.equal(g.equal(["a"], "a"), false);
  assert.equal(g.equal("", ""), true);
});

test("PKCE verifier/challenge pair: S256, URL-safe, 43 characters", () => {
  const verifier = g.randomUrlSafe(48);
  const challenge = g.pkceChallenge(verifier);
  assert.match(challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(challenge, crypto.createHash("sha256").update(verifier).digest("base64url"));
  assert.notEqual(g.randomUrlSafe(), g.randomUrlSafe());
});

test("transaction server expiry is enforced independently of cookie Max-Age", () => {
  const st = transaction();
  const token = g.sealTransaction(st, cfg.sessionSecret);
  assert.deepEqual(g.readTransaction(token, cfg, st.exp - 1), st);
  assert.equal(g.readTransaction(token, cfg, st.exp), null);
  assert.equal(g.readTransaction(token, cfg, st.exp + 86400), null);
  // A replayed cookie that a browser kept past Max-Age is still refused by the server.
  const old = { ...transaction(), iat: NOW - 10_000, exp: NOW - 10_000 + g.OAUTH_TTL_SECONDS };
  assert.equal(g.readTransaction(g.sealTransaction(old, cfg.sessionSecret), cfg, NOW), null);
  // A different SESSION_SECRET derives a different OAuth key.
  assert.equal(g.readTransaction(g.sealTransaction(st, "another-test-only-secret"), cfg, NOW), null);
  // Verifier substitution under a valid-looking signature is rejected.
  const [, payload, signature] = token.split(".");
  const swapped = Buffer.from(JSON.stringify({ ...st, verifier: g.randomUrlSafe(48) })).toString("base64url");
  assert.equal(g.readTransaction(`oauth2.${swapped}.${signature}`, cfg, NOW), null);
  assert.equal(g.readTransaction(`oauth2.${payload}`, cfg, NOW), null);
  assert.equal(g.readTransaction(undefined, cfg, NOW), null);
  assert.equal(g.readTransaction("x".repeat(3001), cfg, NOW), null);
});

test("clear cookie uses identical name, Path and attributes with Max-Age=0", () => {
  const set = g.oauthCookie("oauth2.payload.signature", 600);
  const clear = g.oauthCookie("", 0);
  assert.equal(clear, "iphs_oauth=; Path=/.netlify/functions/google-callback; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
  const attrs = (cookie) => cookie.split("; ").slice(1, -1);
  assert.deepEqual(attrs(clear), attrs(set));
  assert.equal(set.split("=")[0], clear.split("=")[0]);
  for (const maxAge of [1, 599, 601, 3600, -1, "600"]) assert.throws(() => g.oauthCookie("abc", maxAge), g.OAuthError);
  assert.throws(() => g.oauthCookie(undefined, 0), g.OAuthError);
  assert.throws(() => g.oauthCookie("a\r\nSet-Cookie: x=y", 600), g.OAuthError);
});

test("fixed response helpers: no-store, no-referrer, 405 with Allow: GET, header-injection guard", () => {
  const notAllowed = g.response(405, "Method Not Allowed", { Allow: "GET" });
  assert.equal(notAllowed.statusCode, 405);
  assert.equal(notAllowed.headers.Allow, "GET");
  assert.equal(notAllowed.headers["Cache-Control"], "no-store");
  assert.equal(notAllowed.headers["Referrer-Policy"], "no-referrer");
  assert.equal(notAllowed.multiValueHeaders, undefined);
  const unavailable = g.response(503, "Service Unavailable");
  assert.equal(unavailable.headers["Cache-Control"], "no-store");
  assert.equal(unavailable.headers["Referrer-Policy"], "no-referrer");
  assert.equal(g.redirect("/index.html").headers.Location, "/index.html");
  for (const location of ["/index.html\r\nSet-Cookie: x=y", "/a b", undefined])
    assert.throws(() => g.redirect(location), g.OAuthError);
});

test("query values are length-bounded", () => {
  assert.equal(g.queryValue({ queryStringParameters: { state: "a".repeat(10) } }, "state", 10), "a".repeat(10));
  assert.throws(() => g.queryValue({ queryStringParameters: { state: "a".repeat(11) } }, "state", 10), g.OAuthError);
  assert.throws(() => g.queryValue({ queryStringParameters: { state: "" } }, "state", 10), g.OAuthError);
  assert.equal(g.queryValue({ rawQuery: "state=abc", queryStringParameters: { state: "abc" } }, "state", 10), "abc");
});

test("claim boundaries: skew limits, optional nbf and hd type", () => {
  assert.deepEqual(validate({ ...good(), iat: NOW + 60 }), { ok: true });
  assert.deepEqual(validate({ ...good(), iat: NOW - 660 }), { ok: true });
  assert.deepEqual(validate({ ...good(), iat: NOW - 100, exp: NOW - 59 }), { ok: true });
  assert.deepEqual(validate({ ...good(), nbf: NOW + 60 }), { ok: true });
  assert.equal(validate({ ...good(), nbf: "0" }).error, "time");
  assert.equal(validate({ ...good(), exp: NOW - 20, iat: NOW - 10 }).error, "time");
  assert.equal(validate({ ...good(), iat: 1.5 }).error, "time");
  assert.equal(validate({ ...good(), aud: [] }).error, "audience");
  assert.deepEqual(validate({ ...good(), azp: undefined }), { ok: true });
  assert.equal(validate({ ...good(), nonce: undefined }).error, "nonce");
  assert.equal(g.validateIdTokenClaims(good(), { clientId: cfg.clientId, nonce: "", now: NOW }).error, "nonce");
  assert.equal(validate({ ...good(), sub: "" }).error, "subject");
  assert.equal(validate({ ...good(), sub: "x".repeat(256) }).error, "subject");
  assert.equal(validate({ ...good(), email_verified: undefined }).error, "email");
  assert.equal(validate({ ...good(), email: "student@gmail.com", hd: 7 }).error, "claims");
  assert.equal(validate(null).error, "claims");
  assert.equal(validate([good()]).error, "claims");
});

test("domain approval requires both configured domain and hd claim", () => {
  const noDomain = { ...cfg, autoApproveDomains: [] };
  assert.equal(g.decideAccount({ ...noDomain, email: "student@kenyon.edu", hd: "kenyon.edu", existingUser: null }).status, "pending");
  assert.equal(g.decideAccount({ ...cfg, email: "student@gmail.com", hd: undefined, existingUser: null }).status, "pending");
  // Pending accounts are re-evaluated against current policy on each login.
  assert.deepEqual(g.decideAccount({ ...cfg, email: "prof@gmail.com", existingUser: { email: "prof@gmail.com", status: "pending", role: "student" } }),
    { status: "approved", role: "admin" });
  // Approved students keep approval when the roster entry disappears.
  assert.equal(g.decideAccount({ ...cfg, autoApproveEmails: [], email: "roster@gmail.com",
    existingUser: { email: "roster@gmail.com", status: "approved", role: "student" } }).status, "approved");
  // A changed email that still hits current policy is re-approved; a rejection stays sticky despite a roster hit.
  assert.equal(g.decideAccount({ ...cfg, email: "roster@gmail.com", existingUser: { email: "old@gmail.com", status: "approved", role: "student" } }).status, "approved");
  assert.equal(g.decideAccount({ ...cfg, email: "roster@gmail.com", existingUser: { email: "roster@gmail.com", status: "rejected", role: "student" } }).status, "rejected");
});

test("new Google record has the §5 shape and no credential or reset fields", () => {
  const users = {};
  const at = "2026-10-20T14:02:11.000Z";
  const result = g.provisionGoogle(users, { ...good(), name: "Example\nStudent" }, cfg, at);
  assert.equal(result.changed, true);
  assert.equal(result.value.isNew, true);
  assert.deepEqual(users["student@kenyon.edu"], {
    username: "student@kenyon.edu", createdAt: at, email: "student@kenyon.edu", googleSub: "subject-placeholder",
    provider: "google", name: "Example Student", status: "approved", role: "student", lastLoginAt: at,
  });
  for (const key of ["salt", "passwordHash", "resetToken", "resetTokenExpires"])
    assert.equal(Object.hasOwn(users["student@kenyon.edu"], key), false);
  const later = "2026-10-21T09:00:00.000Z";
  const again = g.provisionGoogle(users, { ...good(), name: "Renamed" }, cfg, later);
  assert.equal(again.value.isNew, false);
  assert.equal(again.value.user.createdAt, at);
  assert.equal(again.value.user.lastLoginAt, later);
  assert.equal(again.value.user.name, "Example Student");
  assert.equal(g.displayName("   ", "fallback"), "fallback");
  assert.equal(g.displayName("x".repeat(500), "fallback").length, 120);
});

test("rejected Google account stays rejected and admin-listed email gains no role", () => {
  const users = { "prof@gmail.com": { username: "prof@gmail.com", email: "prof@gmail.com", googleSub: "subject-placeholder",
    provider: "google", name: "P", status: "rejected", role: "student", createdAt: "x", lastLoginAt: "x" } };
  const { user } = g.provisionGoogle(users, { ...good(), email: "prof@gmail.com", hd: undefined }, cfg).value;
  assert.equal(user.status, "rejected");
  assert.equal(user.role, "student");
});

test("helper never logs during token exchange success or failure", async () => {
  const methods = ["log", "info", "warn", "error", "debug"];
  const saved = methods.map((m) => console[m]);
  const seen = [];
  methods.forEach((m) => { console[m] = (...args) => seen.push([m, args]); });
  try {
    await g.exchangeCode({ code: "placeholder", verifier: "placeholder", cfg,
      fetchImpl: async () => new Response(JSON.stringify({ id_token: "synthetic", access_token: "synthetic" })) });
    await assert.rejects(g.exchangeCode({ code: "placeholder", verifier: "placeholder", cfg,
      fetchImpl: async () => new Response("failure", { status: 500 }) }), g.OAuthError);
  } finally { methods.forEach((m, i) => { console[m] = saved[i]; }); }
  assert.deepEqual(seen, []);
});

test("token exchange sends a form-encoded POST and returns only the ID token", async () => {
  let request;
  const result = await g.exchangeCode({ code: "placeholder", verifier: "placeholder", cfg,
    fetchImpl: async (url, options) => { request = options;
      return new Response(JSON.stringify({ id_token: "synthetic", access_token: "synthetic-access", refresh_token: "synthetic-refresh" })); } });
  assert.equal(result, "synthetic");
  assert.equal(request.method, "POST");
  assert.equal(request.headers["Content-Type"], "application/x-www-form-urlencoded");
  assert.ok(request.body instanceof URLSearchParams);
  await assert.rejects(g.exchangeCode({ code: "placeholder", verifier: "placeholder", cfg,
    fetchImpl: async () => new Response(JSON.stringify({ id_token: 42 })) }), g.OAuthError);
  await assert.rejects(g.exchangeCode({ code: "placeholder", verifier: "placeholder", cfg,
    fetchImpl: async () => new Response(JSON.stringify(["id_token"])) }), g.OAuthError);
});
