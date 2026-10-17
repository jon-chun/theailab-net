import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { createRequire } from "node:module";
// Dummy credentials used only by these tests (kept in one place so no literal is assigned to a password key).
const PW = {
  ok: "correct-horse-1",
  wrong: "nope-nope-1",
  any: "whatever-1",
  fresh: "long-enough-1",
  reset1: "another-pass-9",
  reset2: "second-pass-22",
  reset3: "first-pass-111",
  current: "old-pass-1234",
  badCurrent: "wrong-wrong-1",
  anything: "anything-1",
  concurrent: "concurrent-pass-2",
};


// Real handler source runs under vm with an in-memory Blobs-like store behind the
// real users-store.js repository (so CAS retries are exercised), a mail stub and
// fixed dummy secrets. No SDK, network or .env is used.
const nodeRequire = createRequire(import.meta.url);
const FUNCS = new URL("../../netlify/functions/", import.meta.url);
const SECRET = "dummy-session-secret-for-tests-only";
const LEAK = "backend-detail-xyz";

function loadCjs(file, sandbox, requireMap) {
  const source = fs.readFileSync(new URL(file, FUNCS), "utf8");
  const module = { exports: {} };
  vm.runInNewContext(`(function(require, module, exports) {\n${source}\n})`, sandbox)((name) => {
    if (!(name in requireMap)) throw new Error(`unexpected require: ${name}`);
    return requireMap[name];
  }, module, module.exports);
  return module.exports;
}

function fakeStore(initial) {
  let data = initial == null ? null : structuredClone(initial);
  let version = data === null ? 0 : 1;
  const s = {
    writes: 0, setCalls: 0, failGet: false, beforeSet: null,
    async getWithMetadata(key, options) {
      assert.equal(key, "users.json"); assert.equal(options.consistency, "strong");
      if (s.failGet) throw new Error(LEAK);
      return data === null ? null : { data: structuredClone(data), etag: String(version) };
    },
    async setJSON(key, next, condition) {
      s.setCalls++;
      const hook = s.beforeSet;
      if (hook) { s.beforeSet = null; await hook(); }
      if ((condition.onlyIfNew && data !== null) || (condition.onlyIfMatch && condition.onlyIfMatch !== String(version))) {
        return { modified: false };
      }
      data = structuredClone(next); version++; s.writes++;
      return { modified: true, etag: String(version) };
    },
    data: () => structuredClone(data),
    raw(fn) { data = data || {}; fn(data); version++; },
  };
  return s;
}

function world({ users = {}, env = {}, mail } = {}) {
  const logs = [];
  const sink = (...a) => logs.push(a.map(String).join(" "));
  const consoleStub = { log: sink, info: sink, warn: sink, error: sink };
  const processStub = { env: { SESSION_SECRET: SECRET, ...env } };
  const sandbox = { process: processStub, Buffer, console: consoleStub, setTimeout, URL };
  const storeModule = loadCjs("util/users-store.js", sandbox, { "@netlify/blobs": {} });
  const fake = fakeStore(users);
  const repo = storeModule.createRepository(fake, 5);
  let usersStoreCalls = 0;
  const mails = [];
  const mailModule = { sendMail: async (m) => { mails.push(m); return mail ? mail(m) : { skipped: false, ok: true }; } };
  const auth = loadCjs("util/auth.js", sandbox, { crypto: nodeRequire("crypto") });
  const requireMap = {
    crypto: nodeRequire("crypto"),
    "./util/users-store": { usersStore: () => { usersStoreCalls++; return repo; }, UsersStoreError: storeModule.UsersStoreError },
    "./util/auth": auth,
    "./util/mail": mailModule,
  };
  return {
    fake, repo, auth, mails, logs, env: processStub.env,
    storeUses: () => usersStoreCalls,
    handler: (name) => loadCjs(`${name}.js`, sandbox, requireMap).handler,
    pwUser(username, password, extra = {}) {
      const { salt, hash } = auth.hashPassword(password);
      return { username, name: username, email: `${username}@example.test`, salt, passwordHash: hash,
        status: "approved", role: "student", createdAt: "2026-01-01T00:00:00.000Z", ...extra };
    },
    cookie(username, role = "student") { return auth.makeSessionCookie({ username, role }).split(";")[0]; },
  };
}

const ev = (method, body, cookie) => ({
  httpMethod: method,
  headers: cookie ? { cookie } : {},
  body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
});
const json = (r) => JSON.parse(r.body);
const hdr = (r, name) => Object.entries(r.headers || {}).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];
const googleUser = (extra = {}) => ({
  username: "gina@example.test", name: "Gina", email: "gina@example.test", googleSub: "sub-123",
  provider: "google", status: "approved", role: "student", createdAt: "2026-01-01T00:00:00.000Z", ...extra,
});
const future = () => Date.now() + 10 * 60 * 1000;
const NEW_PW = "brand-new-pass-1";

// ---------------------------------------------------------------- source checks

const HANDLERS = ["login", "register", "logout", "session", "forgot-password", "reset-password",
  "change-password", "admin-bootstrap", "admin-decide", "admin-users"];

test("no migrated handler imports the removed loadUsers/saveUsers module API", () => {
  for (const name of HANDLERS) {
    const source = fs.readFileSync(new URL(`${name}.js`, FUNCS), "utf8");
    assert.doesNotMatch(source, /\bsaveUsers\b/, `${name} mentions saveUsers`);
    assert.doesNotMatch(source, /\{[^}]*\bloadUsers\b[^}]*\}\s*=\s*require\(/, `${name} destructures loadUsers from a module`);
    assert.doesNotMatch(source, /console\.\w+\([^)]*\b(err|error|e)\b\s*\)/, `${name} logs a raw exception`);
  }
});

test("hasPasswordCredentials accepts only non-Google records with well-formed salt and hash", () => {
  const w = world();
  const { salt, hash } = w.auth.hashPassword("whatever-pass");
  assert.equal(w.auth.hasPasswordCredentials({ salt, passwordHash: hash }), true);
  assert.equal(w.auth.hasPasswordCredentials({ provider: "password", salt, passwordHash: hash }), true);
  assert.equal(w.auth.hasPasswordCredentials({ provider: "google", salt, passwordHash: hash }), false);
  assert.equal(w.auth.hasPasswordCredentials(googleUser()), false);
  assert.equal(w.auth.hasPasswordCredentials(null), false);
  assert.equal(w.auth.hasPasswordCredentials(undefined), false);
  assert.equal(w.auth.hasPasswordCredentials({ salt: "short", passwordHash: hash }), false);
  assert.equal(w.auth.hasPasswordCredentials({ salt, passwordHash: "abc" }), false);
  assert.equal(w.auth.hasPasswordCredentials({ salt, passwordHash: 5 }), false);
});

// ---------------------------------------------------------------- login

test("login: password account approved gets the existing 200 and session cookie", async () => {
  const w = world(); w.fake.raw((d) => { d.alice = w.pwUser("alice", "correct-horse-1", { role: "admin" }); });
  const r = await w.handler("login")(ev("POST", { username: " Alice ", password: PW.ok }));
  assert.equal(r.statusCode, 200);
  assert.deepEqual(json(r), { message: "Logged in.", role: "admin" });
  const cookie = hdr(r, "Set-Cookie");
  assert.match(cookie, /^iphs_session=[^;]+; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200$/);
  const payload = w.auth.verify(cookie.split(";")[0].slice("iphs_session=".length));
  assert.equal(payload.sub, "alice"); assert.equal(payload.role, "admin");
  assert.equal(w.fake.writes, 0);
});

test("login: wrong password and unknown user return the same 401", async () => {
  const w = world(); w.fake.raw((d) => { d.alice = w.pwUser("alice", "correct-horse-1"); });
  const bad = await w.handler("login")(ev("POST", { username: "alice", password: PW.wrong }));
  const none = await w.handler("login")(ev("POST", { username: "nobody", password: PW.wrong }));
  assert.equal(bad.statusCode, 401); assert.equal(none.statusCode, 401);
  assert.deepEqual(json(bad), { error: "Invalid username or password." });
  assert.equal(bad.body, none.body);
  assert.equal(hdr(bad, "Set-Cookie"), undefined);
});

test("login: Google-only record gets the invalid-credential 401, even with planted credentials", async () => {
  const w = world();
  const planted = w.pwUser("x", "correct-horse-1");
  w.fake.raw((d) => {
    d["gina@example.test"] = googleUser();
    d["mixed@example.test"] = googleUser({ username: "mixed@example.test", salt: planted.salt, passwordHash: planted.passwordHash });
  });
  for (const username of ["gina@example.test", "mixed@example.test"]) {
    const r = await w.handler("login")(ev("POST", { username, password: PW.ok }));
    assert.equal(r.statusCode, 401); assert.deepEqual(json(r), { error: "Invalid username or password." });
    assert.equal(hdr(r, "Set-Cookie"), undefined);
  }
  assert.equal(w.fake.writes, 0);
});

test("login: pending and rejected keep their messages; unknown status or role never mints a session", async () => {
  const w = world();
  w.fake.raw((d) => {
    d.p = w.pwUser("p", "correct-horse-1", { status: "pending" });
    d.r = w.pwUser("r", "correct-horse-1", { status: "rejected" });
    d.u = w.pwUser("u", "correct-horse-1", { status: "suspended" });
    d.m = w.pwUser("m", "correct-horse-1", { status: undefined });
    d.o = w.pwUser("o", "correct-horse-1", { role: "superuser" });
  });
  const login = w.handler("login");
  let r = await login(ev("POST", { username: "p", password: PW.ok }));
  assert.equal(r.statusCode, 403); assert.deepEqual(json(r), { error: "Your account is still pending admin approval." });
  r = await login(ev("POST", { username: "r", password: PW.ok }));
  assert.equal(r.statusCode, 403); assert.deepEqual(json(r), { error: "Your account request was not approved." });
  for (const username of ["u", "m", "o"]) {
    r = await login(ev("POST", { username, password: PW.ok }));
    assert.equal(r.statusCode, 403, username); assert.equal(hdr(r, "Set-Cookie"), undefined, username);
  }
});

test("login: inherited names are not users; method and JSON checks are unchanged", async () => {
  const w = world(); const login = w.handler("login");
  for (const username of ["__proto__", "constructor", "prototype", "tostring"]) {
    const r = await login(ev("POST", { username, password: PW.any }));
    assert.equal(r.statusCode, 401, username);
  }
  assert.equal((await login(ev("GET"))).statusCode, 405);
  assert.equal((await login(ev("POST", "{not json"))).statusCode, 400);
});

// ---------------------------------------------------------------- register

const REG = { username: "Newbie", password: PW.fresh, name: "New Bie", email: "newbie@example.test" };

test("register: creates the pending student record and sends one plain-text notification after commit", async () => {
  const w = world({ env: { ADMIN_NOTIFY_EMAIL: "notify@example.test" } });
  const r = await w.handler("register")(ev("POST", REG));
  assert.equal(r.statusCode, 201);
  assert.deepEqual(json(r), { message: "Registration received. An admin must approve your account before you can log in." });
  const rec = w.fake.data().newbie;
  assert.deepEqual(Object.keys(rec).sort(), ["createdAt", "email", "name", "passwordHash", "role", "salt", "status", "username"]);
  assert.equal(rec.status, "pending"); assert.equal(rec.role, "student"); assert.equal(rec.name, "New Bie");
  assert.equal(w.auth.verifyPassword("long-enough-1", rec.salt, rec.passwordHash), true);
  assert.equal(w.mails.length, 1);
  assert.equal(w.mails[0].to, "notify@example.test");
  assert.equal("html" in w.mails[0], false);
  assert.equal(typeof w.mails[0].text, "string");
});

test("register: no ADMIN_NOTIFY_EMAIL means no mail attempt", async () => {
  const w = world();
  assert.equal((await w.handler("register")(ev("POST", REG))).statusCode, 201);
  assert.equal(w.mails.length, 0);
});

test("register: occupied username is 409 and the record is untouched", async () => {
  const w = world({ env: { ADMIN_NOTIFY_EMAIL: "notify@example.test" } });
  const existing = w.pwUser("newbie", "other-pass-123"); w.fake.raw((d) => { d.newbie = existing; });
  const r = await w.handler("register")(ev("POST", REG));
  assert.equal(r.statusCode, 409); assert.deepEqual(json(r), { error: "That username is already registered." });
  assert.deepEqual(w.fake.data().newbie, existing);
  assert.equal(w.mails.length, 0);
});

test("register: reserved names are rejected without touching storage", async () => {
  const w = world({ env: { ADMIN_NOTIFY_EMAIL: "notify@example.test" } });
  for (const username of ["__proto__", "constructor", "prototype", "CONSTRUCTOR"]) {
    const r = await w.handler("register")(ev("POST", { ...REG, username }));
    assert.equal(r.statusCode, 400, username);
  }
  assert.equal(w.fake.writes, 0); assert.deepEqual(w.fake.data(), {}); assert.equal(w.mails.length, 0);
});

test("register: a concurrent registration of the same name loses with 409 after the CAS conflict", async () => {
  const w = world({ env: { ADMIN_NOTIFY_EMAIL: "notify@example.test" } });
  const winner = w.pwUser("newbie", "winner-pass-1");
  w.fake.raw(() => {});
  w.fake.beforeSet = async () => w.fake.raw((d) => { d.newbie = winner; });
  const r = await w.handler("register")(ev("POST", REG));
  assert.equal(r.statusCode, 409);
  assert.deepEqual(w.fake.data().newbie, winner);
  assert.equal(w.mails.length, 0);
});

test("register: notification is sent once even when the CAS write retries", async () => {
  const w = world({ env: { ADMIN_NOTIFY_EMAIL: "notify@example.test" } });
  w.fake.raw(() => {});
  w.fake.beforeSet = async () => w.fake.raw((d) => { d.someoneelse = w.pwUser("someoneelse", "other-pass-123"); });
  const r = await w.handler("register")(ev("POST", REG));
  assert.equal(r.statusCode, 201);
  assert.equal(w.fake.setCalls, 2);
  assert.equal(w.mails.length, 1);
  assert.ok(w.fake.data().newbie); assert.ok(w.fake.data().someoneelse);
});

test("register: duplicate email grants nothing and does not modify the other account", async () => {
  const w = world();
  const other = w.pwUser("other", "other-pass-123", { email: "newbie@example.test", role: "admin" });
  w.fake.raw((d) => { d.other = other; });
  const r = await w.handler("register")(ev("POST", REG));
  assert.equal(r.statusCode, 201);
  assert.deepEqual(w.fake.data().other, other);
  assert.equal(w.fake.data().newbie.status, "pending"); assert.equal(w.fake.data().newbie.role, "student");
});

test("register: mail failure still returns 201 and logs only a fixed label", async () => {
  const w = world({ env: { ADMIN_NOTIFY_EMAIL: "notify@example.test" }, mail: async () => { throw new Error(LEAK); } });
  const r = await w.handler("register")(ev("POST", REG));
  assert.equal(r.statusCode, 201);
  assert.ok(w.logs.length >= 1);
  for (const line of w.logs) { assert.doesNotMatch(line, new RegExp(LEAK)); assert.doesNotMatch(line, /example\.test/); }
});

test("register: validation and method are unchanged", async () => {
  const w = world(); const register = w.handler("register");
  assert.equal((await register(ev("GET"))).statusCode, 405);
  assert.equal((await register(ev("POST", "{bad"))).statusCode, 400);
  assert.equal((await register(ev("POST", { ...REG, username: "a@b" }))).statusCode, 400);
  assert.equal((await register(ev("POST", { ...REG, password: "short" }))).statusCode, 400);
  assert.equal((await register(ev("POST", { ...REG, email: "nope" }))).statusCode, 400);
});

// ---------------------------------------------------------------- admin-bootstrap

const BOOT = { secret: "bootstrap-secret", username: "Root", password: PW.fresh, name: "Root Admin" };

test("admin-bootstrap: creates a new approved admin without email", async () => {
  const w = world({ env: { ADMIN_BOOTSTRAP_SECRET: "bootstrap-secret" } });
  const r = await w.handler("admin-bootstrap")(ev("POST", BOOT));
  assert.equal(r.statusCode, 201); assert.deepEqual(json(r), { message: "Admin account 'root' created." });
  const rec = w.fake.data().root;
  assert.deepEqual(Object.keys(rec).sort(), ["createdAt", "name", "passwordHash", "role", "salt", "status", "username"]);
  assert.equal(rec.role, "admin"); assert.equal(rec.status, "approved");
  assert.equal(w.auth.verifyPassword("long-enough-1", rec.salt, rec.passwordHash), true);
});

test("admin-bootstrap: existing username is 409 and never overwritten", async () => {
  const w = world({ env: { ADMIN_BOOTSTRAP_SECRET: "bootstrap-secret" } });
  const existing = w.pwUser("root", "original-pass-1"); w.fake.raw((d) => { d.root = existing; });
  const r = await w.handler("admin-bootstrap")(ev("POST", BOOT));
  assert.equal(r.statusCode, 409);
  assert.deepEqual(w.fake.data().root, existing); assert.equal(w.fake.writes, 0);
});

test("admin-bootstrap: secret, validation and method checks are unchanged", async () => {
  const off = world(); assert.equal((await off.handler("admin-bootstrap")(ev("POST", BOOT))).statusCode, 403);
  const w = world({ env: { ADMIN_BOOTSTRAP_SECRET: "bootstrap-secret" } }); const h = w.handler("admin-bootstrap");
  assert.equal((await h(ev("GET"))).statusCode, 405);
  assert.equal((await h(ev("POST", "{bad"))).statusCode, 400);
  assert.equal((await h(ev("POST", { ...BOOT, secret: "wrong" }))).statusCode, 403);
  assert.equal((await h(ev("POST", { ...BOOT, password: "short" }))).statusCode, 400);
  for (const username of ["__proto__", "constructor", "prototype"]) {
    assert.equal((await h(ev("POST", { ...BOOT, username }))).statusCode, 400, username);
  }
  assert.equal(w.fake.writes, 0);
});

// ---------------------------------------------------------------- admin-decide

test("admin-decide: only admins; malformed or missing cookie is 403 without exception", async () => {
  const w = world(); w.fake.raw((d) => { d.bob = w.pwUser("bob", "pw-pw-pw-1", { status: "pending" }); });
  const h = w.handler("admin-decide"); const body = { username: "bob", action: "approve" };
  assert.equal((await h(ev("POST", body))).statusCode, 403);
  assert.equal((await h(ev("POST", body, w.cookie("bob", "student")))).statusCode, 403);
  assert.equal((await h(ev("POST", body, "iphs_session=%E0%A4%A"))).statusCode, 403);
  assert.equal((await h(ev("POST", body, "iphs_session=garbage.sig"))).statusCode, 403);
  assert.equal((await h(ev("GET", undefined, w.cookie("a", "admin")))).statusCode, 405);
  assert.equal(w.fake.data().bob.status, "pending");
});

test("admin-decide: sets only status and decidedAt, returns the existing message", async () => {
  const w = world(); const bob = w.pwUser("bob", "pw-pw-pw-1", { status: "pending" });
  w.fake.raw((d) => { d.bob = bob; });
  const h = w.handler("admin-decide"); const admin = w.cookie("root", "admin");
  let r = await h(ev("POST", { username: "Bob", action: "approve" }, admin));
  assert.equal(r.statusCode, 200); assert.deepEqual(json(r), { message: "User bob approved." });
  let rec = w.fake.data().bob;
  assert.equal(rec.status, "approved"); assert.equal(typeof rec.decidedAt, "string");
  const { status: s1, decidedAt: d1, ...rest } = rec; const { status: s0, ...rest0 } = bob;
  assert.deepEqual(rest, rest0);
  r = await h(ev("POST", { username: "bob", action: "reject" }, admin));
  assert.deepEqual(json(r), { message: "User bob rejected." });
  assert.equal(w.fake.data().bob.status, "rejected");
});

test("admin-decide: absent user is 404, invalid action is 400, already-in-state is a no-op", async () => {
  const w = world(); w.fake.raw((d) => { d.bob = w.pwUser("bob", "pw-pw-pw-1", { status: "approved", decidedAt: "2026-02-02T00:00:00.000Z" }); });
  const h = w.handler("admin-decide"); const admin = w.cookie("root", "admin");
  assert.equal((await h(ev("POST", { username: "ghost", action: "approve" }, admin))).statusCode, 404);
  assert.equal((await h(ev("POST", { username: "__proto__", action: "approve" }, admin))).statusCode, 404);
  assert.equal((await h(ev("POST", { username: "bob", action: "delete" }, admin))).statusCode, 400);
  const before = w.fake.writes;
  const r = await h(ev("POST", { username: "bob", action: "approve" }, admin));
  assert.equal(r.statusCode, 200); assert.deepEqual(json(r), { message: "User bob approved." });
  assert.equal(w.fake.writes, before);
  assert.equal(w.fake.data().bob.decidedAt, "2026-02-02T00:00:00.000Z");
});

test("admin-decide: deciding a Google account never changes role, identity or credentials", async () => {
  const w = world(); const g = googleUser({ status: "pending" }); w.fake.raw((d) => { d[g.username] = g; });
  const r = await w.handler("admin-decide")(ev("POST", { username: g.username, action: "approve" }, w.cookie("root", "admin")));
  assert.equal(r.statusCode, 200);
  const rec = w.fake.data()[g.username];
  const { status, decidedAt, ...rest } = rec; const { status: s0, ...rest0 } = g;
  assert.deepEqual(rest, rest0);
  assert.equal("salt" in rec, false); assert.equal("passwordHash" in rec, false);
});

// ---------------------------------------------------------------- admin-users

test("admin-users: adds email, provider and decidedAt and never leaks secrets", async () => {
  const w = world();
  w.fake.raw((d) => {
    d.alice = w.pwUser("alice", "pw-pw-pw-1", { resetToken: "tok-secret", resetTokenExpires: future(), decidedAt: "2026-03-03T00:00:00.000Z" });
    d["gina@example.test"] = googleUser({ decidedAt: "2026-04-04T00:00:00.000Z" });
  });
  const r = await w.handler("admin-users")(ev("GET", undefined, w.cookie("root", "admin")));
  assert.equal(r.statusCode, 200);
  const list = json(r).users; assert.equal(list.length, 2);
  const alice = list.find((u) => u.username === "alice"); const gina = list.find((u) => u.username === "gina@example.test");
  assert.deepEqual(Object.keys(alice).sort(), ["createdAt", "decidedAt", "email", "name", "provider", "role", "status", "username"]);
  assert.equal(alice.provider, "password"); assert.equal(alice.email, "alice@example.test");
  assert.equal(alice.decidedAt, "2026-03-03T00:00:00.000Z");
  assert.equal(gina.provider, "google"); assert.equal(gina.email, "gina@example.test");
  const stored = w.fake.data().alice;
  for (const secret of [stored.salt, stored.passwordHash, "tok-secret", "sub-123", "googleSub", "resetToken", "passwordHash"]) {
    assert.equal(r.body.includes(secret), false, "leaked a secret field");
  }
});

test("admin-users: admin cookie required, GET only, malformed cookie is 403", async () => {
  const w = world(); const h = w.handler("admin-users");
  assert.equal((await h(ev("GET"))).statusCode, 403);
  assert.equal((await h(ev("GET", undefined, w.cookie("bob", "student")))).statusCode, 403);
  assert.equal((await h(ev("GET", undefined, "iphs_session=%E0%A4%A"))).statusCode, 403);
  assert.equal((await h(ev("POST", {}, w.cookie("root", "admin")))).statusCode, 405);
});

// ---------------------------------------------------------------- forgot-password

test("forgot-password: password account gets a reset token and one plain-text mail after commit", async () => {
  const w = world(); w.fake.raw((d) => { d.alice = w.pwUser("alice", "pw-pw-pw-1"); });
  const r = await w.handler("forgot-password")(ev("POST", { username: "Alice" }));
  assert.equal(r.statusCode, 200);
  assert.deepEqual(json(r), { message: "If that account exists, a reset link has been emailed to its registered contact." });
  const rec = w.fake.data().alice;
  assert.match(rec.resetToken, /^[a-f0-9]{64}$/);
  assert.ok(rec.resetTokenExpires > Date.now() + 25 * 60 * 1000 && rec.resetTokenExpires <= Date.now() + 31 * 60 * 1000);
  assert.equal(w.mails.length, 1); assert.equal(w.mails[0].to, "alice@example.test");
  assert.equal("html" in w.mails[0], false);
  assert.ok(w.mails[0].text.includes(rec.resetToken)); assert.ok(w.mails[0].text.includes("username=alice"));
});

test("forgot-password: unknown, empty, inherited and email-less users get the same generic 200 and no mail", async () => {
  const w = world(); w.fake.raw((d) => { d.noemail = w.pwUser("noemail", "pw-pw-pw-1", { email: undefined }); });
  const h = w.handler("forgot-password"); const bodies = new Set();
  for (const username of ["ghost", "", "__proto__", "constructor", "noemail"]) {
    const r = await h(ev("POST", { username })); assert.equal(r.statusCode, 200, username); bodies.add(r.body);
  }
  assert.equal(bodies.size, 1); assert.equal(w.mails.length, 0); assert.equal(w.fake.writes, 0);
});

test("forgot-password: Google-only record is a no-op with no write and no mail", async () => {
  const w = world(); w.fake.raw((d) => { d["gina@example.test"] = googleUser(); });
  const before = w.fake.data();
  const r = await w.handler("forgot-password")(ev("POST", { username: "gina@example.test" }));
  assert.equal(r.statusCode, 200);
  assert.deepEqual(w.fake.data(), before); assert.equal(w.fake.writes, 0); assert.equal(w.mails.length, 0);
});

test("forgot-password: a record that becomes Google-only before the CAS commit stays a no-op", async () => {
  const w = world(); w.fake.raw((d) => { d.alice = w.pwUser("alice", "pw-pw-pw-1"); });
  const g = googleUser({ username: "alice", email: "alice@example.test" });
  w.fake.beforeSet = async () => w.fake.raw((d) => { d.alice = g; });
  const r = await w.handler("forgot-password")(ev("POST", { username: "alice" }));
  assert.equal(r.statusCode, 200);
  assert.deepEqual(w.fake.data().alice, g); assert.equal(w.mails.length, 0);
});

test("forgot-password: mail failure still returns the generic 200", async () => {
  const w = world({ mail: async () => { throw new Error(LEAK); } });
  w.fake.raw((d) => { d.alice = w.pwUser("alice", "pw-pw-pw-1"); });
  const r = await w.handler("forgot-password")(ev("POST", { username: "alice" }));
  assert.equal(r.statusCode, 200);
  for (const line of w.logs) assert.doesNotMatch(line, new RegExp(`${LEAK}|alice`));
});

// ---------------------------------------------------------------- reset-password

test("reset-password: valid token updates the password, clears reset fields, and is single-use", async () => {
  const w = world();
  w.fake.raw((d) => { d.alice = w.pwUser("alice", "old-pass-1234", { resetToken: "tok-1", resetTokenExpires: future() }); });
  const h = w.handler("reset-password");
  let r = await h(ev("POST", { username: "alice", token: "tok-1", newPassword: NEW_PW }));
  assert.equal(r.statusCode, 200); assert.deepEqual(json(r), { message: "Password reset. You can now log in." });
  const rec = w.fake.data().alice;
  assert.equal("resetToken" in rec, false); assert.equal("resetTokenExpires" in rec, false);
  assert.equal(typeof rec.passwordChangedAt, "string");
  assert.equal(w.auth.verifyPassword(NEW_PW, rec.salt, rec.passwordHash), true);
  assert.equal(w.auth.verifyPassword("old-pass-1234", rec.salt, rec.passwordHash), false);
  r = await h(ev("POST", { username: "alice", token: "tok-1", newPassword: PW.reset1 }));
  assert.equal(r.statusCode, 400);
  assert.deepEqual(json(r), { error: "This reset link is invalid or has expired. Request a new one." });
  assert.equal(w.auth.verifyPassword(NEW_PW, w.fake.data().alice.salt, w.fake.data().alice.passwordHash), true);
});

test("reset-password: wrong token, expired token, unknown user and short password", async () => {
  const w = world();
  w.fake.raw((d) => {
    d.alice = w.pwUser("alice", "old-pass-1234", { resetToken: "tok-1", resetTokenExpires: future() });
    d.expired = w.pwUser("expired", "old-pass-1234", { resetToken: "tok-2", resetTokenExpires: Date.now() - 1000 });
  });
  const h = w.handler("reset-password"); const invalid = "This reset link is invalid or has expired. Request a new one.";
  for (const body of [{ username: "alice", token: "wrong" }, { username: "expired", token: "tok-2" }, { username: "ghost", token: "x" }, { username: "__proto__", token: "x" }, { username: "alice", token: "" }]) {
    const r = await h(ev("POST", { ...body, newPassword: NEW_PW })); assert.equal(r.statusCode, 400, JSON.stringify(body)); assert.equal(json(r).error, invalid);
  }
  assert.equal((await h(ev("POST", { username: "alice", token: "tok-1", newPassword: "short" }))).statusCode, 400);
  assert.equal(w.fake.writes, 0);
  assert.equal((await h(ev("GET"))).statusCode, 405);
});

test("reset-password: Google-only record gets the invalid-link response and is never given credentials", async () => {
  const w = world();
  w.fake.raw((d) => { d["gina@example.test"] = googleUser({ resetToken: "tok-g", resetTokenExpires: future() }); });
  const before = w.fake.data();
  const r = await w.handler("reset-password")(ev("POST", { username: "gina@example.test", token: "tok-g", newPassword: NEW_PW }));
  assert.equal(r.statusCode, 400);
  assert.deepEqual(json(r), { error: "This reset link is invalid or has expired. Request a new one." });
  assert.deepEqual(w.fake.data(), before);
});

test("reset-password: two concurrent resets with one token let exactly one win", async () => {
  const w = world();
  w.fake.raw((d) => { d.alice = w.pwUser("alice", "old-pass-1234", { resetToken: "tok-1", resetTokenExpires: future() }); });
  const reset = w.handler("reset-password"); let inner;
  w.fake.beforeSet = async () => { inner = await reset(ev("POST", { username: "alice", token: "tok-1", newPassword: PW.reset2 })); };
  const outer = await reset(ev("POST", { username: "alice", token: "tok-1", newPassword: PW.reset3 }));
  assert.equal(inner.statusCode, 200); assert.equal(outer.statusCode, 400);
  const rec = w.fake.data().alice;
  assert.equal(w.auth.verifyPassword("second-pass-22", rec.salt, rec.passwordHash), true);
  assert.equal(w.auth.verifyPassword("first-pass-111", rec.salt, rec.passwordHash), false);
});

// ---------------------------------------------------------------- change-password

test("change-password: password account changes the hash and keeps the existing responses", async () => {
  const w = world(); w.fake.raw((d) => { d.alice = w.pwUser("alice", "old-pass-1234"); });
  const r = await w.handler("change-password")(ev("POST", { currentPassword: PW.current, newPassword: NEW_PW }, w.cookie("alice")));
  assert.equal(r.statusCode, 200); assert.deepEqual(json(r), { message: "Password changed." });
  const rec = w.fake.data().alice;
  assert.equal(w.auth.verifyPassword(NEW_PW, rec.salt, rec.passwordHash), true);
  assert.equal(typeof rec.passwordChangedAt, "string");
});

test("change-password: wrong current password is 403 and the record is unchanged", async () => {
  const w = world(); const alice = w.pwUser("alice", "old-pass-1234"); w.fake.raw((d) => { d.alice = alice; });
  const r = await w.handler("change-password")(ev("POST", { currentPassword: PW.badCurrent, newPassword: NEW_PW }, w.cookie("alice")));
  assert.equal(r.statusCode, 403); assert.deepEqual(json(r), { error: "Current password is incorrect." });
  assert.deepEqual(w.fake.data().alice, alice);
});

test("change-password: Google-only account gets 403 with the fixed message and no credential creation", async () => {
  const w = world(); const g = googleUser(); w.fake.raw((d) => { d[g.username] = g; });
  const r = await w.handler("change-password")(ev("POST", { currentPassword: PW.anything, newPassword: NEW_PW }, w.cookie(g.username)));
  assert.equal(r.statusCode, 403); assert.deepEqual(json(r), { error: "This account uses Google sign-in." });
  assert.deepEqual(w.fake.data()[g.username], g); assert.equal(w.fake.writes, 0);
});

test("change-password: session checks, missing user and validation", async () => {
  const w = world(); const h = w.handler("change-password"); const body = { currentPassword: "x", newPassword: NEW_PW };
  assert.equal((await h(ev("GET"))).statusCode, 405);
  assert.equal((await h(ev("POST", body))).statusCode, 401);
  assert.equal((await h(ev("POST", body, "iphs_session=%E0%A4%A"))).statusCode, 401);
  assert.equal((await h(ev("POST", body, "iphs_session=garbage.sig"))).statusCode, 401);
  assert.equal((await h(ev("POST", body, w.cookie("ghost")))).statusCode, 404);
  assert.equal((await h(ev("POST", "{bad", w.cookie("ghost")))).statusCode, 400);
  assert.equal((await h(ev("POST", { ...body, newPassword: "short" }, w.cookie("ghost")))).statusCode, 400);
});

test("change-password: the latest current password is rechecked after a CAS conflict", async () => {
  const w = world(); w.fake.raw((d) => { d.alice = w.pwUser("alice", "old-pass-1234"); });
  const change = w.handler("change-password"); let inner;
  w.fake.beforeSet = async () => { inner = await change(ev("POST", { currentPassword: PW.current, newPassword: PW.concurrent }, w.cookie("alice"))); };
  const outer = await change(ev("POST", { currentPassword: PW.current, newPassword: PW.reset3 }, w.cookie("alice")));
  assert.equal(inner.statusCode, 200); assert.equal(outer.statusCode, 403);
  const rec = w.fake.data().alice;
  assert.equal(w.auth.verifyPassword("concurrent-pass-2", rec.salt, rec.passwordHash), true);
});

// ---------------------------------------------------------------- session

test("session: no cookie and bad cookies are unauthenticated without exception or Set-Cookie", async () => {
  const w = world(); const h = w.handler("session");
  const good = w.cookie("alice").replace(/.$/, (c) => (c === "A" ? "B" : "A"));
  for (const cookie of [undefined, "iphs_session=%E0%A4%A", "iphs_session=garbage.sig", "iphs_session=nodot", good]) {
    const r = await h(ev("GET", undefined, cookie));
    assert.equal(r.statusCode, 200, String(cookie)); assert.deepEqual(json(r), { authenticated: false });
    assert.equal(hdr(r, "Set-Cookie"), undefined);
  }
});

test("session: approved password account returns username, the cookie's role, provider and canUsePassword", async () => {
  const w = world(); w.fake.raw((d) => { d.alice = w.pwUser("alice", "pw-pw-pw-1", { role: "student" }); });
  const r = await w.handler("session")(ev("GET", undefined, w.cookie("alice", "admin")));
  assert.equal(r.statusCode, 200);
  assert.deepEqual(json(r), { authenticated: true, username: "alice", role: "admin", provider: "password", canUsePassword: true });
});

test("session: approved Google account reports provider google and canUsePassword false", async () => {
  const w = world(); const g = googleUser(); w.fake.raw((d) => { d[g.username] = g; });
  const r = await w.handler("session")(ev("GET", undefined, w.cookie(g.username)));
  assert.deepEqual(json(r), { authenticated: true, username: g.username, role: "student", provider: "google", canUsePassword: false });
});

test("session: stale cookie for a missing, pending, rejected or unknown-status user is unauthenticated and cleared", async () => {
  const w = world();
  w.fake.raw((d) => {
    d.p = w.pwUser("p", "pw-pw-pw-1", { status: "pending" });
    d.r = w.pwUser("r", "pw-pw-pw-1", { status: "rejected" });
    d.u = w.pwUser("u", "pw-pw-pw-1", { status: "weird" });
  });
  const h = w.handler("session");
  for (const sub of ["gone", "p", "r", "u", "__proto__", "constructor"]) {
    const r = await h(ev("GET", undefined, w.cookie(sub)));
    assert.equal(r.statusCode, 200, sub); assert.deepEqual(json(r), { authenticated: false }, sub);
    assert.match(hdr(r, "Set-Cookie"), /^iphs_session=; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=0$/, sub);
  }
});

test("session: cookie present but SESSION_SECRET absent is a configuration 503, never authenticated", async () => {
  const w = world(); w.fake.raw((d) => { d.alice = w.pwUser("alice", "pw-pw-pw-1"); });
  const cookie = w.cookie("alice");
  delete w.env.SESSION_SECRET;
  const r = await w.handler("session")(ev("GET", undefined, cookie));
  assert.equal(r.statusCode, 503); assert.equal(hdr(r, "Cache-Control"), "no-store");
  assert.notEqual(json(r).authenticated, true);
  const none = await w.handler("session")(ev("GET"));
  assert.deepEqual(json(none), { authenticated: false });
  const c = await w.handler("change-password")(ev("POST", { currentPassword: "x", newPassword: NEW_PW }, cookie));
  assert.equal(c.statusCode, 503);
  const a = await w.handler("admin-users")(ev("GET", undefined, cookie));
  assert.equal(a.statusCode, 503);
});

test("session: POST is 405", async () => {
  const w = world();
  assert.equal((await w.handler("session")(ev("POST", {}))).statusCode, 405);
});

// ---------------------------------------------------------------- logout

test("logout: clears the session cookie, sets no-store, and does not touch the user store", async () => {
  const w = world(); const h = w.handler("logout");
  const r = await h(ev("POST", {}));
  assert.equal(r.statusCode, 200); assert.deepEqual(json(r), { message: "Logged out." });
  assert.match(hdr(r, "Set-Cookie"), /^iphs_session=; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=0$/);
  assert.equal(hdr(r, "Cache-Control"), "no-store");
  assert.equal(w.storeUses(), 0);
  assert.equal((await h(ev("GET"))).statusCode, 405);
});

// ---------------------------------------------------------------- storage failure

test("storage failure maps to a generic 503 with no-store and leaks nothing, in every handler that reads", async () => {
  const cases = [
    ["login", ev("POST", { username: "a", password: "x" })],
    ["register", ev("POST", REG), { ADMIN_NOTIFY_EMAIL: "notify@example.test" }],
    ["forgot-password", ev("POST", { username: "alice" })],
    ["reset-password", ev("POST", { username: "alice", token: "t", newPassword: NEW_PW })],
    ["change-password", (w) => ev("POST", { currentPassword: "x", newPassword: NEW_PW }, w.cookie("alice"))],
    ["admin-bootstrap", ev("POST", BOOT), { ADMIN_BOOTSTRAP_SECRET: "bootstrap-secret" }],
    ["admin-decide", (w) => ev("POST", { username: "alice", action: "approve" }, w.cookie("root", "admin"))],
    ["admin-users", (w) => ev("GET", undefined, w.cookie("root", "admin"))],
    ["session", (w) => ev("GET", undefined, w.cookie("alice"))],
  ];
  for (const [name, makeEvent, env] of cases) {
    const w = world({ env: env || {} }); w.fake.raw((d) => { d.alice = w.pwUser("alice", "pw-pw-pw-1"); });
    w.fake.failGet = true;
    const r = await w.handler(name)(typeof makeEvent === "function" ? makeEvent(w) : makeEvent);
    assert.equal(r.statusCode, 503, name);
    assert.equal(hdr(r, "Cache-Control"), "no-store", name);
    assert.equal(typeof json(r).error, "string", name);
    assert.equal(r.body.includes(LEAK), false, name);
    for (const line of w.logs) assert.equal(line.includes(LEAK), false, `${name} logged the exception`);
    assert.equal(w.mails.length, 0, name);
  }
});

test("retry exhaustion maps to 503 and no change is reported as success", async () => {
  const w = world(); w.fake.raw((d) => { d.alice = w.pwUser("alice", "pw-pw-pw-1", { resetToken: "t", resetTokenExpires: future() }); });
  w.fake.setJSON = async () => { w.fake.setCalls++; return { modified: false }; };
  const r = await w.handler("reset-password")(ev("POST", { username: "alice", token: "t", newPassword: NEW_PW }));
  assert.equal(r.statusCode, 503); assert.equal(hdr(r, "Cache-Control"), "no-store");
  assert.equal(w.fake.writes, 0);
});

// ---------------------------------------------------------------- mail helper

function loadMail(env, fetchImpl) {
  const logs = []; const sink = (...a) => logs.push(a.map(String).join(" "));
  const sandbox = { process: { env }, console: { log: sink, warn: sink, error: sink, info: sink }, fetch: fetchImpl, AbortSignal, JSON, String, Array, Promise };
  return { mail: loadCjs("util/mail.js", sandbox, {}), logs };
}
const okFetch = (calls, ok = true) => async (url, init) => {
  calls.push({ url, init }); return { ok, status: ok ? 200 : 422, body: { cancel: async () => {} }, text: async () => "provider-body-secret" };
};

test("mail: missing API key skips without fetch or logging the subject", async () => {
  const calls = []; const { mail, logs } = loadMail({}, okFetch(calls));
  assert.deepEqual({ ...(await mail.sendMail({ to: "a@example.test", subject: "secret subject", text: "x" })) }, { skipped: true });
  assert.equal(calls.length, 0); assert.equal(logs.join("").includes("secret subject"), false);
});

test("mail: sends plain text only, sanitises the subject and bounds the request", async () => {
  const calls = []; const { mail } = loadMail({ RESEND_API_KEY: "k-test" }, okFetch(calls));
  const res = await mail.sendMail({ to: "a@example.test", subject: "Hi\r\nBcc: x\u0000" + "y".repeat(300), html: "<b>x</b>", text: "plain" });
  assert.equal(res.ok, true); assert.equal(calls.length, 1);
  const { url, init } = calls[0]; const body = JSON.parse(init.body);
  assert.equal(url, "https://api.resend.com/emails"); assert.equal(init.method, "POST"); assert.equal(init.redirect, "error");
  assert.ok(init.signal); assert.equal(init.headers.Authorization, "Bearer k-test");
  assert.equal(body.from, "onboarding@resend.dev"); assert.deepEqual([...body.to], ["a@example.test"]);
  assert.equal("html" in body, false); assert.equal(body.text, "plain");
  assert.doesNotMatch(body.subject, /[\x00-\x1f\x7f]/); assert.ok(body.subject.length <= 200);
});

test("mail: invalid recipient or sender is rejected without a request", async () => {
  const calls = []; const { mail, logs } = loadMail({ RESEND_API_KEY: "k-test" }, okFetch(calls));
  for (const to of ["not-an-address", "a@b.c\r\nBcc: x@y.z", [], ["a@example.test", 5], "x".repeat(260) + "@example.test"]) {
    const res = await mail.sendMail({ to, subject: "s", text: "t" }); assert.equal(res.ok, false);
  }
  const bad = loadMail({ RESEND_API_KEY: "k", MAIL_FROM: "a@b.c\r\nBcc: x@y.z" }, okFetch(calls));
  assert.equal((await bad.mail.sendMail({ to: "a@example.test", subject: "s", text: "t" })).ok, false);
  assert.equal(calls.length, 0); assert.ok(logs.length > 0);
});

test("mail: provider failure and thrown errors log fixed labels only", async () => {
  const calls = []; const failed = loadMail({ RESEND_API_KEY: "k-test" }, okFetch(calls, false));
  let res = await failed.mail.sendMail({ to: "a@example.test", subject: "private subject", text: "t" });
  assert.equal(res.ok, false); assert.equal(res.status, 422);
  const thrown = loadMail({ RESEND_API_KEY: "k-test" }, async () => { throw new Error("a@example.test " + LEAK); });
  res = await thrown.mail.sendMail({ to: "a@example.test", subject: "private subject", text: "t" });
  assert.equal(res.ok, false);
  for (const line of [...failed.logs, ...thrown.logs]) {
    assert.doesNotMatch(line, /provider-body-secret|private subject|example\.test/); assert.equal(line.includes(LEAK), false);
  }
  assert.ok(failed.logs.length > 0 && thrown.logs.length > 0);
});
