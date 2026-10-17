import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

// The adapter is loaded with a mocked SDK so this suite needs no installed
// dependency and never touches the real Netlify Blobs service.
function loadAdapter(sdk, env = {}, extraGlobals = {}) {
  const source = fs.readFileSync(new URL("../../netlify/functions/util/users-store.js", import.meta.url), "utf8");
  const module = { exports: {} };
  vm.runInNewContext(`(function(require, module, exports) {\n${source}\n})`,
    { process: { env }, setTimeout, ...extraGlobals })((name) => {
      assert.equal(name, "@netlify/blobs"); return sdk;
    }, module, module.exports);
  return module.exports;
}
const adapter = loadAdapter({});
function fakeStore(initial = null) {
  let data = initial && structuredClone(initial); let version = initial ? 1 : 0;
  return {
    async getWithMetadata(key, options) {
      assert.equal(key, "users.json"); assert.equal(options.consistency, "strong"); assert.equal(options.type, "json");
      return data === null ? null : { data: structuredClone(data), etag: String(version) };
    },
    async setJSON(key, next, condition) {
      assert.equal(key, "users.json");
      if ((condition.onlyIfNew && data !== null) || (condition.onlyIfMatch && condition.onlyIfMatch !== String(version)))
        return { modified: false };
      data = structuredClone(next); version++;
      return { modified: true, etag: String(version) };
    },
  };
}

test("legacy initialization uses event before store creation", () => {
  const calls = []; const store = fakeStore(); const event = { blobs: "placeholder" };
  const a = loadAdapter({
    connectLambda: (seen) => { assert.equal(seen, event); calls.push("connect"); },
    getStore: (options) => { assert.equal(options.consistency, "strong"); calls.push("store"); return store; },
  });
  a.usersStore(event);
  assert.deepEqual(calls, ["connect", "store"]);
});

test("production path: automatic request context, store name users, strong consistency, no explicit credentials", () => {
  const seen = []; const event = { blobs: "placeholder" };
  const a = loadAdapter({
    connectLambda: () => seen.push("connect"),
    getStore: (options) => { seen.push(options); return fakeStore(); },
  }, { SITE_ID: "", BLOBS_TOKEN: "" });
  a.usersStore(event);
  assert.equal(seen[0], "connect");
  assert.equal(seen[1].name, "users");
  assert.equal(seen[1].consistency, "strong");
  assert.equal("siteID" in seen[1], false);
  assert.equal("token" in seen[1], false);
});

test("explicit SITE_ID and BLOBS_TOKEN pair is used only when both are set, without connectLambda", () => {
  const seen = [];
  const sdk = {
    connectLambda: () => seen.push("connect"),
    getStore: (options) => { seen.push(options); return fakeStore(); },
  };
  loadAdapter(sdk, { SITE_ID: "site-placeholder", BLOBS_TOKEN: "token-placeholder" }).usersStore({});
  assert.equal(seen.length, 1);
  assert.deepEqual({ ...seen[0] }, { name: "users", siteID: "site-placeholder", token: "token-placeholder", consistency: "strong" });
  // Only one of the pair set: fall back to the automatic request context.
  seen.length = 0;
  loadAdapter(sdk, { SITE_ID: "site-placeholder" }).usersStore({});
  assert.equal(seen[0], "connect");
  assert.equal(seen[1].siteID, undefined);
  seen.length = 0;
  loadAdapter(sdk, { BLOBS_TOKEN: "token-placeholder" }).usersStore({});
  assert.equal(seen[0], "connect");
  assert.equal(seen[1].token, undefined);
});

test("store construction is request-scoped: nothing is created at module load, each call builds a new store", () => {
  let created = 0;
  const sdk = {
    connectLambda: () => {},
    getStore: () => { created++; return fakeStore(); },
  };
  const a = loadAdapter(sdk);
  assert.equal(created, 0);
  const r1 = a.usersStore({}); const r2 = a.usersStore({});
  assert.equal(created, 2);
  assert.notEqual(r1, r2);
  assert.equal(typeof r1.loadUsers, "function");
  assert.equal(typeof r1.mutateUsers, "function");
});

test("exports: usersStore, createRepository, UsersStoreError; old saveUsers and loadUsers are gone", () => {
  assert.deepEqual(Object.keys(adapter).sort(), ["UsersStoreError", "createRepository", "usersStore"]);
  assert.equal(adapter.saveUsers, undefined);
  assert.equal(adapter.loadUsers, undefined);
  const repo = adapter.createRepository(fakeStore());
  assert.deepEqual(Object.keys(repo).sort(), ["loadUsers", "mutateUsers"]);
  const err = new adapter.UsersStoreError("store_data");
  assert.equal(err.code, "store_data");
  assert.equal(err.message, "store_data");
  assert.equal(Object.prototype.toString.call(err), "[object Error]"); // vm realm: instanceof would be cross-realm
});

test("data shape: missing blob yields an empty null-prototype map; existing map keyed by username is preserved", async () => {
  const empty = await adapter.createRepository(fakeStore()).loadUsers();
  assert.equal(Object.keys(empty).length, 0);
  assert.equal(Object.getPrototypeOf(empty), null);
  const seeded = { alice: { username: "alice", status: "approved" }, bob: { username: "bob", status: "pending" } };
  const users = await adapter.createRepository(fakeStore(seeded)).loadUsers();
  assert.equal(Object.getPrototypeOf(users), null);
  assert.deepEqual(Object.keys(users).sort(), ["alice", "bob"]);
  assert.equal(users.alice.status, "approved");
  assert.equal(users.constructor, undefined);
  assert.equal(users.__proto__, undefined);
});

test("first write uses onlyIfNew; later writes use onlyIfMatch with the read ETag; key is users.json", async () => {
  const conditions = [];
  const store = fakeStore(); const original = store.setJSON.bind(store);
  store.setJSON = async (key, data, condition) => { conditions.push({ key, condition: { ...condition } }); return original(key, data, condition); };
  const repository = adapter.createRepository(store);
  await repository.mutateUsers((users) => { users.a = { username: "a" }; return { changed: true, value: 1 }; });
  await repository.mutateUsers((users) => { users.b = { username: "b" }; return { changed: true, value: 2 }; });
  assert.deepEqual(conditions, [
    { key: "users.json", condition: { onlyIfNew: true } },
    { key: "users.json", condition: { onlyIfMatch: "1" } },
  ]);
  assert.deepEqual(Object.keys(await repository.loadUsers()).sort(), ["a", "b"]);
});

test("every read asks for json type and strong consistency (loadUsers and mutateUsers)", async () => {
  const seenOptions = [];
  const base = fakeStore({ a: { username: "a" } }); const original = base.getWithMetadata.bind(base);
  base.getWithMetadata = async (key, options) => { seenOptions.push({ ...options }); return original(key, options); };
  const repository = adapter.createRepository(base);
  await repository.loadUsers();
  await repository.mutateUsers(() => ({ changed: false, value: null }));
  assert.deepEqual(seenOptions, [
    { type: "json", consistency: "strong" },
    { type: "json", consistency: "strong" },
  ]);
});

test("each retry re-reads and re-runs the mutator against the latest data; attempts are bounded", async () => {
  const store = fakeStore({ n: { count: 0 } });
  const original = store.setJSON.bind(store); let bumps = 0;
  store.setJSON = async (key, data, condition) => {
    // Competing writer lands first on the first two attempts.
    if (bumps < 2) { bumps++; await original(key, { n: { count: 100 * bumps } }, { onlyIfMatch: condition.onlyIfMatch }); }
    return original(key, data, condition);
  };
  const seen = [];
  const repository = adapter.createRepository(store, 5);
  await repository.mutateUsers((users) => { seen.push(users.n.count); users.n.count += 1; return { changed: true, value: null }; });
  assert.deepEqual(seen, [0, 100, 200]);
  assert.equal((await repository.loadUsers()).n.count, 201);
});

test("conflict exhaustion throws store_conflict after exactly maxAttempts writes and never reports success", async () => {
  const store = fakeStore({ a: { username: "a" } }); let writes = 0; let reads = 0;
  const get = store.getWithMetadata.bind(store);
  store.getWithMetadata = async (...args) => { reads++; return get(...args); };
  store.setJSON = async () => { writes++; return { modified: false }; };
  const repository = adapter.createRepository(store, 3);
  await assert.rejects(repository.mutateUsers((u) => { u.b = { username: "b" }; return { changed: true, value: "ok" }; }), { code: "store_conflict" });
  assert.equal(writes, 3);
  assert.equal(reads, 3);
  // The backing data was never changed because no write succeeded.
  assert.deepEqual(Object.keys(await adapter.createRepository(store).loadUsers()), ["a"]);
});

test("a mutator that throws propagates and performs no write", async () => {
  const store = fakeStore({ a: { username: "a" } }); let writes = 0;
  store.setJSON = async () => { writes++; return { modified: true }; };
  const boom = new Error("precondition failed");
  await assert.rejects(adapter.createRepository(store).mutateUsers(() => { throw boom; }), boom);
  assert.equal(writes, 0);
});

test("mutation is synchronous and side-effect free: no mail or network call during retries", async () => {
  const calls = [];
  const a = loadAdapter({}, {}, { fetch: (...args) => { calls.push(args); throw new Error("network"); } });
  const store = fakeStore({ a: { username: "a" } });
  const original = store.setJSON.bind(store); let injected = false;
  store.setJSON = async (key, data, condition) => {
    if (!injected) { injected = true; await original(key, { a: { username: "a", n: 1 } }, { onlyIfMatch: condition.onlyIfMatch }); }
    return original(key, data, condition);
  };
  let runs = 0; let mails = 0;
  const value = await a.createRepository(store).mutateUsers((users) => { runs++; users.a.seen = true; return { changed: true, value: "token" }; });
  // Caller sends mail only after mutateUsers resolves; the adapter itself never does.
  mails++;
  assert.equal(value, "token");
  assert.equal(runs, 2);
  assert.equal(mails, 1);
  assert.equal(calls.length, 0);
});

test("async or malformed mutator results are rejected with store_mutator before any write", async () => {
  const store = fakeStore(); let writes = 0;
  store.setJSON = async () => { writes++; return { modified: true }; };
  const repository = adapter.createRepository(store);
  await assert.rejects(repository.mutateUsers(async () => ({ changed: true })), { code: "store_mutator" });
  await assert.rejects(repository.mutateUsers(() => undefined), { code: "store_mutator" });
  await assert.rejects(repository.mutateUsers(() => ({ value: 1 })), { code: "store_mutator" });
  await assert.rejects(repository.mutateUsers(() => ({ changed: "yes", value: 1 })), { code: "store_mutator" });
  assert.equal(writes, 0);
});

test("malformed SDK write result fails with store_api", async () => {
  const store = fakeStore(); store.setJSON = async () => ({});
  await assert.rejects(adapter.createRepository(store).mutateUsers(() => ({ changed: true, value: 1 })), { code: "store_api" });
});

test("invalid stored data (array, scalar, missing ETag) fails closed with store_data", async () => {
  for (const snapshot of [{ data: [], etag: "1" }, { data: "x", etag: "1" }, { data: null, etag: "1" }, { data: {}, etag: "" }, { data: {} }]) {
    await assert.rejects(adapter.createRepository({ getWithMetadata: async () => snapshot }).loadUsers(), { code: "store_data" });
  }
});

test("concurrent creations preserve both users via CAS retry", async () => {
  const repository = adapter.createRepository(fakeStore());
  let attempts = 0;
  await Promise.all(["one", "two"].map((username) => repository.mutateUsers((users) => {
    attempts++; users[username] = { username }; return { changed: true, value: username };
  })));
  assert.deepEqual(Object.keys(await repository.loadUsers()).sort(), ["one", "two"]);
  assert.ok(attempts >= 3);
});

test("conflict retry rechecks latest rejection rather than restoring approval", async () => {
  const store = fakeStore({ student: { status: "approved" } });
  const original = store.setJSON.bind(store); let inject = true;
  store.setJSON = async (key, data, condition) => {
    if (inject) { inject = false; await original(key, { student: { status: "rejected" } }, { onlyIfMatch: "1" }); }
    return original(key, data, condition);
  };
  const repository = adapter.createRepository(store);
  const status = await repository.mutateUsers((users) => {
    users.student.lastLoginAt = "placeholder";
    return { changed: true, value: users.student.status };
  });
  assert.equal(status, "rejected");
  assert.equal((await repository.loadUsers()).student.status, "rejected");
});

test("no-op does not write; conflict exhaustion and invalid store data fail", async () => {
  const store = fakeStore(); let writes = 0;
  store.setJSON = async () => { writes++; return { modified: false }; };
  const repository = adapter.createRepository(store, 2);
  assert.equal(await repository.mutateUsers(() => ({ changed: false, value: "none" })), "none");
  assert.equal(writes, 0);
  await assert.rejects(repository.mutateUsers(() => ({ changed: true, value: "none" })), { code: "store_conflict" });
  assert.equal(writes, 2);
  await assert.rejects(adapter.createRepository({ getWithMetadata: async () => ({ data: [], etag: "1" }) }).loadUsers(),
    { code: "store_data" });
  await assert.rejects(repository.mutateUsers(async () => ({ changed: true })), { code: "store_mutator" });
});
