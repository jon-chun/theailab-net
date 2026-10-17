const { connectLambda, getStore } = require("@netlify/blobs");
const KEY = "users.json";

class UsersStoreError extends Error {
  constructor(code) { super(code); this.code = code; }
}
function checkedUsers(snapshot) {
  if (!snapshot) return Object.create(null);
  if (!snapshot.data || typeof snapshot.data !== "object" || Array.isArray(snapshot.data) ||
      typeof snapshot.etag !== "string" || !snapshot.etag) throw new UsersStoreError("store_data");
  return Object.assign(Object.create(null), snapshot.data);
}
function createRepository(store, maxAttempts = 5) {
  async function snapshot() {
    return store.getWithMetadata(KEY, { type: "json", consistency: "strong" });
  }
  async function loadUsers() { return checkedUsers(await snapshot()); }
  async function mutateUsers(mutator) {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const current = await snapshot();
      const users = checkedUsers(current);
      const result = mutator(users);
      if (!result || typeof result.changed !== "boolean" || typeof result.then === "function")
        throw new UsersStoreError("store_mutator");
      if (!result.changed) return result.value;
      const condition = current ? { onlyIfMatch: current.etag } : { onlyIfNew: true };
      const written = await store.setJSON(KEY, users, condition);
      if (!written || typeof written.modified !== "boolean") throw new UsersStoreError("store_api");
      if (written.modified) return result.value;
      if (attempt + 1 < maxAttempts) {
        await new Promise((resolve) => setTimeout(resolve, 10 * (attempt + 1)));
      }
    }
    throw new UsersStoreError("store_conflict");
  }
  return { loadUsers, mutateUsers };
}
function usersStore(event) {
  const siteID = process.env.SITE_ID;
  const token = process.env.BLOBS_TOKEN;
  let store;
  if (siteID && token) {
    store = getStore({ name: "users", siteID, token, consistency: "strong" });
  } else {
    connectLambda(event);
    store = getStore({ name: "users", consistency: "strong" });
  }
  return createRepository(store);
}
module.exports = { usersStore, createRepository, UsersStoreError };
