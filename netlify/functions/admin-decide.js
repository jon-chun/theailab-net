const { usersStore } = require("./util/users-store");
const { SESSION_COOKIE, parseCookies, verify } = require("./util/auth");

const VALID_ACTIONS = new Set(["approve", "reject"]);

// Guarded session read: malformed cookies are unauthenticated; a supplied cookie with no
// configured secret is a configuration error, never an authenticated response.
function readSession(event) {
  const headers = (event && event.headers) || {};
  const header = headers.cookie || headers.Cookie;
  if (!header) return { session: null };
  let token;
  try {
    token = parseCookies(header)[SESSION_COOKIE];
  } catch {
    return { session: null };
  }
  if (!token) return { session: null };
  if (!process.env.SESSION_SECRET) return { unavailable: true };
  try {
    const session = verify(token);
    if (!session || typeof session !== "object" || typeof session.sub !== "string") return { session: null };
    return { session };
  } catch {
    return { session: null };
  }
}

const unavailable = () => ({
  statusCode: 503,
  headers: { "Cache-Control": "no-store" },
  body: JSON.stringify({ error: "Service temporarily unavailable. Try again shortly." }),
});

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const read = readSession(event);
  if (read.unavailable) {
    console.error("admin-decide: configuration_unavailable");
    return unavailable();
  }
  const session = read.session;
  if (!session || session.role !== "admin") {
    return { statusCode: 403, body: JSON.stringify({ error: "Admin access required." }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid JSON" }) };
  }

  const username = String(body.username || "").trim().toLowerCase();
  const action = String(body.action || "");

  if (!VALID_ACTIONS.has(action)) {
    return { statusCode: 400, body: JSON.stringify({ error: "action must be 'approve' or 'reject'." }) };
  }

  const target = action === "approve" ? "approved" : "rejected";
  const decidedAt = new Date().toISOString(); // prepared outside the CAS mutator

  let found;
  try {
    const repository = usersStore(event);
    found = await repository.mutateUsers((users) => {
      const user = Object.hasOwn(users, username) ? users[username] : undefined;
      if (!user) return { changed: false, value: false };
      if (user.status === target) return { changed: false, value: true }; // already in state: no-op
      user.status = target;
      user.decidedAt = decidedAt;
      return { changed: true, value: true };
    });
  } catch {
    console.error("admin-decide: storage_unavailable");
    return unavailable();
  }

  if (!found) {
    return { statusCode: 404, body: JSON.stringify({ error: "User not found." }) };
  }
  return { statusCode: 200, body: JSON.stringify({ message: `User ${username} ${target}.` }) };
};
