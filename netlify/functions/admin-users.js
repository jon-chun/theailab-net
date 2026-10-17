const { usersStore } = require("./util/users-store");
const { SESSION_COOKIE, parseCookies, verify } = require("./util/auth");

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
  if (event.httpMethod !== "GET") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const read = readSession(event);
  if (read.unavailable) {
    console.error("admin-users: configuration_unavailable");
    return unavailable();
  }
  const session = read.session;
  if (!session || session.role !== "admin") {
    return { statusCode: 403, body: JSON.stringify({ error: "Admin access required." }) };
  }

  let users;
  try {
    const repository = usersStore(event);
    users = await repository.loadUsers();
  } catch {
    console.error("admin-users: storage_unavailable");
    return unavailable();
  }

  // Explicit allow-list: no hashes, salts, reset fields, tokens or Google subject.
  const list = Object.values(users).map((u) => ({
    username: u.username,
    name: u.name,
    email: u.email,
    status: u.status,
    role: u.role,
    provider: typeof u.provider === "string" && u.provider ? u.provider : "password",
    createdAt: u.createdAt,
    decidedAt: u.decidedAt,
  }));

  return { statusCode: 200, body: JSON.stringify({ users: list }) };
};
