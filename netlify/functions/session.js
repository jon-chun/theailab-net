const { usersStore } = require("./util/users-store");
const { SESSION_COOKIE, parseCookies, verify, clearSessionCookie, hasPasswordCredentials } = require("./util/auth");

const NO_STORE = { "Cache-Control": "no-store" };

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

exports.handler = async (event) => {
  if (event.httpMethod !== "GET") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const read = readSession(event);
  if (read.unavailable) {
    console.error("session: configuration_unavailable");
    return { statusCode: 503, headers: NO_STORE, body: JSON.stringify({ error: "Service temporarily unavailable. Try again shortly." }) };
  }
  const session = read.session;
  if (!session) {
    return { statusCode: 200, body: JSON.stringify({ authenticated: false }) };
  }

  let user;
  try {
    const repository = usersStore(event);
    const users = await repository.loadUsers();
    user = Object.hasOwn(users, session.sub) ? users[session.sub] : undefined;
  } catch {
    console.error("session: storage_unavailable");
    return { statusCode: 503, headers: NO_STORE, body: JSON.stringify({ error: "Service temporarily unavailable. Try again shortly." }) };
  }

  if (!user || user.status !== "approved") {
    return {
      statusCode: 200,
      headers: { "Set-Cookie": clearSessionCookie() },
      body: JSON.stringify({ authenticated: false }),
    };
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      authenticated: true,
      username: session.sub,
      role: session.role,
      provider: user.provider === "google" ? "google" : "password",
      canUsePassword: hasPasswordCredentials(user),
    }),
  };
};
