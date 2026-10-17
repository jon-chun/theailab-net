const { usersStore } = require("./util/users-store");
const { verifyPassword, makeSessionCookie, hasPasswordCredentials } = require("./util/auth");

const ROLES = new Set(["student", "admin"]);

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid JSON" }) };
  }

  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");

  const invalidResponse = {
    statusCode: 401,
    body: JSON.stringify({ error: "Invalid username or password." }),
  };

  let user;
  try {
    const repository = usersStore(event);
    const users = await repository.loadUsers();
    user = Object.hasOwn(users, username) ? users[username] : undefined;
  } catch {
    console.error("login: storage_unavailable");
    return {
      statusCode: 503,
      headers: { "Cache-Control": "no-store" },
      body: JSON.stringify({ error: "Service temporarily unavailable. Try again shortly." }),
    };
  }

  if (!user) return invalidResponse;
  // Google-only (or malformed) records have no password to check: same 401.
  if (!hasPasswordCredentials(user)) return invalidResponse;
  if (!verifyPassword(password, user.salt, user.passwordHash)) return invalidResponse;

  if (user.status === "pending") {
    return { statusCode: 403, body: JSON.stringify({ error: "Your account is still pending admin approval." }) };
  }
  if (user.status === "rejected") {
    return { statusCode: 403, body: JSON.stringify({ error: "Your account request was not approved." }) };
  }
  // Only an exactly approved account with an expected role can receive a session.
  if (user.status !== "approved" || !ROLES.has(user.role)) {
    return { statusCode: 403, body: JSON.stringify({ error: "Your account cannot log in." }) };
  }

  return {
    statusCode: 200,
    headers: { "Set-Cookie": makeSessionCookie(user) },
    body: JSON.stringify({ message: "Logged in.", role: user.role }),
  };
};
