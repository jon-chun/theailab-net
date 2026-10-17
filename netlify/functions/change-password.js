const { usersStore } = require("./util/users-store");
const {
  SESSION_COOKIE, parseCookies, verify, verifyPassword, hashPassword, hasPasswordCredentials,
} = require("./util/auth");

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
    console.error("change-password: configuration_unavailable");
    return unavailable();
  }
  const session = read.session;
  if (!session) {
    return { statusCode: 401, body: JSON.stringify({ error: "Not logged in." }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid JSON" }) };
  }

  const currentPassword = String(body.currentPassword || "");
  const newPassword = String(body.newPassword || "");

  if (newPassword.length < 8) {
    return { statusCode: 400, body: JSON.stringify({ error: "New password must be at least 8 characters." }) };
  }

  // Prepared outside the CAS mutator.
  const { salt, hash } = hashPassword(newPassword);
  const changedAt = new Date().toISOString();

  let outcome;
  try {
    const repository = usersStore(event);
    outcome = await repository.mutateUsers((users) => {
      const user = Object.hasOwn(users, session.sub) ? users[session.sub] : undefined;
      if (!user) return { changed: false, value: { status: 404, error: "Account not found." } };
      if (!hasPasswordCredentials(user)) {
        const message = user.provider === "google" ? "This account uses Google sign-in." : "Current password is incorrect.";
        return { changed: false, value: { status: 403, error: message } };
      }
      // Verified against the latest record, so a conflict retry rechecks the current password.
      if (!verifyPassword(currentPassword, user.salt, user.passwordHash)) {
        return { changed: false, value: { status: 403, error: "Current password is incorrect." } };
      }
      user.salt = salt;
      user.passwordHash = hash;
      user.passwordChangedAt = changedAt;
      return { changed: true, value: { status: 200, message: "Password changed." } };
    });
  } catch {
    console.error("change-password: storage_unavailable");
    return unavailable();
  }

  if (outcome.status !== 200) {
    return { statusCode: outcome.status, body: JSON.stringify({ error: outcome.error }) };
  }
  return { statusCode: 200, body: JSON.stringify({ message: outcome.message }) };
};
