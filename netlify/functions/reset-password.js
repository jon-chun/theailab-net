const { usersStore } = require("./util/users-store");
const { hashPassword, hasPasswordCredentials } = require("./util/auth");

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
  const token = String(body.token || "");
  const newPassword = String(body.newPassword || "");

  if (newPassword.length < 8) {
    return { statusCode: 400, body: JSON.stringify({ error: "New password must be at least 8 characters." }) };
  }

  const invalidResponse = {
    statusCode: 400,
    body: JSON.stringify({ error: "This reset link is invalid or has expired. Request a new one." }),
  };

  // Prepared outside the CAS mutator.
  const { salt, hash } = hashPassword(newPassword);
  const changedAt = new Date().toISOString();

  let reset;
  try {
    const repository = usersStore(event);
    reset = await repository.mutateUsers((users) => {
      const user = Object.hasOwn(users, username) ? users[username] : undefined;
      if (!user || !hasPasswordCredentials(user)) return { changed: false, value: false };
      if (typeof user.resetToken !== "string" || !user.resetToken || !user.resetTokenExpires) return { changed: false, value: false };
      if (user.resetToken !== token) return { changed: false, value: false };
      if (Date.now() > user.resetTokenExpires) return { changed: false, value: false };
      user.salt = salt;
      user.passwordHash = hash;
      user.passwordChangedAt = changedAt;
      delete user.resetToken;
      delete user.resetTokenExpires;
      return { changed: true, value: true };
    });
  } catch {
    console.error("reset-password: storage_unavailable");
    return {
      statusCode: 503,
      headers: { "Cache-Control": "no-store" },
      body: JSON.stringify({ error: "Service temporarily unavailable. Try again shortly." }),
    };
  }

  if (!reset) return invalidResponse;
  return { statusCode: 200, body: JSON.stringify({ message: "Password reset. You can now log in." }) };
};
