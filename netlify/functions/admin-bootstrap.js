const { usersStore } = require("./util/users-store");
const { hashPassword } = require("./util/auth");

const USERNAME_RE = /^[a-zA-Z0-9._-]{3,40}$/;
const RESERVED_USERNAMES = new Set(["__proto__", "constructor", "prototype"]);

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const bootstrapSecret = process.env.ADMIN_BOOTSTRAP_SECRET;
  if (!bootstrapSecret) {
    return { statusCode: 403, body: JSON.stringify({ error: "Bootstrap disabled." }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid JSON" }) };
  }

  if (body.secret !== bootstrapSecret) {
    return { statusCode: 403, body: JSON.stringify({ error: "Invalid bootstrap secret." }) };
  }

  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");
  const name = String(body.name || "").trim();

  if (!USERNAME_RE.test(username) || RESERVED_USERNAMES.has(username) || password.length < 8) {
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid username or password." }) };
  }

  // Prepared outside the CAS mutator.
  const { salt, hash } = hashPassword(password);
  const createdAt = new Date().toISOString();

  let created;
  try {
    const repository = usersStore(event);
    created = await repository.mutateUsers((users) => {
      if (Object.hasOwn(users, username)) return { changed: false, value: false };
      users[username] = {
        username,
        name: name || username,
        salt,
        passwordHash: hash,
        status: "approved",
        role: "admin",
        createdAt,
      };
      return { changed: true, value: true };
    });
  } catch {
    console.error("admin-bootstrap: storage_unavailable");
    return {
      statusCode: 503,
      headers: { "Cache-Control": "no-store" },
      body: JSON.stringify({ error: "Service temporarily unavailable. Try again shortly." }),
    };
  }

  if (!created) {
    return { statusCode: 409, body: JSON.stringify({ error: "That username is already registered." }) };
  }
  return { statusCode: 201, body: JSON.stringify({ message: `Admin account '${username}' created.` }) };
};
