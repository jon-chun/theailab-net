const { usersStore } = require("./util/users-store");
const { hashPassword } = require("./util/auth");
const { sendMail } = require("./util/mail");

const USERNAME_RE = /^[a-zA-Z0-9._-]{3,40}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RESERVED_USERNAMES = new Set(["__proto__", "constructor", "prototype"]);

const oneLine = (value) => String(value).replace(/[\r\n]+/g, " ");

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
  const name = String(body.name || "").trim();
  const email = String(body.email || "").trim().toLowerCase();

  if (!USERNAME_RE.test(username)) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Username must be 3-40 characters: letters, numbers, dot, dash, underscore." }),
    };
  }
  if (RESERVED_USERNAMES.has(username)) {
    return { statusCode: 400, body: JSON.stringify({ error: "That username is not available." }) };
  }
  if (password.length < 8) {
    return { statusCode: 400, body: JSON.stringify({ error: "Password must be at least 8 characters." }) };
  }
  if (!EMAIL_RE.test(email)) {
    return { statusCode: 400, body: JSON.stringify({ error: "A valid email address is required (used for password resets)." }) };
  }

  // Everything non-deterministic is prepared before the CAS mutator, which may run several times.
  const { salt, hash } = hashPassword(password);
  const createdAt = new Date().toISOString();
  const record = {
    username,
    name: name || username,
    email,
    salt,
    passwordHash: hash,
    status: "pending",
    role: "student",
    createdAt,
  };

  let created;
  try {
    const repository = usersStore(event);
    created = await repository.mutateUsers((users) => {
      if (Object.hasOwn(users, username)) return { changed: false, value: false };
      users[username] = { ...record };
      return { changed: true, value: true };
    });
  } catch {
    console.error("register: storage_unavailable");
    return {
      statusCode: 503,
      headers: { "Cache-Control": "no-store" },
      body: JSON.stringify({ error: "Service temporarily unavailable. Try again shortly." }),
    };
  }

  if (!created) {
    return { statusCode: 409, body: JSON.stringify({ error: "That username is already registered." }) };
  }

  // Advisory notification: once, after the successful commit, never inside the retry loop.
  const notifyEmail = String(process.env.ADMIN_NOTIFY_EMAIL || "").trim();
  if (notifyEmail) {
    try {
      await sendMail({
        to: notifyEmail,
        subject: `New account request: ${oneLine(username)}`,
        text: `New account application pending approval.\nUsername: ${oneLine(username)}\nName: ${oneLine(name || username)}\nEmail: ${oneLine(email)}\nRequested: ${createdAt}\nReview at https://theailab.net/core/admin.html`,
      });
    } catch {
      console.error("register: notification_failed");
    }
  }

  return {
    statusCode: 201,
    body: JSON.stringify({ message: "Registration received. An admin must approve your account before you can log in." }),
  };
};
