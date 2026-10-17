const crypto = require("crypto");
const { usersStore } = require("./util/users-store");
const { hasPasswordCredentials } = require("./util/auth");
const { sendMail } = require("./util/mail");

const RESET_TTL_MS = 30 * 60 * 1000; // 30 minutes

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
  const genericResponse = {
    statusCode: 200,
    body: JSON.stringify({ message: "If that account exists, a reset link has been emailed to its registered contact." }),
  };

  if (!username) return genericResponse;

  // Prepared once, outside the CAS mutator.
  const token = crypto.randomBytes(32).toString("hex");
  const expires = Date.now() + RESET_TTL_MS;

  let recipient = null;
  try {
    const repository = usersStore(event);
    recipient = await repository.mutateUsers((users) => {
      const user = Object.hasOwn(users, username) ? users[username] : undefined;
      // Always the same generic answer so the endpoint cannot enumerate accounts.
      // Google-only records stay a no-op: no reset fields, no mail.
      if (!user || !user.email || !hasPasswordCredentials(user)) return { changed: false, value: null };
      user.resetToken = token;
      user.resetTokenExpires = expires;
      return { changed: true, value: user.email };
    });
  } catch {
    console.error("forgot-password: storage_unavailable");
    return {
      statusCode: 503,
      headers: { "Cache-Control": "no-store" },
      body: JSON.stringify({ error: "Service temporarily unavailable. Try again shortly." }),
    };
  }

  if (!recipient) return genericResponse;

  const resetUrl = `https://theailab.net/reset-password.html?username=${encodeURIComponent(username)}&token=${token}`;
  try {
    await sendMail({
      to: recipient,
      subject: "Password reset requested - IPHS 400",
      text: `A password reset was requested for account ${username}.\nReset here (expires in 30 minutes): ${resetUrl}\nIf you didn't request this, ignore this email.`,
    });
  } catch {
    console.error("forgot-password: mail_failed");
  }

  return genericResponse;
};
