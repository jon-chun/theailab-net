const crypto = require("crypto");

const SESSION_COOKIE = "iphs_session";
const SESSION_TTL_SECONDS = 60 * 60 * 12; // 12 hours

function getSessionSecret() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    throw new Error("SESSION_SECRET environment variable is not set");
  }
  return secret;
}

function hashPassword(password, salt) {
  const useSalt = salt || crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, useSalt, 64).toString("hex");
  return { salt: useSalt, hash: derived };
}

function verifyPassword(password, salt, expectedHash) {
  const { hash } = hashPassword(password, salt);
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(expectedHash, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function sign(payload) {
  const secret = getSessionSecret();
  const json = JSON.stringify(payload);
  const b64 = Buffer.from(json).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(b64).digest("base64url");
  return `${b64}.${sig}`;
}

function verify(token) {
  if (!token || !token.includes(".")) return null;
  const [b64, sig] = token.split(".");
  const secret = getSessionSecret();
  const expected = crypto.createHmac("sha256", secret).update(b64).digest("base64url");
  const a = Buffer.from(sig || "");
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(b64, "base64url").toString());
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function makeSessionCookie(user) {
  const payload = {
    sub: user.username,
    role: user.role || "student",
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const token = sign(payload);
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

function getSessionFromEvent(event) {
  const cookies = parseCookies(event.headers.cookie || event.headers.Cookie);
  const token = cookies[SESSION_COOKIE];
  return verify(token);
}

function hasPasswordCredentials(user) {
  return !!user && user.provider !== "google" &&
    typeof user.salt === "string" && /^[a-f0-9]{32}$/i.test(user.salt) &&
    typeof user.passwordHash === "string" && /^[a-f0-9]{128}$/i.test(user.passwordHash);
}

module.exports = {
  hasPasswordCredentials,
  SESSION_COOKIE,
  hashPassword,
  verifyPassword,
  makeSessionCookie,
  clearSessionCookie,
  getSessionFromEvent,
  parseCookies,
  sign,
  verify,
};
