const { makeSessionCookie, clearSessionCookie } = require("./util/auth");
const { usersStore } = require("./util/users-store");
const { sendMail } = require("./util/mail");
const g = require("./util/google-oauth");

exports.handler = async (event) => {
  if (event.httpMethod !== "GET") return g.response(405, "Method Not Allowed", { Allow: "GET" });
  const clear = g.oauthCookie("", 0);
  const fail = (reason, marker = "google") => {
    console.warn(`google-callback: ${reason}`);
    return g.redirect(`/login.html?error=${marker}`, [clear]);
  };
  let cfg;
  try { cfg = g.config(); }
  catch {
    console.warn("google-callback: unavailable");
    return g.response(503, "Google sign-in is unavailable. Please restart sign-in later.", {}, [clear]);
  }
  try {
    const host = String((event.headers || {}).host || (event.headers || {}).Host || "").toLowerCase();
    if (host !== new URL(cfg.siteUrl).host) return fail("origin");
    const state = g.queryValue(event, "state", 128);
    const code = g.queryValue(event, "code", 4096);
    const providerError = g.queryValue(event, "error", 256);
    const st = g.readTransaction(g.transactionCookieFromEvent(event), cfg);
    if (!st || !g.equal(st.state, state)) return fail("state");
    if (providerError) {
      if (code) return fail("query");
      if (providerError === "access_denied") return g.redirect("/login.html?cancelled=1", [clear]);
      return fail("provider");
    }
    if (!code) return fail("query");
    const idToken = await g.exchangeCode({ code, verifier: st.verifier, cfg });
    const claims = g.decodeTokenEndpointIdToken(idToken);
    const validation = g.validateIdTokenClaims(claims, { clientId: cfg.clientId, nonce: st.nonce });
    if (!validation.ok) {
      return validation.error === "unsupported_account" ? fail("account", "account") : fail("claims");
    }
    const timestamp = new Date().toISOString();
    const { user, isNew } = await usersStore(event).mutateUsers((users) =>
      g.provisionGoogle(users, claims, cfg, timestamp));
    if (user.status === "pending") {
      if (isNew && cfg.notifyEmail) {
        await sendMail({
          to: cfg.notifyEmail, subject: "Course account pending approval",
          text: `A Google account is pending approval.\nEmail: ${user.email}\nName: ${user.name}\nReview: ${cfg.siteUrl}/core/admin.html`,
        });
      }
      return g.redirect("/login.html?pending=1", [clear, clearSessionCookie()]);
    }
    if (user.status === "rejected") return g.redirect("/login.html?rejected=1", [clear, clearSessionCookie()]);
    if (user.status !== "approved") return fail("account_status");
    return g.redirect(g.safeNextPath(st.next), [makeSessionCookie(user), clear]);
  } catch (error) {
    if (error instanceof g.OAuthError && error.code === "account_conflict") return fail("conflict", "account-conflict");
    if (error instanceof g.OAuthError && error.code === "query") return fail("query");
    return fail("unavailable");
  }
};
