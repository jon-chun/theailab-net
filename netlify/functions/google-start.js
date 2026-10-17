const g = require("./util/google-oauth");

exports.handler = async (event) => {
  if (event.httpMethod !== "GET") return g.response(405, "Method Not Allowed", { Allow: "GET" });
  try {
    const cfg = g.config();
    const next = g.safeNextPath(g.queryValue(event, "next", 512));
    const host = String((event.headers || {}).host || (event.headers || {}).Host || "").toLowerCase();
    if (host !== new URL(cfg.siteUrl).host) {
      return g.redirect(`${cfg.siteUrl}/login.html?next=${encodeURIComponent(next)}`);
    }
    const iat = Math.floor(Date.now() / 1000);
    const transaction = {
      purpose: "google-login-v2", clientId: cfg.clientId, redirectUri: cfg.redirectUri,
      state: g.randomUrlSafe(), nonce: g.randomUrlSafe(), verifier: g.randomUrlSafe(48),
      next, iat, exp: iat + g.OAUTH_TTL_SECONDS,
    };
    const url = g.buildAuthUrl({ ...cfg, ...transaction, codeChallenge: g.pkceChallenge(transaction.verifier) });
    return g.redirect(url, [g.oauthCookie(g.sealTransaction(transaction, cfg.sessionSecret), g.OAUTH_TTL_SECONDS)]);
  } catch (error) {
    if (error instanceof g.OAuthError && error.code === "query") return g.response(400, "Invalid sign-in request.");
    console.warn("google-start: unavailable");
    return g.response(503, "Google sign-in is unavailable. Please use the existing password login or try again later.");
  }
};
