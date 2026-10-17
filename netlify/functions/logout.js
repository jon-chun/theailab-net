const { clearSessionCookie } = require("./util/auth");

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }
  return {
    statusCode: 200,
    headers: { "Set-Cookie": clearSessionCookie(), "Cache-Control": "no-store" },
    body: JSON.stringify({ message: "Logged out." }),
  };
};
