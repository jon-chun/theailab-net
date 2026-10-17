const RESEND_API_URL = "https://api.resend.com/emails";
async function sendMail({ to, subject, text }) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return { skipped: true };
  const from = process.env.MAIL_FROM || "onboarding@resend.dev";
  const recipients = Array.isArray(to) ? to : [to];
  if (/[\r\n]/.test(from) || !recipients.length || recipients.some((email) =>
    typeof email !== "string" || email.length > 254 || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email))) {
    console.warn("mail: invalid_configuration");
    return { skipped: false, ok: false };
  }
  try {
    const res = await fetch(RESEND_API_URL, {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(5000),
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to: recipients,
        subject: String(subject || "Course account notification").replace(/[\x00-\x1f\x7f]/g, " ").slice(0, 200),
        text: String(text || "Check the course account administration page.").slice(0, 8000) }),
    });
    if (res.body) await res.body.cancel().catch(() => {});
    if (!res.ok) console.warn("mail: delivery_failed");
    return { skipped: false, ok: res.ok, status: res.status };
  } catch {
    console.warn("mail: delivery_failed");
    return { skipped: false, ok: false };
  }
}
module.exports = { sendMail };
