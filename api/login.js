const crypto = require("crypto");

function safeEqual(a, b) {
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));

  return x.length === y.length &&
    crypto.timingSafeEqual(x, y);
}

module.exports = (req, res) => {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const { username, password } = req.body || {};

  const expectedUser = process.env.CHATMAX_USERNAME;
  const expectedPassword = process.env.CHATMAX_PASSWORD;
  const secret = process.env.CHATMAX_SESSION_SECRET;

  if (!expectedUser || !expectedPassword || !secret) {
    return res.status(500).json({
      error: "Login configuration missing."
    });
  }

  if (
    !safeEqual(username, expectedUser) ||
    !safeEqual(password, expectedPassword)
  ) {
    return res.status(401).json({
      error: "Incorrect username or password."
    });
  }

  const issuedAt = String(Date.now());

  const signature = crypto
    .createHmac("sha256", secret)
    .update(issuedAt)
    .digest("hex");

  res.setHeader(
    "Set-Cookie",
    `chatmax_session=${issuedAt}.${signature}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`
  );

  return res.status(200).json({ ok: true });
};
