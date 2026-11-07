const crypto = require("crypto");

module.exports = (req, res) => {
  const raw = req.headers.cookie || "";
  const match = raw.match(/(?:^|;\s*)chatmax_session=([^;]+)/);

  if (!match || !process.env.CHATMAX_SESSION_SECRET) {
    return res.status(401).json({ authenticated: false });
  }

  const parts = decodeURIComponent(match[1]).split(".");

  if (parts.length !== 2 || !/^\d+$/.test(parts[0])) {
    return res.status(401).json({ authenticated: false });
  }

  const age = Date.now() - Number(parts[0]);

  if (age < 0 || age > 12 * 60 * 60 * 1000) {
    return res.status(401).json({ authenticated: false });
  }

  const expected = crypto
    .createHmac("sha256", process.env.CHATMAX_SESSION_SECRET)
    .update(parts[0])
    .digest("hex");

  const a = Buffer.from(parts[1]);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ authenticated: false });
  }

  return res.status(200).json({ authenticated: true });
};
