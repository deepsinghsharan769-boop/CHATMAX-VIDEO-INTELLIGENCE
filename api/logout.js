module.exports = (req, res) => {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).end();
  }

  res.setHeader(
    "Set-Cookie",
    "chatmax_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
  );

  return res.status(200).json({ ok: true });
};
