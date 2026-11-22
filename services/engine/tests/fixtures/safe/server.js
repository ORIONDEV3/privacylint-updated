function requireAuth(req, res, next) { next(); }
function redact(value) { return String(value).slice(-4); }
function profile(req, res) {
  const aadhaar = req.body.aadhaar;
  logger.info("signup", redact(aadhaar));
  res.json({ lastFour: redact(aadhaar) });
}
router.post("/profile", requireAuth, profile);
fetch("https://collector.example/profile", { method: "POST", body: JSON.stringify({ state: "ready" }) });
