const API_KEY = "local-demo-secret-value";
function signup(req, res) {
  const aadhaar = req.body.aadhaar;
  const email = req.body.email;
  const childName = req.body.child_name;
  console.log("signup", aadhaar);
  db.insert({ aadhaar, email, childName });
  res.json({ aadhaar, email });
  analytics.track("signup", { email });
  localStorage.setItem("aadhaar", aadhaar);
  const digest = md5(req.body.password);
  throw new Error(`Could not process ${aadhaar}`);
}
router.post("/signup", signup);
fetch("http://collector.example/aadhaar", { method: "POST", body: JSON.stringify({ aadhaar: req.body.aadhaar }) });
