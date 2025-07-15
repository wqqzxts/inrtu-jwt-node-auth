const jwt = require("../services/jwt");

function auth(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "access token missing" });
  }

  try {
    const decoded = jwt.verifyAccess(token);
    req.userId = decoded.sub;
    next();
  } catch (error) {
    return res.status(403).json({ msg: "invalid or expired access token" });
  }
}

module.exports = auth;