const jwt = require("../services/jwt");
const { UnauthorizedError, ForbiddenError } = require("../util/errors");

function auth(req, res, next) {
  if (!req.cookies.refresh) throw new ForbiddenError("Refresh token missing");

  const authHeader = req.headers["authorization"];
  const accessToken = authHeader && authHeader.split(" ")[1];

  if (!accessToken) {    
    throw new UnauthorizedError("Access token missing");
  }

  try {
    const decoded = jwt.verifyAccess(accessToken);
    req.userId = decoded.sub;
    next();
  } catch (error) {
    next(error);
  }
}

module.exports = auth;