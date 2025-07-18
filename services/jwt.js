const jwt = require("jsonwebtoken");
const config = require("../config");
const { UnauthorizedError, ForbiddenError } = require("../util/errors");

class JwtService {
  genAccess(userId) {
    return jwt.sign({ sub: userId }, config.jwt.secret, {
      expiresIn: config.jwt.expAccess,
    });
  }

  verifyAccess(token) {
    try {
      return jwt.verify(token, config.jwt.secret);
    } catch (error) {
      throw new UnauthorizedError("Invalid or expired access token");
    }
  }

  genRefresh(userId) {
    return jwt.sign({ sub: userId }, config.jwt.secret, {
      expiresIn: config.jwt.expRefresh,
    });
  }

  verifyRefresh(token) {
    try {
      return jwt.verify(token, config.jwt.secret);
    } catch (error) {
      throw new ForbiddenError("Invalid or expired refresh token");
    }
  }
}

module.exports = new JwtService();
