const jwt = require("jsonwebtoken");
const config = require("../config");

class JwtService {
  genAccess(userId) {
    return jwt.sign({ sub: userId }, config.jwt.secret, {
      expiresIn: config.jwt.expAccess,
    });
  }

  verifyAccess(token) {
    return jwt.verify(token, config.jwt.secret);
  }

  genRefresh(userId) {
    return jwt.sign({ sub: userId }, config.jwt.secret, {
      expiresIn: config.jwt.expRefresh,
    });
  }

  verifyRefresh(token) {
    return jwt.verify(token, config.jwt.secret);
  }
}

module.exports = new JwtService();
