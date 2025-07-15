const authService = require("../services/auth");
const jwt = require("../services/jwt");
const config = require("../config");

class AuthController {
  async register(req, res, next) {
    try {
      const user = await authService.register(req.body);

      res.status(200).json({
        msg: "user registered",
        user: {
          id: user.id,
          email: user.email,
          is_active: user.is_active,
          created_at: user.created_at,
        },
      });
    } catch (error) {
      console.log("register error: ", error);
    }
  }

  async login(req, res, next) {
    try {
      const { email, password } = req.body;
      const tokens = await authService.login(email, password);

      res.cookie("refresh", tokens.refresh, {
        httpOnly: config.refresh_cookie.httpOnly,
        secure: config.refresh_cookie.secure,
        sameSite: config.refresh_cookie.sameSite,
        maxAge: config.jwt.expRefresh,
      });

      res.json({
        access: tokens.access,
      });
    } catch (error) {
      console.log("login error: ", error);
      return res.status(401).json({ msg: "invalid credentials" });
    }
  }

  async refresh(req, res, next) {
    try {
      const refresh = req.cookies.refresh;
      if (!refresh) {
        return res.status(401).json({ msg: "refresh token missing" });
      }

      const decoded = jwt.verifyRefresh(refresh);

      const access = await authService.refresh(decoded.sub);

      res.json({
        access: access,
      });
    } catch (error) {
      console.log("refresh error: ", error);
      return res.status(401).json({ msg: "invalid or expired refresh token" });
    }
  }

  async logout(req, res, next) {
    try {
      res.clearCookie("refresh", {
        httpOnly: config.refresh_cookie.httpOnly,
        secure: config.refresh_cookie.secure,
        sameSite: config.refresh_cookie.sameSite,
      });

      res.json({ msg: "logged out successfully" });
    } catch (error) {
        console.log("logout error: ", error);
        return res.status(501).json({ msg: "server error" });
    }
  }
}

module.exports = new AuthController();
