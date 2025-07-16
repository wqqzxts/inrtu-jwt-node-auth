const authService = require("../services/auth");
const jwt = require("../services/jwt");
const config = require("../config");

class AuthController {
  async register(req, res, next) {
    try {
      const user = await authService.register(req.body);

      res.status(200).json({
        msg: "finish the registration: check your email for verification code",
        user: {
          id: user.id,
          email: user.email,
          is_active: user.is_active,
          created_at: user.created_at,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  async login(req, res, next) {
    try {
      const { email, password } = req.body;
      const tokens = await authService.login(email, password);

      res.status(200).cookie("refresh", tokens.refresh, {
        httpOnly: config.refresh_cookie.httpOnly,
        secure: config.refresh_cookie.secure,
        sameSite: config.refresh_cookie.sameSite,
        maxAge: config.jwt.expRefresh,
      });

      res.status(200).json({
        access: tokens.access,
      });
    } catch (error) {  
      next(error);
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
      next(error);
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
      next(error);
    }
  }

  async verifyEmail(req, res, next) {
    try {
      const { email, otp } = req.body;
      await authService.verifyOtp(email, otp);

      res.json({
        msg: "email verified successfully",
      });
    } catch (error) {
      next(error);
    }
  }

  async resendOtp(req, res, next) {
    try {
      const { email } = req.body;
      await authService.resendOtp(email);

      res.json({
        msg: "new verification code sent to your email",
      });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new AuthController();
