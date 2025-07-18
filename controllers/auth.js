const authService = require("../services/auth");
const jwt = require("../services/jwt");
const config = require("../config");

class AuthController {
  async register(req, res, next) {
    try {
      const user = await authService.register(req.body);

      res.status(200).json({
        msg: "Check your email for verification code",
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
        return res.status(403).json({ msg: "Refresh token missing" });
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

      res.json({ msg: "Logged out successfully" });
    } catch (error) {
      next(error);
    }
  }

  async verifyEmail(req, res, next) {
    try {
      const { email, otp } = req.body;
      await authService.verifyEmail(email, otp);

      res.json({
        msg: "Email verified successfully",
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
        msg: "New verification code sent to your email",
      });
    } catch (error) {
      next(error);
    }
  }

  async requestPasswdReset(req, res, next) {
    try {
      const { email } = req.body;
      await authService.requestPasswdReset(email);

      res.status(201).json({
        msg: "If an account with provided email exists, a verification code has been sent"
      });
    } catch (error) {
      next(error);
    }
  }

  async resetPassword(req, res, next) {
    try {
      const { email, otp, new_password } = req.body;
      await authService.resetPassword(email, otp, new_password);

      res.status(201).json({
        msg: "Password reset successfully"
      });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new AuthController();
