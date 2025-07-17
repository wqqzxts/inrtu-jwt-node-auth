const express = require("express");
const router = express.Router();
const authController = require("../controllers/auth.js");
const authMiddleware = require("../middleware/auth.js");
const userController = require("../controllers/user.js")

router.post("/api/v1/auth/register", authController.register);
router.post("/api/v1/auth/login", authController.login);
router.post("/api/v1/auth/logout", authMiddleware, authController.logout);
router.post("/api/v1/auth/refresh", authController.refresh);
router.post("/api/v1/auth/email_verify", authController.verifyEmail);
router.post("/api/v1/auth/email_verify_resend", authController.resendOtp);
router.post("/api/v1/auth/password_reset_request", authController.requestPasswdReset);
router.post("/api/v1/auth/password_reset", authController.resetPassword);

router.patch("/api/v1/user/edit/security/update_password", authMiddleware, userController.updatePassword);


module.exports = router;