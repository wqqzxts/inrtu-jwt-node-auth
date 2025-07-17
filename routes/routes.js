const express = require("express");
const router = express.Router();
const authController = require("../controllers/auth.js");
const authMiddleware = require("../middleware/auth.js");
const userController = require("../controllers/user.js")

router.post("/api/v1/auth/register", authController.register);
router.post("/api/v1/auth/login", authController.login);
router.post("/api/v1/auth/logout", authMiddleware, authController.logout);
router.post("/api/v1/auth/refresh", authController.refresh);
router.post("/api/v1/auth/otp_email", authController.verifyEmail);
router.post("/api/v1/auth/resend_otp_email", authController.resendOtp)
router.patch("/api/v1/auth/update_password", authMiddleware, userController.updatePassword);

module.exports = router;