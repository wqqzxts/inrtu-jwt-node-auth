require("dotenv").config();

module.exports = {
  jwt: {
    secret: process.env.JWT_SECRET || "debug",
    expAccess: "15m",
    expRefresh: 4320000,
  },
  refresh_cookie: {
    httpOnly: true,
    secure: process.env.ENV_STATE === "prod",
    sameSite: process.env.ENV_STATE === "prod" ? "strict" : "lax",
  },
  client: {
    passwdHashed: true,
  },
  smtp: {
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    auth: {
      user: process.env.SMTP_SENDER,
      pass: process.env.SMTP_PASSWORD,
    },
  },
  otp: {
    expEmailOtp: 15, // minutes
  }
};
