const { createTransport } = require("nodemailer");
const config = require("../config");

const transporter = createTransport({
  host: config.smtp.host,
  port: config.smtp.port,
  auth: {
    user: config.smtp.auth.user,
    pass: config.smtp.auth.pass,
  },
});
