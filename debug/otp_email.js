const { createTransport } = require("nodemailer");
require("dotenv").config();

const transporter = createTransport({
  host: process.env.SMTP_HOST || 'smtp.ethereal.email',
  port: process.env.SMTP_PORT || 587,
  auth: {
    user: "gilberto.shanahan7@ethereal.email",
    pass: process.env.SMTP_PASSWORD,
  },
});
