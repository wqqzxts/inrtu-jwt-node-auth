const db = require("../debug/db");
const jwt = require("../services/jwt");
const config = require("../config");
const isHash = require("../util/is_hash");
const otpEmail = require("../debug/otp_email");
const { randomInt } = require("crypto");

class AuthService {
  async register(userData) {
    const { last_name, first_name, patronymic, is_male, email, password } =
      userData;

    if (config.client.passwdHashed && !isHash(password)) {
      throw new Error("user password must be hashed on the client-side");
    }

    try {
      const result = await db.query(
        `
        INSERT INTO users
        (last_name, first_name, patronymic, is_male, email, password) 
        VALUES ($1, $2, $3, $4, $5, $6) 
        RETURNING id, email, is_active, created_at
        `,
        [last_name, first_name, patronymic, is_male, email, password]
      );

      await this.sendOtp(email);

      return result.rows[0];
    } catch (error) {
      throw new Error(
        `user creation in the db is failed due to: ${error.message}`
      );
    }
  }

  async login(email, password) {
    const user = await db.query(
      `
            SELECT id, password, is_active FROM users WHERE email = $1
            `,
      [email]
    );

    if (user.rows.length === 0) throw new Error("user not found");

    const userData = user.rows[0];

    if (!isHash(userData.password))
      throw new Error("user password must be hashed on the client-side");

    if (userData.password !== password) throw new Error("invalid password");

    // if (!userData.is_active) // to do

    await db.query(`UPDATE users SET last_login = NOW() WHERE id = $1`, [
      userData.id,
    ]);

    return {
      userId: userData.id,
      access: jwt.genAccess(userData.id),
      refresh: jwt.genRefresh(userData.id),
    };
  }

  async refresh(userId) {
    const user = await db.query(
      `SELECT id, is_active FROM users WHERE id = $1`,
      [userId]
    );

    if (user.rows.length === 0) throw new Error("user not found");

    // if (!user.rows[0].is_active) // to do

    return jwt.genAccess(userId);
  }

  async sendOtp(email) {
    const otp = randomInt(100000, 999999).toString();
    const now = new Date();

    try {
      await db.query(
        `
        INSERT INTO otp_codes (email, otp_code, created_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (email)
        DO UPDATE SET otp_code = $2, created_at = $3, attempts = 0
        `,
        [email, otp, now]
      );
    } catch (error) {
      throw new Error("failed to add otp to db");
    }

    try {
      await otpEmail.sendMail({
        from: config.smtp.auth.user,
        to: email,
        subject: "otp",
        text: `your verification code is: ${otp}`,
        html: `<p>your verification code is: <strong>${otp}</strong></p>`,
      });
    } catch (error) {
      throw new Error("failed to send otp");
    }

    return true;
  }

  async verifyOtp(email, otp) {
    try {
      const result = await db.query(
        `
        SELECT * FROM otp_codes WHERE email = $1
        `,
        [email]
      );

      if (result.rows.length === 0) throw new Error("otp not found");

      const otpRecord = result.rows[0];
      const now = new Date();
      const otpAge = (now - otpRecord.created_at) / 1000 / 60;

      if (otpAge > config.otp.expEmailOtp) throw new Error("otp expired");
      if (otpRecord.attempts >= 3)
        throw new Error("too many attempts. request a new otp");

      if (otpRecord.otp_code !== otp.toString()) {
        await db.query(
          `
          UPDATE otp_codes SET attempts = attempts + 1 WHERE email = $1
          `,
          [email]
        );
        throw new Error("invalid otp");
      }

      await db.query(`UPDATE users SET is_active = true WHERE email = $1`, [
        email,
      ]);

      await db.query(`DELETE FROM otp_codes WHERE email = $1`, [email]);

      return true;
    } catch (error) {
      throw new Error("failed to verify OTP");
    }
  }

  async resendOtp(email) {
    try {
      const user = await db.query(`SELECT id FROM users WHERE email = $1`, [
        email,
      ]);

      if (user.rows.length === 0) throw new Error("user not found");

      return await this.sendOtp(email);
    } catch (error) {
      throw new Error("failed to resend OTP");
    }
  }
}

module.exports = new AuthService();
