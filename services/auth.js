const db = require("../debug/db");
const jwt = require("../services/jwt");
const config = require("../config");
const isHash = require("../util/is_hash");
const otpEmail = require("../debug/otp_email");
const { randomInt } = require("crypto");
const {
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  InternalServerError,
} = require("../util/errors");

class AuthService {
  async register(userData) {
    const { last_name, first_name, patronymic, is_male, email, password } =
      userData;

    if (config.client.passwdHashed && !isHash(password))
      throw new BadRequestError("Password is not hashed");

    const { client, query, release } = await db.getClient();
    try {
      await query(`BEGIN`);

      const result = await query(
        `
        INSERT INTO users
        (last_name, first_name, patronymic, is_male, email, password) 
        VALUES ($1, $2, $3, $4, $5, $6) 
        RETURNING id, email, is_active, created_at
        `,
        [last_name, first_name, patronymic, is_male, email, password]
      );

      try {
        await this.sendOtp(email, query);
        await query(`COMMIT`);

        return result.rows[0];
      } catch (otpErr) {
        throw new InternalServerError(
          `Failed to insert otp to db OR to send email otp: ${otpErr.message}`
        );
      }
    } catch (error) {
      await query(`ROLLBACK`);
      throw new InternalServerError(
        `Failed to insert user to db: ${error.message}`
      );
    } finally {
      release();
    }
  }

  async login(email, password) {
    const user = await db.query(
      `
      SELECT id, password, is_active FROM users WHERE email = $1
      `,
      [email]
    );

    if (user.rows.length === 0)
      throw new UnauthorizedError("Invalid credentials");

    const userData = user.rows[0];

    if (!isHash(userData.password))
      throw new BadRequestError("Password is not hashed");

    if (userData.password !== password)
      throw new UnauthorizedError("Invalid credentials");

    if (!userData.is_active)
      throw new ForbiddenError("User account is not active");

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

    if (user.rows.length === 0) throw new BadRequestError("User not found");

    if (!user.rows[0].is_active)
      throw new ForbiddenError("User account is not active");

    // i guess we first need to verify refresh jwt
    return jwt.genAccess(userId);
  }

  async sendOtp(email, query = db.query) {
    const otp = randomInt(100000, 999999).toString();
    const now = new Date();

    try {
      await query(
        `
        INSERT INTO otp_codes (email, otp_code, created_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (email)
        DO UPDATE SET otp_code = $2, created_at = $3, attempts = 0
        `,
        [email, otp, now]
      );

      await otpEmail.sendMail({
        from: config.smtp.auth.user,
        to: email,
        subject: "Регистрация на платформе Карьерный Навигатор",
        text: `Пожалуйста, подтвердите ваш email-адрес с помощью этого кода: ${otp}`,
        html: `<p>Пожалуйста, подтвердите ваш email-адрес с помощью этого кода: <strong>${otp}</strong></p>`,
      });

      return true;
    } catch (error) {
      throw error;
    }
  }

  async verifyOtp(email, otp) {
    try {
      const result = await db.query(
        `
        SELECT * FROM otp_codes WHERE email = $1
        `,
        [email]
      );

      if (result.rows.length === 0)
        throw new BadRequestError("Verification code not found");

      const otpRecord = result.rows[0];
      const now = new Date();
      const otpAge = (now - otpRecord.created_at) / 1000 / 60;

      if (otpAge > config.otp.expEmailOtp)
        throw new UnauthorizedError("Verification code expired");

      if (otpRecord.attempts >= 3)
        throw new ForbiddenError(
          "Too many attempts. Request a new verification code"
        );

      if (otpRecord.otp_code !== otp.toString()) {
        await db.query(
          `
          UPDATE otp_codes SET attempts = attempts + 1 WHERE email = $1
          `,
          [email]
        );
        throw new UnauthorizedError("Invalid credentials");
      }

      await db.query(`UPDATE users SET is_active = true WHERE email = $1`, [
        email,
      ]);

      await db.query(`DELETE FROM otp_codes WHERE email = $1`, [email]);

      return true;
    } catch (error) {
      throw new InternalServerError(`Failed to verify OTP: ${error.message}`);
    }
  }

  async resendOtp(email) {
    try {
      const user = await db.query(`SELECT id FROM users WHERE email = $1`, [
        email,
      ]);

      const userRequested = await db.query(
        `SELECT * FROM otp_codes WHERE email = $1`,
        [email]
      );

      if (user.rows.length === 0) throw new BadRequestError("User not found");
      if (userRequested.rows.length === 0)
        throw new ForbiddenError("User did not request verification code");

      return await this.sendOtp(email);
    } catch (error) {
      throw new InternalServerError(
        `Failed to resend verification code: ${error.message}`
      );
    }
  }
}

module.exports = new AuthService();
