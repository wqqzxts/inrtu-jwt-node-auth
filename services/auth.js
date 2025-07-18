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
  InternalServerError,
} = require("../util/errors");

class AuthService {
  async register(userData) {
    const { last_name, first_name, patronymic, is_male, email, password } =
      userData;

    if (config.client.passwdHashed && !isHash(password.toString()))
      throw new BadRequestError("Password is not hashed");

    const { client, query, release } = await db.getClient();
    try {
      let result;
      try {
        await query(`BEGIN`);

        result = await query(
          `
        INSERT INTO users
        (last_name, first_name, patronymic, is_male, email, password) 
        VALUES ($1, $2, $3, $4, $5, $6) 
        RETURNING id, email, is_active, created_at
        `,
          [last_name, first_name, patronymic, is_male, email, password]
        );
      } catch (error) {
        throw new InternalServerError(
          `Failed to insert user into DB: ${error.message}`
        );
      }

      try {
        await this.sendOtp(
          email,
          "Регистрация на платформе Карьерный Навигатор",
          "Пожалуйста, подтвердите ваш email-адрес с помощью этого кода: ${otp}",
          "<p>Пожалуйста подтвердите ваш email-адрес с помощью этого кода: <strong>${otp}</strong></p>",
          query
        );
        await query(`COMMIT`);

        return result.rows[0];
      } catch (error) {
        throw new InternalServerError(
          `Failed to send email OTP: ${error.message}`
        );
      }
    } catch (error) {
      await query(`ROLLBACK`);
      throw new InternalServerError(
        `Failed to register user: ${error.message}`
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

    if (!isHash(userData.password).toString())
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

    return jwt.genAccess(userId);
  }

  async sendOtp(
    email,
    emailSubject = "Подтверждение действия на платформе Карьерный Навигатор",
    emailText = "Пожалуйста подтвердите ваше действие с помощью этого кода: ${otp}",
    emailHtml = "<p>Пожалуйста подтвердите ваше действие с помощью этого кода: <strong>${otp}</strong></p>",
    query = db.query
  ) {
    const otp = randomInt(100000, 999999).toString();
    const now = new Date();

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
      subject: emailSubject,
      text: emailText.replace("${otp}", otp),
      html: emailHtml.replace("${otp}", otp),
    });
  }

  async verifyEmail(email, otp) {
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
      try {
        await db.query(`BEGIN`);

        await db.query(
          `
          UPDATE otp_codes SET attempts = attempts + 1 WHERE email = $1
          `,
          [email]
        );

        await db.query(`COMMIT`);
      } catch (error) {
        await db.query(`ROLLBACK`);
        throw new InternalServerError("Failed to record verification attempt");
      }
      throw new UnauthorizedError("Invalid credentials");
    }

    try {
      await db.query(`BEGIN`);

      await db.query(`UPDATE users SET is_active = true WHERE email = $1`, [
        email,
      ]);

      await db.query(`DELETE FROM otp_codes WHERE email = $1`, [email]);

      await db.query(`COMMIT`);
    } catch (error) {
      await db.query(`ROLLBACK`);
      throw new InternalServerError(`Failed to verify email: ${error.message}`);
    }
  }

  async resendOtp(email) {
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

    try {
      await this.sendOtp(
        email,
        "Регистрация на платформе Карьерный Навигатор",
        "Пожалуйста, подтвердите ваш email-адрес с помощью этого кода: ${otp}",
        "<p>Пожалуйста подтвердите ваш email-адрес с помощью этого кода: <strong>${otp}</strong></p>"
      );
    } catch (error) {
      throw new InternalServerError(
        `Failed to resend verification code: ${error.message}`
      );
    }
  }

  async requestPasswdReset(email) {
    const result = await db.query(`SELECT id FROM users WHERE email = $1`, [
      email,
    ]);

    if (result.rows.length === 0) return;

    try {
      await this.sendOtp(
        email,
        "Сброс пароля на платформе Карьерный Навигатор",
        "Пожалуйста, подтвердите сброс вашего пароля с помощью этого кода: ${otp}",
        "<p>Пожалуйста подтвердите сброс вашего пароля с помощью этого кода: <strong>${otp}</strong></p>"
      );
    } catch (error) {
      throw new InternalServerError(
        `Failed to send email OTP: ${error.message}`
      );
    }
  }

  async resetPassword(email, otp, newPassword) {
    if (config.client.passwdHashed && !isHash(newPassword.toString()))
      throw new BadRequestError("Password is not hashed");

    const otpResult = await db.query(
      `
        SELECT * FROM otp_codes WHERE email = $1
        `,
      [email]
    );

    if (otpResult.rows.length === 0)
      throw new BadRequestError("Verification code not found");

    const otpRecord = otpResult.rows[0];
    const now = new Date();
    const otpAge = (now - otpRecord.created_at) / 1000 / 60;

    if (otpAge > config.otp.expPasswdOtp)
      throw new UnauthorizedError("Verification code expired");

    if (otpRecord.attempts >= 3)
      throw new ForbiddenError(
        "Too many attempts. Request a new verification code"
      );

    if (otpRecord.otp_code !== otp.toString()) {
      try {
        await db.query(`BEGIN`);

        await db.query(
          `
          UPDATE otp_codes SET attempts = attempts + 1 WHERE email = $1
          `,
          [email]
        );

        await db.query(`COMMIT`);
      } catch (error) {
        await db.query(`ROLLBACK`);
        throw new InternalServerError("Failed to record verification attempt");
      }
      throw new UnauthorizedError("Invalid credentials");
    }

    const userResult = await db.query(
      `
        SELECT id, password FROM users WHERE email = $1
        `,
      [email]
    );

    if (userResult.rows.length === 0)
      throw new BadRequestError("User not found");

    const user = userResult.rows[0];

    if (user.password === newPassword.toString())
      throw new BadRequestError("New password is the same as current");

    try {
      await db.query(`BEGIN`);

      await db.query(
        `
        UPDATE users SET password = $1 WHERE id = $2
        `,
        [newPassword, user.id]
      );

      await db.query(
        `
        DELETE FROM otp_codes WHERE email = $1
        `,
        [email]
      );

      await db.query(`COMMIT`);
    } catch (error) {
      await db.query(`ROLLBACK`);
      throw new InternalServerError(
        `Failed to reset password: ${error.message}`
      );
    }
  }
}

module.exports = new AuthService();
