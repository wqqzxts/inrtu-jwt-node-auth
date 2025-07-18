const db = require("../debug/db");
const config = require("../config");
const isHash = require("../util/is_hash");
const {
  BadRequestError,
  UnauthorizedError,
  InternalServerError,
} = require("../util/errors");

class UserService {
  async updatePassword(userId, currentPassword, newPassword) {
    if (
      config.client.passwdHashed &&
      (!isHash(currentPassword) || !isHash(newPassword))
    )
      throw new BadRequestError("Password is not hashed");

    if (!currentPassword || !newPassword)
      throw new BadRequestError("Both current and new password are required");

    if (currentPassword.toString() === newPassword.toString())
      throw new BadRequestError("New password is the same as current");

    const result = await db.query(
      `
            SELECT password FROM users WHERE id = $1
            `,
      [userId]
    );

    if (result.rows.length === 0) throw new BadRequestError("User not found");

    const user = result.rows[0];

    if (user.password !== currentPassword)
      throw new UnauthorizedError("Invalid credentials");

    try {
      await db.query(`BEGIN`);

      await db.query(`UPDATE users SET password = $1 WHERE id = $2`, [
        newPassword,
        userId,
      ]);

      await db.query(`COMMIT`);
    } catch (error) {
      await db.query("ROLLBACK");
      throw new InternalServerError(
        `Failed to update password: ${error.message}`
      );
    }
  }
}

module.exports = new UserService();
