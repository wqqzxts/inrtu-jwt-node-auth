const db = require("../debug/db");
const jwt = require("../services/jwt");
const config = require("../config");
const isHash = require("../util/is_hash");

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

      return result.rows[0];
    } catch (error) {
      console.error("Database error:", error); // Add this line
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

  // async logout() {
  //     // does the db knows anything about logout?
  // }

  async refresh(userId) {
    const user = await db.query(
      `SELECT id, is_active FROM users WHERE id = $1`,
      [userId]
    );

    if (user.rows.length === 0) throw new Error("user not found");

    // if (!user.rows[0].is_active) // to do

    return jwt.genAccess(userId);
  }
}

module.exports = new AuthService();
