const db = require('../debug/db');
const jwtService = require('../services/jwt');
const config = require('../config');
const isHash = require('../util/is_hash');

class AuthService {
    async register(userData) {
        const { last_name, first_name, patronymic, is_male, email, password } = userData; 

        if (config.client.passwdHashed && !this.isHash(password)) {
            throw new Error('user password must be hashed on the client-side');
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
            throw new Error('user creation in the db is failed due to:', error);
        }
    }

    async login(email, password) {

    }

    async logout() {

    }

    async refresh() {

    }
}

module.exports = new AuthService();