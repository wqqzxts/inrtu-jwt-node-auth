const db = require('../debug/db');
const jwtService = require('../services/jwt');
const config = require('../config');
const isHash = require('../util/is_hash');

class AuthService {
    async register(userData) {
        const { last_name, first_name, patronymic, is_male, email, password } = userData;
    }

    async login(email, password) {

    }

    async logout() {

    }

    async refresh() {

    }
}

module.exports = new AuthService();