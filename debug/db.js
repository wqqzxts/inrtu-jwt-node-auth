const { Pool } = require('pg');

const pool = new Pool({
    user: process.env.PG_USER || 'postgres',
    host: process.env.PG_HOST || 'localhost',
    database: process.env.PG_DATABASE || 'debug-jwt-node-auth',
    password: process.env.PG_PASSWORD || '1024',
});

module.exports = {
    query: (text, params) => pool.query(text, params),
};