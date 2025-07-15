const { Pool } = require('pg');

const pool = new Pool({
    user: process.env.PG_USER || 'postgres',
    host: process.env.PG_HOST || 'localhost',
    port: process.env.PG_PORT || '1024',
    database: process.env.PG_DATABASE || 'debug-jwt-node-auth',
    password: process.env.PG_PASSWORD || '1111',
});

module.exports = {
    query: (text, params) => pool.query(text, params),
};