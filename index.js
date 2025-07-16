require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const routes = require('./routes/auth_routes');

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use('/', routes);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`running on ${PORT}. env: ${process.env.ENV_STATE}`)
});