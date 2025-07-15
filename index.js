const express = require('express');
const cookieParser = require('cookie-parser');
const routes = require('./routes/auth_routes');

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use('/', routes);

app.listen(3000);
console.log('debug: listening on p: 3000');