require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const routes = require("./routes/routes");
const errorHandler = require("./middleware/error_handler")

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use("/", routes);
app.use(errorHandler);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`running on ${PORT}. env: ${process.env.ENV_STATE}`);
});
