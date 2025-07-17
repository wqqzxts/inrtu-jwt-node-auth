function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal Server Error";

  if (process.env.ENV_STATE !== "prod") console.error(err.stack);

  res.status(statusCode).json({
    error: message,
  });
}

module.exports = errorHandler;
``