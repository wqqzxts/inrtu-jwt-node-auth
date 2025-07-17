class CustomError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}

class BadRequestError extends CustomError {
    constructor(message) {
        super(message, 400)
    }
}

class UnauthorizedError extends CustomError {
    constructor(message) {
        super(message, 401)
    }
}

class ForbiddenError extends CustomError {
    constructor(message) {
        super(message, 403)
    }
}

class NotFoundError extends CustomError {
    constructor(message) {
        super(message, 404)
    }
}

class InternalServerError extends CustomError {
    constructor(message) {
        super(message, 500)
    }
}

module.exports = {
    CustomError,
    BadRequestError,
    UnauthorizedError,
    ForbiddenError,
    NotFoundError,
    InternalServerError,
};