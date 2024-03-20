const db = require('../config/database');
const { errorResponse } = require('../components/utils')

// routes exception
const routesExceptions = [
    '/innovate-xcel/api/user/register',
    '/innovate-xcel/api/user/login'
]


function checkJwtToken(req, res, next) {
    if (routesExceptions.includes(req.path)) {
        // If the route is an exception, proceed to the next middleware or route handler
        next();
    } else {
        const token = req.headers["auth-token"];

        // Check if token is provided
        if (!token) {
            return errorResponse(res, "Invalid request. Token is required. Please log in or provide valid credentials.", 401);
        }

        const insertQuery = 'SELECT jwt_token FROM users WHERE jwt_token = ?';
        db.query(insertQuery, [token], (error, result) => {
            if (error) {
                return errorResponse(res, error);
            }

            // Check if user is logged in
            if (!result || result.length === 0 || !result[0].jwt_token) {
                return errorResponse(res, "Invalid request. Token is required or not valid.");
            }

            next();
        });
    }
}

module.exports = checkJwtToken;