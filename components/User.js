const db = require('../config/database');
const jwt = require('jsonwebtoken');

class User {

    constructor() {
        this.tokenExpirationTime = process.env.TOKEN_EXPITATION_TIME ?? '6h'
    }

    updateUserToken(userId) {
        const token = jwt.sign({ _id: userId }, process.env.TOKEN_SECRET, { expiresIn: this.tokenExpirationTime });

        // save new device data and token
        const insertQuery = 'UPDATE users SET jwt_token = ? WHERE id = ?';
        db.query(insertQuery, [ token, userId]);

        return token
    }
}

module.exports = User