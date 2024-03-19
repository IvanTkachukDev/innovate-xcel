require('dotenv').config();

const router = require('express').Router();
const useragent = require('express-useragent');
const bcrypt = require('bcryptjs');
const requestIP = require('request-ip');

const { errorResponse, extractFromObj } = require('../../components/utils');
const Authentication = require('../../components/Authentication');
const Mailer = require('../../components/Mailer');
const User = require('../../components/User');
const db = require('../../config/database');

router.use(useragent.express());

const auth = new Authentication()
const user = new User()


function sendPinToEmail(res, email, pin, message) {
    const mailer = new Mailer('/validateEmailWithPIN.ejs');
    mailer.send(email, 'Email Pin Validation', { pin });

    res.status(201).send({
        status: "success",
        message: "We've just sent a verification PIN to your email address. Please check your inbox and paste it in the provided field to complete the verification process. " + message,
        pin
    });
}

// EMAIL VALIDATION
router.post('/validate-email', (req, res) => {
    const validationErrors = auth.middlewareValidation(req.body);
    if (validationErrors) return errorResponse(res, validationErrors.details[0].message);

    const email = req.body.email;

    // check if pin exists
    const selectPinQuery = 'SELECT * FROM pins WHERE email = ?';
    db.query(selectPinQuery, [email], (error, pinData) => {
        if (error) return errorResponse(res, error);

        const pin = Math.floor(Math.random() * 9000) + 1000;
        const message = "If you haven't received the email, please make sure you provided correct email."

        if (pinData.length) {
            const updatePinQuery = 'UPDATE pins SET requestTimes = requestTimes + 1, value = ? WHERE email = ? AND requestTimes <> 3';
            db.query(updatePinQuery, [pin, email], (error, result) => {
                if (error) return errorResponse(res, error);

                if (result.affectedRows === 0) {
                    // if no pin was updated, so the pin requests times are over limit
                    const hoursLeft = Math.floor((new Date() - new Date(pinData[0].updated_at)) / (1000 * 60 * 60));

                    // check if the last request was made more the N hours 
                    if (hoursLeft <= (process.env.UPDATE_DATA_EACH_HOURS || 5)) {
                        return errorResponse(res, 'Too many pin requests. Please try again later.', 429);
                    } else {
                        // reset pin if it was requested long enough time ago
                        const resetPinQuery = 'UPDATE pins SET requestTimes = 0, value = ? WHERE email = ?';
                        db.query(resetPinQuery, [pin, email], (error) => {
                            if (error) return errorResponse(res, error);

                            sendPinToEmail(res, email, pin, message)
                        });
                    }
                } else {
                    sendPinToEmail(res, email, pin, message)
                }
            });
        } else {
            // check if email is not registered
            const findUserQuery = `SELECT email FROM users WHERE email = ?`
            db.query(findUserQuery, [email], (error, result) => {
                if (error) return errorResponse(res, error);
                if (result.length) return errorResponse(res, 'User with the provided email already exists.', 409);

                // save pin
                const insertPinQuery = 'INSERT INTO pins (email, value, requestTimes) VALUES (?, ?, ?)';
                db.query(insertPinQuery, [email, pin, 0], (error) => {
                    if (error) return errorResponse(res, error);

                    sendPinToEmail(res, email, pin, message)
                });
            })
        }
    });
});

// PIN VALIDATION - USER ACCOUNT CREATION
router.post('/register', (req, res) => {
    const validationErrors = auth.registerValidation(req.body)
    if (validationErrors) return errorResponse(res, validationErrors.details[0].message)

    const { username, password, pin, email, AppName, AppVersion } = req.body
    const selectQuery = `SELECT value FROM pins
                        WHERE value = ? AND email = ? AND NOT EXISTS (
                            SELECT id FROM users
                            WHERE pins.email = users.email
                        )`;

    db.query(selectQuery, [pin, email], async (error, result) => {
        if (error) return errorResponse(res, error)
        if (!result.length) return errorResponse(res, 'Provided pin is not correct.', 409)

        // hash password
        const salt = await bcrypt.genSalt(10);
        const encryptedPassword = await bcrypt.hash(password, salt)

        // save user data
        const insertQuery = 'INSERT INTO users (username, email, password, ip, app_name, app_version) VALUES (?, ?, ?, ?, ?, ?)';
        db.query(insertQuery, [username, email, encryptedPassword, requestIP.getClientIp(req), AppName, AppVersion], (error, result) => {
            if (error) return errorResponse(res, error)

            // reset pin data after registration
            const resetPinQuery = 'UPDATE pins SET requestTimes = 0 WHERE email = ?';
            db.query(resetPinQuery, [email]);

            // generate token
            const token = user.updateUserToken(result.insertId)

            const selectQuery = 'SELECT * FROM users WHERE id = ?';
            db.query(selectQuery, [result.insertId], (dbError, userData) => {
                if (dbError) return dbError;

                let data = extractFromObj(userData[0], ['password', 'pin', 'jwt_token', 'passwordRequestTimes'])

                // create user  config file
                const uploadsError = handleUploadsDir(data)
                if (uploadsError) return errorResponse(res, uploadsError)

                res.status(201).send({ status: "success", token, data })
            })
        })
    })
})