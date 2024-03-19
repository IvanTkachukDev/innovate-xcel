require('dotenv').config()

const nodemailer = require('nodemailer');
const fs = require('fs');
const ejs = require('ejs');

class Mailer {

    constructor(template, sender = process.env.APP_EMAIL_ADDRESS) {
        this.emailTemplate = fs.readFileSync('./views/' + template, 'utf8');
        this.sender = sender
    }

    createTransport() {
        return nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.APP_EMAIL_ADDRESS,
                pass: process.env.APP_EMAIL_PASSWORD
            }
        })
    }

    send(recipient, subject, templateData = null, sender = null) {
        const mailOptions = {
            from: sender ? sender : this.sender,
            to: recipient,
            subject,
            html: ejs.render(this.emailTemplate, templateData)
        };

        const transporter = this.createTransport()

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('Email sent: ' + info.response);
            }
        })
    }
}

module.exports = Mailer