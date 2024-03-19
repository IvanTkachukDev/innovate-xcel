const Joi = require('@hapi/joi');

class Authentication {

    constructor() { }

    middlewareValidation(data) {
        const middlewareSchema = Joi.object({
            productKey: Joi.string().length(36).required(),
            email: Joi.string().min(6).max(100).required().email(),
        });

        return middlewareSchema.validate(data).error;
    }

    registerValidation(data) {
        const userSchema = Joi.object({
            productKey: Joi.string().length(36).required(),
            username: Joi.string().min(2).max(255).required(),
            password: Joi.string().min(8).max(255).required(),
            pin: Joi.number().min(0).max(9999).required(),
            email: Joi.string().min(6).max(100).required().email(),
            AppName: Joi.string().min(4).required(),
            AppVersion: Joi.required(),
        });

        return userSchema.validate(data).error;
    }
}

module.exports = Authentication