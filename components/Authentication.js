const Joi = require('@hapi/joi');

class Authentication {

    constructor() { }

    middlewareValidation(data) {
        const middlewareSchema = Joi.object({
            email: Joi.string().min(6).max(100).required().email(),
        });

        return middlewareSchema.validate(data).error;
    }

    registerValidation(data) {
        const userSchema = Joi.object({
            username: Joi.string().min(2).max(255).required(),
            password: Joi.string().min(8).max(255).required(),
            pin: Joi.number().min(0).max(9999).required(),
            email: Joi.string().min(6).max(100).required().email(),
            AppName: Joi.string().min(4).required(),
            AppVersion: Joi.required(),
        });

        return userSchema.validate(data).error;
    }

    loginValidation(data) {
        const loginSchema = Joi.object({
            email: Joi.string().min(2).max(255).required(),
            password: Joi.string().min(8).required()
        });

        return loginSchema.validate(data).error;
    }

    identifierValidation(data) {
        const identifierSchema = Joi.object({
            identifier: Joi.string().min(2).max(100).required()
        });

        return identifierSchema.validate(data).error;
    }

    passwordValidation(data) {
        const passwordSchema = Joi.object({
            password: Joi.string().min(8).max(255).required(),
            email: Joi.string().min(6).max(100).required().email(),
            pin: Joi.number().min(0).max(9999).required()
        });

        return passwordSchema.validate(data).error;
    }
}

module.exports = Authentication