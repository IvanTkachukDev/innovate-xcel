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
}

module.exports = Authentication