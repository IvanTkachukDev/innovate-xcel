function extractFromObj(obj, keys) {
    return Object.fromEntries(
        Object.entries(obj).filter(([key, value]) =>
            !keys.includes(key))
    );
}

function errorResponse(res, message, status = 400) {
    res.status(status).send({ status: 'failed', message })
}

module.exports = {
    extractFromObj,
    errorResponse
}