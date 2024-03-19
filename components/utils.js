function errorResponse(res, message, status = 400) {
    res.status(status).send({ status: 'failed', message })
}

module.exports = {
    extractFromObj,
    errorResponse
}