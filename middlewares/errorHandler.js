const errorHandler = (err, req, res, next) => {
    console.error('Global error handler: ', err);
    res.status(500).json({
        error: 'Internal server error.',
        message: 'An unexpected error occured. Please try again later.'
    })
}

module.exports = errorHandler