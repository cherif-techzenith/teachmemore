// Dependencies
const jwt = require('jsonwebtoken')

const authenticate = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if(!token){
        return res.status(401).json({
            error: 'Authorization token is required'
        });
    }

    try {
        const jwtSecret = process.env.JWT_SECRET;
        const decoded = jwt.verify(token, jwtSecret);
        req.user = decoded;
        next();
    } catch (error) {
        console.error("JWT verification error: ", error);
        return res.status(500).json({
            error: 'Invalid token.'
        })
    }
}

module.exports = authenticate