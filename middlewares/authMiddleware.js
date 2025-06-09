// Dependencies
const jwt = require('jsonwebtoken')
const tokenDenylist = require('../utils/tokenDenylist'); // Import the denylist
const userService = require('../services/userService'); // Or your authService

const authenticate = async(req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if(!token){
        return res.status(401).json({
            error: 'Token d\'autorisation est requis'
        });
    }

    // Check if the token is in the denylist
    if (tokenDenylist.has(token)) {
        return res.status(401).json({
            error: 'Token invalide.' // Token has been revoked
        });
    }

    try {
        const jwtSecret = process.env.JWT_ACCESS_SECRET;
        if (!jwtSecret) {
            console.error("JWT_ACCESS_SECRET is not defined in environment variables.");
            return res.status(500).json({
                error: 'Erreur de configuration interne du serveur.'
            });
        }
        const decodedTokenPayload = jwt.verify(token, jwtSecret); // This is just the JWT payload
        
        // Fetch full user auth data including roles and permissions from DB
        const userAuthData = await userService.getUserAuthData(decodedTokenPayload.userId);

        if (!userAuthData || !userAuthData.is_active) {
            // User not found in DB or is inactive
            return res.status(401).json({ error: 'Utilisateur non trouvé ou inactif.' });
        }

        req.user = {
            userId: userAuthData.user_id, // Ensure consistent casing if needed
            username: userAuthData.username,
            email: userAuthData.email,
            roles: userAuthData.roles || [],
            permissions: userAuthData.permissions || []
        };

        next();
    } catch (error) {
        console.error("Erreur de vérification JWT : ", error.message);
        // Differentiate between token expiration and other verification errors
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: 'Token expiré.'
            });
        }
        return res.status(401).json({
            error: 'Token invalide.'
        })
    }
}

module.exports = authenticate