// middlewares/authorizeMiddleware.js

/**
 * Middleware to check if the authenticated user has the required permission(s).
 * @param {string | string[]} requiredPermissions - A single permission string or an array of permission strings.
 *                                                 If an array, the user must have ALL permissions in the array.
 */
const authorize = (requiredPermissions) => {
    return (req, res, next) => {
        if (!req.user || !req.user.roles || !req.user.permissions) {
            console.warn('Authorization check failed: req.user, req.user.roles, or req.user.permissions not found. Ensure authMiddleware runs first and populates them.');
            return res.status(403).json({ error: 'Accès interdit. Données utilisateur non chargées.' });
        }

        const superadminRoleName = process.env.SUPERADMIN_ROLE_NAME || 'superadmin';
        if (req.user.roles.includes(superadminRoleName)) {
            return next(); // Superadmin has universal access
        }

        if (!req.user.permissions) { // Should be redundant due to the check above, but good for safety
            return res.status(403).json({ error: 'Accès interdit. Permissions utilisateur non chargées.' });
        }

        const userPermissions = req.user.permissions;
        const permissionsToCheck = Array.isArray(requiredPermissions) ? requiredPermissions : [requiredPermissions];

        const hasAllPermissions = permissionsToCheck.every(p => userPermissions.includes(p));

        if (hasAllPermissions) {
            return next();
        }
        return res.status(403).json({ error: 'Accès interdit. Permissions insuffisantes.' });
    };
};

module.exports = authorize;