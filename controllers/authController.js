const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { validationResult } = require('express-validator');
const { pool } = require('../config/database');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const userService = require('../services/userService');
const tokenDenylist = require('../utils/tokenDenylist');
const notificationServiceClient = require('../services/notificationServiceClient');

// User registration
const register = async(req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array()
        });
    }

    const { username, email, password, password_confirmation } = req.body;

    try {
        const existingUser = await userService.findExistingUser(username, email);
        if (existingUser) {
            if (existingUser.username === username) {
                return res.status(409).json({
                    error: "Nom d'utilisateur déjà existant."
                });
            } else if (existingUser.email === email) {
                return res.status(409).json({
                    error: 'Adresse e-mail déjà existante.'
                });
            }
        }
        
        if (password !== password_confirmation) {
            return res.status(409).json({
                error: 'La confirmation du mot de passe ne correspond pas.'
            })
        }

        const { user: newUser, verificationToken } = await userService.createUser({ username, email, password });

        // Construct verification URL
        const verificationUrl = `${req.protocol}://${req.get('host')}/auth/verify-email/${verificationToken}`;

        // Send email verification via the notification service client
        await notificationServiceClient.sendEmailVerification(newUser.email, newUser.username, verificationUrl);

        res.status(201).json({
            message: "Utilisateur enregistré avec succès. Veuillez vérifier votre e-mail pour valider votre compte."
        });

    } catch (error) {
        console.error("Erreur lors de l'inscription : ", error);
        res.status(500).json({
            error: 'Erreur interne du serveur.'
        });
    }
}

// User login
const login = async(req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array()
        });
    }

    const { identifier, password } = req.body;

    try {
        const user = await userService.findUserByIdentifier(identifier);

        if (!user) {
            return res.status(401).json({
                error: 'Identifiants invalides.',
            })
        }
        
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({
                error: 'Mot de passe incorrect.'
            });
        }

        // Check if user is verified
        if (!user.is_verified) {
            return res.status(403).json({
                error: 'Veuillez vérifier votre e-mail avant de vous connecter.',
            });
        }

        await userService.updateUserLastLogin(user.user_id);

        const payload = {
            userId: user.user_id,
            username: user.username,
            email: user.email
            // Add other claims like roles if necessary
        };

        const accessToken = jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
            expiresIn: '1h'
        });
        const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
            expiresIn: '7d' // Longer-lived
        });

        res.status(200).json({
            message: 'Connexion réussie.',
            accessToken: accessToken,
            refreshToken: refreshToken,
        })

    } catch (error) {
        console.error('Erreur lors de la connexion : ', error);
        res.status(500).json({
            error: 'Erreur interne du serveur.'
        })
    }
}

// Get account details
const me = async(req, res) => {
    const { user: authenticatedUser } = req; // Assuming auth middleware populates req.user
    console.log(authenticatedUser)
    if (!authenticatedUser || !authenticatedUser.userId) {
        return res.status(401).json({ error: "Non autorisé. Données utilisateur non trouvées dans le token." });
    }
    try {
        const userData = await userService.findUserById(authenticatedUser.userId);
        if (!userData) {
            return res.status(404).json({
                error: 'Utilisateur non trouvé'
            });
        }
        const { password, ...userToSend } = userData;
        res.status(200).json(userToSend);
    } catch (error) {
        console.error("Erreur lors de la récupération de l'utilisateur : ", error);
        res.status(500).json({
            error: 'Erreur interne du serveur.'
        });
    }
}

// Update account details
const update = async(req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array()
        })
    }

    const { user: authenticatedUser } = req; // from auth middleware
    const { username, email } = req.body;

    if (!authenticatedUser || !authenticatedUser.userId) {
        return res.status(401).json({ error: 'Non autorisé' });
    }

    try {
        const currentUser = await userService.findUserById(authenticatedUser.userId);
        if (!currentUser) {
            return res.status(404).json({
                error: 'Utilisateur non trouvé',
            });
        }

        if (username || email) {
            const conflictingUser = await userService.findExistingUser(
                username || currentUser.username,
                email || currentUser.email,
                authenticatedUser.userId
            );

            if (conflictingUser) {
                if (username && conflictingUser.username === username) {
                    return res.status(409).json({ error: "Nom d'utilisateur déjà existant." });
                }
                if (email && conflictingUser.email === email) {
                    return res.status(409).json({ error: 'Adresse e-mail déjà existante.' });
                }
            }
        }

        const updateFields = {};
        if (username) updateFields.username = username;
        if (email) updateFields.email = email;

        if (Object.keys(updateFields).length > 0) {
            const rowCount = await userService.updateUser(authenticatedUser.userId, updateFields);
            if (rowCount === 0) {
                return res.status(400).json({
                    error: "Échec de la mise à jour de l'utilisateur. Aucune modification n'a été apportée ou l'utilisateur n'a pas été trouvé."
                });
            }
        }

        res.status(200).json({
            message: 'Utilisateur mis à jour avec succès.'
        })
        
    } catch (error) {
        console.error("Erreur lors de la mise à jour de l'utilisateur : ", error);
        res.status(500).json({
            error: 'Erreur interne du serveur.'
        });
    }
}

// Change Password
const changePassword = async (req, res) => {
    const errors = validationResult(req); // Ensure validation rules for passwords
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { user: authenticatedUser } = req; // from auth middleware
    const { current_password, new_password, new_password_confirmation } = req.body;

    if (!authenticatedUser || !authenticatedUser.userId) {
        return res.status(401).json({ error: 'Non autorisé' });
    }

    if (new_password !== new_password_confirmation) {
        return res.status(400).json({ error: 'Les nouveaux mots de passe ne correspondent pas.' });
    }

    // TODO: Add password strength validation for new_password (e.g., using express-validator)

    try {
        const user = await userService.findUserByIdentifier(authenticatedUser.username);
        if (!user) {
            return res.status(404).json({ error: 'Utilisateur non trouvé.' });
        }

        const isMatch = await bcrypt.compare(current_password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Mot de passe actuel incorrect.' });
        }

        const hashedNewPassword = await bcrypt.hash(new_password, 10);
        const query = 'UPDATE users SET password = $1, updated_at = NOW() WHERE user_id = $2';
        await pool.query(query, [hashedNewPassword, authenticatedUser.userId]);

        // Optionally, revoke all existing tokens for the user here for added security.

        res.status(200).json({ message: 'Mot de passe modifié avec succès.' });
    } catch (error) {
        console.error('Erreur lors du changement de mot de passe :', error);
        res.status(500).json({ error: 'Erreur interne du serveur.' });
    }
};

// Refresh token
const refreshToken = (req, res) => {
    const { refreshToken } = req.body;

    if(!refreshToken){
        return res.status(401).json({
            error: 'Le token de rafraîchissement est requis.'
        });
    }

    if (tokenDenylist.has(refreshToken)) {
        return res.status(403).json({ error: 'Le token de rafraîchissement a été révoqué.' });
    }

    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, decoded) => {
        if (err) {
            return res.status(403).json({
                error: 'Token de rafraîchissement invalide ou expiré.'
            });
        }

        // Check if user still exists or is active in DB
        const userExists = await userService.findUserById(decoded.userId);
        if (!userExists || !userExists.is_verified) {
            return res.status(403).json({ error: "L'utilisateur n'est plus actif ou n'a pas été trouvé." });
        }

        const payload = {
            userId: decoded.userId,
            username: decoded.username,
            email: decoded.email
        };

        const newAccessToken = jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
            expiresIn: '1h'
        });

        res.status(200).json({
            message: 'Token rafraîchi avec succès.',
            accessToken: newAccessToken
        });
    });
}

// Revoke token
const revokeToken = (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        tokenDenylist.add(token);
        // If client sends refresh token to be revoked along with access token
        const { refreshTokenToRevoke } = req.body;
        if (refreshTokenToRevoke) {
            tokenDenylist.add(refreshTokenToRevoke);
        }
         res.status(200).json({ message: 'Token(s) révoqué(s) avec succès.' });
    } else {
        // If no access token in header, maybe they only want to revoke a refresh token sent in body
        const { refreshTokenToRevoke } = req.body;
        if (refreshTokenToRevoke) {
            tokenDenylist.add(refreshTokenToRevoke);
            return res.status(200).json({ message: 'Token de rafraîchissement révoqué avec succès.' });
        }
        res.status(400).json({ error: 'Aucun token fourni à révoquer.' });
    }
};

// Forgot password
const forgotPassword = async (req, res) => {
    const { email } = req.body;

    if(!email){
        return res.status(400).json({
            error: 'L\'adresse e-mail est requise.'
        });
    }

    try {
        const user = await userService.findUserByIdentifier(email); // findUserByIdentifier can find by email

        if (!user) {
            // To prevent email enumeration, always return a 200 OK response.
            console.warn(`Password reset attempt for non-existent or unverified email: ${email}`);
            return res.status(200).json({ // Message en français
                message: "Si un compte avec cette adresse e-mail existe et est vérifié, un lien de réinitialisation de mot de passe a été envoyé."
            }); // Fin du message en français
        }

        // Generate a secure reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        // Hash the token before storing it in the database
        const hashedResetToken = await bcrypt.hash(resetToken, 10);

        // Set token expiry (e.g., 1 hour)
        const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour from now

        // Store the hashed reset token, its expiry, and creation time in the password_reset_tokens table
        const insertTokenQuery = `
            INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at)
            VALUES ($1, $2, $3, NOW())
        `;
        await pool.query(insertTokenQuery, [user.user_id, hashedResetToken, resetTokenExpires]);

        // Construct reset URL (send the raw token in the URL)
        const resetUrl = `${req.protocol}://${req.get('host')}/auth/reset-password/${resetToken}`;

        // TODO: Integrate with notificationServiceClient for password reset emails
        // Example: await notificationServiceClient.sendPasswordResetEmail(user.email, user.username, resetUrl);
        console.log(`Password Reset URL (for ${user.email}): ${resetUrl}`); // For development/testing

        res.status(200).json({ // Message en français
            message: "Si un compte avec cette adresse e-mail existe et est vérifié, un lien de réinitialisation de mot de passe a été envoyé."
        }); // Fin du message en français

    } catch (error) {
        console.error('Erreur lors de la demande de réinitialisation de mot de passe : ', error);
        res.status(500).json({
            error: 'Erreur interne du serveur.'
        });
    }
};

// Reset password
const resetPassword = async (req, res) => {
    const { token: rawResetToken } = req.params; // The raw token from the URL
    const { password, password_confirmation } = req.body;

    const errors = validationResult(req); // Ensure you have validation rules for password
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    if (password !== password_confirmation) {
        return res.status(400).json({ error: 'Les mots de passe ne correspondent pas.' });
    }

    // TODO: Add password strength validation here or via express-validator

    try {
        // Find users with non-expired password_reset_token.
        // Fetch candidate tokens from the password_reset_tokens table.
        const candidatesQuery = `
            SELECT user_id, token 
            FROM password_reset_tokens 
            WHERE expires_at > NOW()
        `;
        const { rows: candidates } = await pool.query(candidatesQuery);

        let matchedTokenEntry = null;
        for (const candidate of candidates) {
            if (await bcrypt.compare(rawResetToken, candidate.token)) {
                matchedTokenEntry = candidate; // Contains user_id and the hashed token
                break;
            }
        }

        if (!matchedTokenEntry) {
            return res.status(400).json({ error: 'Token de réinitialisation de mot de passe invalide ou expiré.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Update user's password in the users table
        const updateUserQuery = `
            UPDATE users 
            SET password = $1, updated_at = NOW()
            WHERE user_id = $2
        `;
        await pool.query(updateUserQuery, [hashedPassword, matchedTokenEntry.user_id]);

        // Delete the used token from password_reset_tokens table
        await pool.query('DELETE FROM password_reset_tokens WHERE token = $1 AND user_id = $2', [matchedTokenEntry.token, matchedTokenEntry.user_id]);

        res.status(200).json({ message: 'Le mot de passe a été réinitialisé avec succès.' });

    } catch (error) {
        console.error('Erreur lors de la réinitialisation du mot de passe : ', error);
        res.status(500).json({ error: 'Erreur interne du serveur.' });
    }
};

// Logout
const logout = (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token) {
        tokenDenylist.add(token);
    }
    // Optionally, if the client sends the refresh token in the body for logout:
    const { refreshToken } = req.body;
    if (refreshToken) {
        tokenDenylist.add(refreshToken);
    }

    // Client should also clear its stored tokens.
    res.status(200).json({ message: 'Déconnexion réussie. Veuillez effacer vos tokens localement.' });
};

// Email verification endpoint
const verifyEmail = async (req, res) => {
    const { token: verificationToken } = req.params;

    if (!verificationToken) {
        return res.status(400).json({ error: 'Le token de vérification est requis.' });
    }

    try {
        const tokenDetails = await userService.findUserByVerificationToken(verificationToken);

        if (!tokenDetails) {
            return res.status(400).json({ error: "token de vérification invalide ou expiré. Veuillez vous enregistrer à nouveau ou demander un nouvel e-mail de vérification." });
        }

        if (tokenDetails.is_verified) {
            return res.status(200).json({ message: 'Adresse e-mail déjà vérifiée. Vous pouvez vous connecter.' });
        }

        await userService.verifyUserEmail(verificationToken); // Pass the token itself
        res.status(200).json({ message: 'Adresse e-mail vérifiée avec succès. Vous pouvez maintenant vous connecter.' });
    } catch (error) {
        console.error("Erreur lors de la vérification de l'e-mail :", error);
        res.status(500).json({ error: "Erreur interne du serveur lors de la vérification de l'e-mail." });
    }
};

// Resend Email Verification
const resendVerificationEmail = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: "L'adresse e-mail est requise." });
    }

    try {
        const user = await userService.findUserByIdentifier(email);

        if (!user) {
            // To prevent email enumeration, always return a success-like message
            console.warn(`Resend verification attempt for non-existent email: ${email}`);
            return res.status(200).json({ message: "Si un compte avec cette adresse e-mail existe et n'est pas encore vérifié, un nouvel e-mail de vérification a été envoyé." });
        }

        if (user.is_verified) {
            return res.status(400).json({ message: 'Cette adresse e-mail est déjà vérifiée.' });
        }

        // Generate and store a new token
        const newVerificationToken = await userService.generateNewVerificationToken(user.user_id);

        if (!newVerificationToken) {
            // Should not happen if user was found, but as a safeguard
            console.error(`Failed to generate new verification token for user: ${user.user_id}`);
            return res.status(500).json({ error: 'Erreur interne du serveur lors de la génération du token.' });
        }

        // Construct verification URL
        const verificationUrl = `${req.protocol}://${req.get('host')}/auth/verify-email/${newVerificationToken}`;

        // Send email verification via the notification service client
        await notificationServiceClient.sendEmailVerification(user.email, user.username, verificationUrl);

        res.status(200).json({ message: "Un nouvel e-mail de vérification a été envoyé à votre adresse." });

    } catch (error) {
        console.error("Erreur lors du renvoi de l'e-mail de vérification : ", error);
        res.status(500).json({ error: 'Erreur interne du serveur.' });
    }
};


module.exports = {
    register, login, logout,
    me, update, changePassword,
    refreshToken, revokeToken,
    forgotPassword, resetPassword,
    verifyEmail,
    resendVerificationEmail,
};