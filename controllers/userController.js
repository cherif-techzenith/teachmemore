// Dependencies
// const { Pool } = require('pg'); // No longer directly needed here
// const bcrypt = require('bcryptjs'); // Moved to userService
// const { v4: uuidv4 } = require('uuid'); // Moved to userService
const { validationResult } = require('express-validator');
// const { pool } = require('../config/database'); // No longer needed for direct user/role assignment queries
const userService = require('../services/userService');
const userRoleService = require('../services/userRoleService'); // Import the new service

// Create user
const createUser = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            errors: errors.array()
        });
    }

    const { username, email, password } = req.body;

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

        const newUser = await userService.createUser({ username, email, password });
        // Note: newUser from userService.createUser now returns { user: actualNewUser, verificationToken }
        // So, to get user details, it should be newUser.user.user_id, newUser.user.username etc.
        res.status(201).json({
            message: 'Utilisateur créé avec succès',
            user: { userId: newUser.user.user_id, username: newUser.user.username, email: newUser.user.email }
        });

    } catch (error) {
        console.error("Erreur lors de la création de l'utilisateur : ", error);
        res.status(500).json({
            error: 'Erreur interne du serveur.'
        });
    }
}

// Get users
const getUsers = async (req, res) => {
    try {
        const page = parseInt(req.query.page, 10) || 1;
        const limit = parseInt(req.query.limit, 10) || 10;

        const result = await userService.getAllUsers({ page, limit });

        res.status(200).json(result);
        // The response will now look like:
        // { users: [...], totalUsers: N, currentPage: X, totalPages: Y }

    } catch (error) {
        console.error('Erreur lors de la récupération des utilisateurs : ', error);
        res.status(500).json({
            error: 'Erreur interne du serveur.'
        });
    }
}

// Get user by ID (changed from username to userId for robustness)
const getUser = async (req, res) => {
    const { userId } = req.params; // Expecting /users/:userId

    try {
        const user = await userService.findUserById(userId);

        if (!user) {
            return res.status(404).json({
                error: 'Utilisateur non trouvé'
            });
        }
        res.status(200).json(user);

    } catch (error) {
        console.error("Erreur lors de la récupération de l'utilisateur : ", error);
        res.status(500).json({
            error: 'Erreur interne du serveur.'
        });
    }
}

// Update user by ID (changed from username to userId for robustness)
const updateUser = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            errors: errors.array()
        })
    }

    const { userId } = req.params; // Expecting /users/:userId
    const { username, email } = req.body;

    try {
        const currentUser = await userService.findUserById(userId);
        if (!currentUser) {
            return res.status(404).json({
                error: 'Utilisateur non trouvé',
            });
        }

        if (username || email) {
            const conflictingUser = await userService.findExistingUser(
                username || currentUser.username,
                email || currentUser.email,
                userId // Exclude self
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

        const rowCount = await userService.updateUser(userId, { username, email });

        if (rowCount === 0 && (username || email)) {
            return res.status(400).json({
                error: "Échec de la mise à jour de l'utilisateur. Aucune modification n'a été apportée."
            })
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

// Delete user by ID (changed from username to userId for robustness)
const deleteUser = async (req, res) => {
    const { userId } = req.params; // Expecting /users/:userId

    try {
        const user = await userService.findUserById(userId);
        if (!user) {
            return res.status(404).json({
                error: 'Utilisateur non trouvé.'
            })
        }

        // Consider what happens to related data (e.g., user_roles).
        // You might need to delete from related tables first or use CASCADE.
        const deleteUserQuery = 'DELETE FROM users WHERE user_id = $1';
        await userService.pool.query(deleteUserQuery, [userId]); // Or move deleteUser to userService

        res.status(200).json({
            message: 'Utilisateur supprimé avec succès'
        })

    } catch (error) {
        console.error("Erreur lors de la suppression de l'utilisateur : ", error);
        res.status(500).json({
            error: 'Erreur interne du serveur.'
        });
    }
}

// Assign role to user
const assignRole = async (req, res) => {
    const errors = validationResult(req); // Ensure validation for userId and roleId
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { userId } = req.params;
    const { roleId } = req.body; // Correctly get roleId from body as per route definition

    try {
        const assigned = await userRoleService.assignRoleToUser(userId, roleId);
        if (!assigned) {
            return res.status(409).json({ error: 'User already has this role.' });
        }
        res.status(200).json({ message: 'Role assigned to user successfully.' });
    } catch (error) {
        console.error('Error assigning role to user: ', error);
        if (error.statusCode === 404) {
            return res.status(404).json({ error: error.message });
        }
        if (error.code === '23503') { // Foreign key violation (e.g. user_id or role_id does not exist)
            return res.status(404).json({ error: 'User or Role not found.' });
        }
        res.status(500).json({ error: 'Internal server error.' });
    }
};


// Remove role from user
const removeRole = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { userId, roleId } = req.params; // Correctly get both from params as per route definition

    try {
        const removed = await userRoleService.removeRoleFromUser(userId, roleId);

        if (!removed) {
            return res.status(404).json({ error: 'Role assignment not found for this user or role does not exist.' });
        }
        res.status(200).json({ message: 'Role removed from user successfully.' });

    } catch (error) {
        console.error('Error removing role from user: ', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
};

module.exports = {
    createUser, updateUser,
    getUser, getUsers,
    deleteUser,
    assignRole, removeRole
}