// Dependencies
const express = require('express')
const { body } = require('express-validator')
const userController = require('../controllers/userController')
const authMiddleware = require('../middlewares/authMiddleware')
const authorize = require('../middlewares/authorizeMiddleware'); // Import authorize middleware

const router = express.Router()

// Create user
router.post('/', [
    authMiddleware, // Authenticate first
    authorize('user:create'), // Then authorize
    body('username').trim().notEmpty().withMessage('Le nom d\'utilisateur est requise.').isLength({ min: 8, max: 20 }).withMessage('Le nom d\'utilisateur doit contenir entre 8 et 20 caractères..'),
    body('email').trim().notEmpty().withMessage('Email is required.').isEmail().withMessage('Format d\'e-mail invalide'),
    body('password').trim().notEmpty().withMessage('Le mot de passe est requis.').isLength({ min: 8 }).withMessage('Le mot de passe doit contenir au moins 8 caractères.'),
    body('password_confirmation')
        .trim()
        .notEmpty().withMessage("La confirmation du mot de passe est requise.")
        .isLength({ min: 8 }).withMessage("La confirmation du mot de passe doit contenir au moins 8 caractères.")
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('La confirmation du mot de passe ne correspond pas au mot de passe.');
            }
            return true;
        })
]
    , userController.createUser)

// Get users
router.get('/', [
    authMiddleware,
    authorize('user:read_all')
], userController.getUsers);

// Get user by ID
router.get('/:userId', [
    authMiddleware,
    authorize('user:read_one')
], userController.getUser);

// Update user by ID
router.put('/:userId', [
    authMiddleware,
    authorize('user:update_any'), // Permission to update any user's profile
    body('username').optional().trim().isLength({ min: 8, max: 20 }).withMessage('Le nom d\'utilisateur doit contenir entre 8 et 20 caractères..'),
    body('email').optional().trim().isEmail().withMessage('Format d\'e-mail invalide'),
], userController.updateUser);

// Assign role to user
router.post('/:userId/roles', [
    authMiddleware,
    authorize('user:assign_role'),
    body('roleId').isInt({ gt: 0 }).withMessage("L'ID du rôle doit être un entier valide.")
], userController.assignRole);

// Remove role from user
router.post('/:userId/roles/:roleId', [
    authMiddleware,
    authorize('user:remove_role'),
], userController.removeRole);


// Delete user by ID
router.delete('/:userId', [
    authMiddleware,
    authorize('user:delete')
], userController.deleteUser);

module.exports = router