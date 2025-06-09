// Dependencies
const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');

const router = express.Router()

// User registration
router.post('/register', [
    body('username')
        .trim()
        .notEmpty().withMessage("Le nom d'utilisateur est requis.")
        .isLength({min: 8, max: 20}).withMessage("Le nom d'utilisateur doit contenir entre 8 et 20 caractères."),
    body('email')
        .trim()
        .notEmpty().withMessage("L'adresse e-mail est requise.")
        .isEmail().withMessage("Format d'e-mail invalide."),
    body('password')
        .trim()
        .notEmpty().withMessage("Le mot de passe est requis.")
        .isLength({ min: 8 }).withMessage("Le mot de passe doit contenir au moins 8 caractères."),
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
], authController.register)

// User login
router.post('/login', [
    body('identifier')
        .trim()
        .notEmpty().withMessage("Le nom d'utilisateur ou l'e-mail est requis."),
    body('password')
        .trim()
        .notEmpty().withMessage("Le mot de passe est requis.")
], authController.login)

// Get account details
router.get('/me', [authMiddleware], authController.me);

// Update user by ID
router.put('/update',[
    body('username')
        .optional()
        .trim()
        .isLength({min: 8, max: 20}).withMessage("Le nom d'utilisateur doit contenir entre 8 et 20 caractères."),
    body('email')
        .optional()
        .trim()
        .isEmail().withMessage("Format d'e-mail invalide."),
], [authMiddleware], authController.update);

// Refresh token
router.post('/refresh-token', [authMiddleware], authController.refreshToken)

// Revoke token
router.post('/revoke-token', [authMiddleware], authController.revokeToken)

// Forgot password
router.post('/forgot-password', authController.forgotPassword)

// Reset password
router.post('/reset-password/:token', [
    body('password')
        .trim()
        .notEmpty().withMessage('Le mot de passe est requis.')
        .isLength({ min: 8 }).withMessage("Le mot de passe doit contenir au moins 8 caractères."),
    body('password_confirmation')
        .trim()
        .notEmpty().withMessage('La confirmation du mot de passe est requise.')
    .isLength({ min: 8 }).withMessage("La confirmation du mot de passe doit contenir au moins 8 caractères.")
    .custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('La confirmation du mot de passe ne correspond pas au mot de passe.');
        }
        return true;
    }),
], authController.resetPassword)

// Logout
router.post('/logout', authController.logout)

// Email Verification Route
router.get('/verify-email/:token', authController.verifyEmail);

// Resend Email Verification Route
router.post('/resend-verification-email', [
    body('email')
        .trim()
        .notEmpty().withMessage("L'adresse e-mail est requise.")
        .isEmail().withMessage("Format d'e-mail invalide.")
], authController.resendVerificationEmail);

module.exports = router