// Dependencies
const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');

const router = express.Router()

// User registration
router.post('/register', [
    body('username').trim().notEmpty().withMessage('Username is required.').isLength({min: 8, max: 20}).withMessage('Username must be between 8 and 20 characters.'),
    body('email').trim().notEmpty().withMessage('Email is required.').isEmail().withMessage('Invalid email format'),
    body('password').trim().notEmpty().withMessage('Password is required.').isLength(8).withMessage('Password must be at least 8 characters.'),
    body('password_confirmation').trim().notEmpty().withMessage('Password confirmation is required.').isLength(8).withMessage('Password confirmation must be at least 8 characters.')
], authController.register)

// User login
router.post('/login', [
    body('identifier').trim().notEmpty().withMessage('Username or Email is required.'),
    body('password').trim().notEmpty().withMessage('Password is required.')
], authController.login)

// Get account details
router.get('/me', [authMiddleware], authController.me);

// Update user by ID
router.put('/update',[
    body('username').optional().trim().isLength({min: 8, max: 20}).withMessage('Username must be between 8 and 20 characters.'),
    body('email').optional().trim().isEmail().withMessage('Invalid email format'),
], [authMiddleware], authController.update);

// Refresh token
router.post('/refresh-token', [authMiddleware], authController.refreshToken)

// Forgot password
router.post('/forgot-password', authController.forgotPassword)

// Reset password
router.post('/reset-password', authController.resetPassword)

// Logout
router.post('/logout', authController.logout)


module.exports = router