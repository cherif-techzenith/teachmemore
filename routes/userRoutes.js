// Dependencies
const express = require('express')
const { body } = require('express-validator')
const userController = require('../controllers/userController')

const router = express.Router()

// Create user
router.post('/', [
    body('username').trim().notEmpty().withMessage('Username is required.').isLength({min: 8, max: 20}).withMessage('Username must be between 8 and 20 characters.'),
    body('email').trim().notEmpty().withMessage('Email is required.').isEmail().withMessage('Invalid email format'),
    body('password').trim().notEmpty().withMessage('Password is required.').isLength(8).withMessage('Password must be at least 8 characters.')
], userController.createUser)

// Get users
router.get('/', userController.getUsers);

// Get user by ID
router.get('/:user', userController.getUser);

// Update user by ID
router.put('/:user',[
    body('username').optional().trim().isLength({min: 8, max: 20}).withMessage('Username must be between 8 and 20 characters.'),
    body('email').optional().trim().isEmail().withMessage('Invalid email format'),
], userController.updateUser);

// Delete user by ID
router.delete('/:user', userController.deleteUser);

module.exports = router