const express = require('express')

const router = express.Router()
const UserController = require('../controllers/UserController')

// Get users
router.get('/', UserController.index)

// Get user
router.get('/:username', UserController.getUser)

// Create user
router.post('/create', UserController.create)

// Update user
router.patch('/update', UserController.update)

// Delete user
router.delete('/delete', UserController.destroy)

module.exports = router