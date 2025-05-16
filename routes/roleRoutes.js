// Dependencies
const express = require('express');
const { body } = require('express-validator');
const roleController = require('../controllers/roleController');
const authMiddleware = require('../middlewares/authMiddleware')

const router = express.Router();

// Get roles
router.get('/', [authMiddleware], roleController.getRoles);

// Create role
router.post('/', [
    body('name').trim().notEmpty().withMessage('Name is required.')
], [authMiddleware], roleController.createRole)

// Get role by ID
router.get('/:roleId', [authMiddleware], roleController.getRoleById);

// Update role
router.put('/:roleId', [
    body('name').optional()
], [authMiddleware], roleController.updateRole)

// Delete role
router.delete('/:roleId', [authMiddleware], roleController.deleteRole);


module.exports = router