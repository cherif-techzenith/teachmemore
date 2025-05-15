// Dependencies
const express = require('express');
const { body } = require('express-validator');
const roleController = require('../controllers/roleController');

const router = express.Router();

// Get roles
router.get('/', roleController.getRoles);

// Create role
router.post('/', [
    body('name').trim().notEmpty().withMessage('Name is required.')
], roleController.createRole)

// Get role by ID
router.get('/:roleId', roleController.getRoleById);

// Update role
router.put('/:roleId', [
    body('name').optional()
], roleController.updateRole)

// Delete role
router.delete('/:roleId', roleController.deleteRole);


module.exports = router