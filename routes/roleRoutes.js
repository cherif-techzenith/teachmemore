// Dependencies
const express = require('express');
const { body } = require('express-validator');
const roleController = require('../controllers/roleController');
const authMiddleware = require('../middlewares/authMiddleware');
const authorize = require('../middlewares/authorizeMiddleware'); // Import authorize middleware

const router = express.Router();

// Get roles
router.get('/', [
    authMiddleware,
    authorize('role:read_all')
], roleController.getRoles);

// Create role
router.post('/', [
    authMiddleware,
    authorize('role:create'),
    body('name').trim().notEmpty().withMessage('Name is required.')
], roleController.createRole)

// Get role by ID
router.get('/:roleId', [
    authMiddleware,
    authorize('role:read_one')
], roleController.getRoleById);

// Update role
router.put('/:roleId', [
    authMiddleware,
    authorize('role:update'),
    body('name').optional()
], roleController.updateRole)

// Delete role
router.delete('/:roleId', [
    authMiddleware,
    authorize('role:delete')
], roleController.deleteRole);

// Future: Routes for assigning/removing permissions to/from roles would use authorize('role:manage_permissions')

module.exports = router