// services/userRoleService.js
const { pool } = require('../config/database');

/**
 * Assigns a role to a user.
 * @param {string} userId - The UUID of the user.
 * @param {number} roleId - The ID of the role.
 * @returns {Promise<boolean>} True if assignment was successful, false if it already existed.
 * @throws {Error} If user or role not found (foreign key constraint), or other DB error.
 */
const assignRoleToUser = async (userId, roleId) => {
    // Check if user exists (optional, as FK constraint will catch it, but can provide clearer error)
    const userCheck = await pool.query('SELECT user_id FROM users WHERE user_id = $1', [userId]);
    if (userCheck.rows.length === 0) {
        const error = new Error('User not found.');
        error.statusCode = 404;
        throw error;
    }

    // Check if role exists (optional, as FK constraint will catch it)
    const roleCheck = await pool.query('SELECT role_id FROM roles WHERE role_id = $1', [roleId]);
    if (roleCheck.rows.length === 0) {
        const error = new Error('Role not found.');
        error.statusCode = 404;
        throw error;
    }

    // Check if assignment already exists
    const existingAssignmentQuery = 'SELECT user_id FROM user_roles WHERE user_id = $1 AND role_id = $2';
    const existingAssignmentResult = await pool.query(existingAssignmentQuery, [userId, roleId]);
    if (existingAssignmentResult.rows.length > 0) {
        return false; // Indicates assignment already exists
    }

    const assignQuery = 'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)';
    await pool.query(assignQuery, [userId, roleId]);
    return true; // Indicates new assignment was made
};

/**
 * Removes a role from a user.
 * @param {string} userId - The UUID of the user.
 * @param {number} roleId - The ID of the role.
 * @returns {Promise<boolean>} True if role was removed, false if assignment was not found.
 * @throws {Error} If there's a database error.
 */
const removeRoleFromUser = async (userId, roleId) => {
    const removeQuery = 'DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2';
    const result = await pool.query(removeQuery, [userId, roleId]);
    return result.rowCount > 0;
};

module.exports = {
    assignRoleToUser,
    removeRoleFromUser,
};