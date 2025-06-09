// services/userService.js
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { pool } = require('../config/database');

const findUserByIdentifier = async (identifier) => {
    const query = 'SELECT user_id, username, email, password, last_login, is_verified, is_active FROM users WHERE username = $1 OR email = $1';
    const result = await pool.query(query, [identifier]);
    return result.rows.length > 0 ? result.rows[0] : null;
};

const findUserById = async (userId) => {
    const userQuery = `
        SELECT u.user_id, u.username, u.email, u.created_at, u.updated_at, u.last_login, u.is_verified, u.is_active
        FROM users u
        WHERE u.user_id = $1
    `;
    const rolesQuery = `
        SELECT r.name
        FROM roles r
        JOIN user_roles ur ON r.role_id = ur.role_id
        WHERE ur.user_id = $1
    `;
    const permissionsQuery = `
        SELECT DISTINCT p.name
        FROM permissions p
        JOIN role_permissions rp ON p.permission_id = rp.permission_id
        JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = $1
    `;

    const [userResult, rolesResult, permissionsResult] = await Promise.all([
        pool.query(userQuery, [userId]),
        pool.query(rolesQuery, [userId]),
        pool.query(permissionsQuery, [userId])
    ]);

    return userResult.rows.length > 0 ? { ...userResult.rows[0], roles: rolesResult.rows.map(r => r.name), permissions: permissionsResult.rows.map(p => p.name) } : null;
};

/**
 * Creates a new user in the database. */
const createUser = async ({ username, email, password }) => {
    const hashedPassword = await bcrypt.hash(password, 10);
    const insertUserQuery = `
        INSERT INTO users (username, email, password, created_at)
        VALUES($1, $2, $3, NOW())
        RETURNING user_id, username, email, created_at, is_verified, is_active
    `;
    const userResult = await pool.query(insertUserQuery, [username, email, hashedPassword]);
    const newUser = userResult.rows[0];

    if (!newUser || !newUser.user_id) {
        throw new Error('User creation failed, no user_id returned.');
    }

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpires = new Date(Date.now() + 24 * 3600000); // 24 hours

    const insertTokenQuery = `
        INSERT INTO email_verification_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
    `;
    await pool.query(insertTokenQuery, [newUser.user_id, verificationToken, verificationExpires]);

    return { user: newUser, verificationToken };
};

const updateUser = async (userId, updateFields) => {
    const { username, email } = updateFields;
    let updateQuery = 'UPDATE users SET updated_at = NOW()';
    const values = [];
    let valueIndex = 1;

    if (username) {
        updateQuery += `, username = $${valueIndex++}`;
        values.push(username);
    }
    if (email) {
        updateQuery += `, email = $${valueIndex++}`;
        values.push(email);
    }

    if (values.length === 0) {
        return 0;
    }

    updateQuery += ` WHERE user_id = $${valueIndex}`;
    values.push(userId);

    const result = await pool.query(updateQuery, values);
    return result.rowCount;
};

const updateUserLastLogin = async (userId) => {
    const updateLastLoginQuery = "UPDATE users SET last_login = NOW() WHERE user_id = $1";
    await pool.query(updateLastLoginQuery, [userId]);
};

const findExistingUser = async (username, email, excludeUserId = null) => {
    let query = 'SELECT user_id, username, email FROM users WHERE (username = $1 OR email = $2)';
    const queryParams = [username, email];
    if (excludeUserId) {
        query += ` AND user_id != $${queryParams.length + 1}`;
        queryParams.push(excludeUserId);
    }
    const result = await pool.query(query, queryParams);
    return result.rows.length > 0 ? result.rows[0] : null;
};

const findUserByVerificationToken = async (token) => {
    const query = `
        SELECT
            evt.user_id,
            u.is_verified
        FROM email_verification_tokens evt
        JOIN users u ON evt.user_id = u.user_id
        WHERE evt.token = $1 AND evt.expires_at > NOW()
    `;
    const result = await pool.query(query, [token]);
    return result.rows.length > 0 ? result.rows[0] : null;
};

const verifyUserEmail = async (token) => {
    const tokenData = await pool.query('SELECT user_id FROM email_verification_tokens WHERE token = $1 AND expires_at > NOW()', [token]);
    if (tokenData.rows.length === 0) return false;
    const userId = tokenData.rows[0].user_id;

    await pool.query('UPDATE users SET is_verified = TRUE, updated_at = NOW() WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM email_verification_tokens WHERE token = $1', [token]);
    return true;
};

/**
 * Generates a new email verification token for a user, deleting any old ones.
 * @param {string} userId - The UUID of the user.
 * @returns {Promise<string|null>} The new verification token, or null if user not found.
 */
const generateNewVerificationToken = async (userId) => {
    const user = await findUserById(userId);
    if (!user) {
        return null; // User not found
    }

    // Delete any existing unexpired tokens for this user
    await pool.query('DELETE FROM email_verification_tokens WHERE user_id = $1', [userId]);

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpires = new Date(Date.now() + 24 * 3600000); // 24 hours

    const insertTokenQuery = `
        INSERT INTO email_verification_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
    `;
    await pool.query(insertTokenQuery, [userId, verificationToken, verificationExpires]);

    return verificationToken;
};

/**
 * Fetches comprehensive authentication data for a user, including their roles and permissions.
 * @param {string} userId - The UUID of the user.
 * @returns {Promise<object|null>} An object with user details, roles, and permissions, or null if user not found.
 */
const getUserAuthData = async (userId) => {
    const userQuery = pool.query('SELECT user_id, username, email, is_active, is_verified FROM users WHERE user_id = $1', [userId]);
    const rolesQuery = pool.query(`
        SELECT r.name
        FROM roles r
        JOIN user_roles ur ON r.role_id = ur.role_id
        WHERE ur.user_id = $1
    `, [userId]);
    const permissionsQuery = pool.query(`
        SELECT DISTINCT p.name
        FROM user_roles ur
        JOIN role_permissions rp ON ur.role_id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.permission_id
        WHERE ur.user_id = $1;
    `, [userId]);

    const [userDataResult, rolesResult, permissionsResult] = await Promise.all([userQuery, rolesQuery, permissionsQuery]);

    if (userDataResult.rows.length === 0) {
        return null;
    }

    return {
        ...userDataResult.rows[0], // user_id, username, email, is_active, is_verified
        roles: rolesResult.rows.map(r => r.name),
        permissions: permissionsResult.rows.map(p => p.name)
    };
};

/**
 * Fetches all distinct permission names associated with a user's roles.
 * @param {string} userId - The UUID of the user.
 * @returns {Promise<string[]>} An array of permission names.
 */
const getUserRolesAndPermissions = async (userId) => {
    const query = `
        SELECT DISTINCT p.name
        FROM user_roles ur
        JOIN role_permissions rp ON ur.role_id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.permission_id
        WHERE ur.user_id = $1;
    `;
    const result = await pool.query(query, [userId]);
    return result.rows.map(row => row.name); // Returns an array of permission names
};

    /**
     * Fetches all users with pagination.
     * @param {object} options - Pagination options.
     * @param {number} options.page - The current page number (1-indexed).
     * @param {number} options.limit - The number of users per page.
     * @returns {Promise<object>} An object containing users and pagination info.
     */
    const getAllUsers = async ({ page = 1, limit = 10 }) => {
    const offset = (page - 1) * limit;
    // Query to get paginated users
    const usersQuery = `
        SELECT u.user_id, u.username, u.email, u.created_at, u.updated_at, u.last_login, u.is_verified, u.is_active
        FROM users u
        ORDER BY u.created_at DESC
        LIMIT $1 OFFSET $2
    `;
    const usersResult = await pool.query(usersQuery, [limit, offset]);

    // For each user, fetch their roles
    const usersWithRoles = await Promise.all(usersResult.rows.map(async (user) => {
        const rolesQuery = pool.query(`
            SELECT r.name
            FROM roles r
            JOIN user_roles ur ON r.role_id = ur.role_id
            WHERE ur.user_id = $1
        `, [user.user_id]);
        const permissionsQuery = pool.query(`
            SELECT DISTINCT p.name
            FROM permissions p
            JOIN role_permissions rp ON p.permission_id = rp.permission_id
            JOIN user_roles ur ON rp.role_id = ur.role_id
            WHERE ur.user_id = $1
        `, [user.user_id]);
        const [rolesQueryResult, permissionsQueryResult] = await Promise.all([rolesQuery, permissionsQuery]);
        return {
            ...user,
            roles: rolesQueryResult.rows.map(r => r.name),
            permissions: permissionsQueryResult.rows.map(p => p.name)
        };
    }));

    // Query to get the total count of users for pagination
    const totalCountQuery = 'SELECT COUNT(*) FROM users';
    const totalCountResult = await pool.query(totalCountQuery);
    const totalUsers = parseInt(totalCountResult.rows[0].count, 10);

    return {
        users: usersWithRoles,
        totalUsers: totalUsers,
        currentPage: page,
        totalPages: Math.ceil(totalUsers / limit)
    };
};
module.exports = {
    findUserByIdentifier,
    findUserById,
    createUser,
    updateUser,
    updateUserLastLogin,
    findExistingUser,
    findUserByVerificationToken,
    verifyUserEmail,
    getUserRolesAndPermissions,
    getUserAuthData,
    generateNewVerificationToken,
    getAllUsers,
};