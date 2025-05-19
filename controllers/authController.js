// Dependencies
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { validationResult } = require('express-validator');
const { pool } = require('../config/database');
const jwt = require('jsonwebtoken')

// User registration
const register = async(req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array()
        });
    }

    const { username, email, password, password_confirmation } = req.body;

    try {
        const existingUserQuery = 'SELECT user_id FROM users WHERE username = $1 OR email = $2';
        const existingUserResult = await pool.query(existingUserQuery, [username, email]);

        if (existingUserResult.rows.length > 0) {
            const existingUser = existingUserResult.rows[0];
            if(existingUser.username === username){
                return res.status(409).json({
                    error: 'Username already exists.'
                });
            }else{
                return res.status(409).json({
                    error: 'Email already exists.'
                });
            }
        }
        
        if(password !== password_confirmation){
            return res.status(409).json({
                error: 'Password confirmation does not match.'
            })
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuidv4();
        const insertUserQuery = `
            INSERT INTO users (user_id, username, email, password, created_at)
            VALUES($1, $2, $3, $4, NOW())
        `;
        await pool.query(insertUserQuery, [userId, username, email, hashedPassword])
        
        res.status(201).json({
            message: 'User registered successfully'
        });

    } catch (error) {
        console.error('Error during registration: ', error);
        res.status(500).json({
            error: 'Internal server error.'
        });
    }
}

// User login
const login = async(req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array()
        });
    }

    const { identifier, password } = req.body;

    try {
        const userQuery = 'SELECT user_id, username, email, password FROM users WHERE username = $1 OR email = $1';
        const userResult = await pool.query(userQuery, [identifier]);

        if(userResult.rows.length === 0){
            return res.status(401).json({
                error: 'Invalid credentials.',
            })
        }

        const user = userResult.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        if(!passwordMatch){
            return res.status(401).json({
                error: 'Incorrect password.'
            });
        }

        const updateLastLoginQuery = "UPDATE users SET last_login = NOW() WHERE username = $1";
        await pool.query(updateLastLoginQuery, [user.username])

        const payload = {
            userId: user.user_id,
            username: user.username,
            email: user.email
        }

        const jwt_secret = process.env.JWT_SECRET
        const token = jwt.sign(payload, jwt_secret, {
            expiresIn: '1h'
        })

        res.status(200).json({
            message: 'Login successful.',
            token: token,
        })

    } catch (error) {
        console.error('Error during login: ', error);
        res.status(500).json({
            error: 'Internal server error.'
        })
    }
}

// Get account details
const me = async(req, res) => {
    const { user } = req;
    
    try {
        const userQuery = 'SELECT user_id, username, email, created_at, updated_at, last_login FROM users WHERE user_id = $1';
        const userResult = await pool.query(userQuery, [user.userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        res.status(200).json(userResult.rows[0]);
    } catch (error) {
        console.error('Error fetching user: ', error);
        res.status(500).json({
            error: 'Internal server error.'
        });
    }
}

// Update account details
const update = async(req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array()
        })
    }

    const { user } = req;
    const { username, email } = req.body;

    try {
        const checkUserQuery = 'SELECT user_id FROM users WHERE user_id = $1';
        const userResult = await pool.query(checkUserQuery, [user.userId]);
        if(userResult.rows.length === 0){
            return res.status(404).json({
                error: 'User not found',
            });
        }

        const existingUserQuery = 'SELECT user_id, username FROM users WHERE username = $1 OR email = $2';
        const existingUserResult = await pool.query(existingUserQuery, [username, email]);
        const existingUser = existingUserResult.rows[0];

        if (existingUser && existingUser.user_id !== user.userId) {
            if(existingUser.username === username){
                return res.status(409).json({
                    error: 'Username already exists.'
                });
            }else{
                return res.status(409).json({
                    error: 'Email already exists.'
                });
            }
        }

        let updateQuery = 'UPDATE users SET updated_at = NOW(),';
        const values = [];
        let valueIndex = 1;

        if(username){
            updateQuery += ` username = $${valueIndex},`;
            values.push(username);
            valueIndex++;
        }

        if(email){
            updateQuery += ` email = $${valueIndex},`;
            values.push(email);
            valueIndex++;
        }

        updateQuery = updateQuery.slice(0, -1);
        updateQuery += ` WHERE user_id = $${valueIndex}`;
        values.push(user.userId);

        const result = await pool.query(updateQuery, values);

        if(result.rowCount === 0){
            return res.status(400).json({
                error: 'Failed to update user. No changes were made.'
            })
        }

        res.status(200).json({
            message: 'User updated suffessfully.'
        })
        
    } catch (error) {
        console.error('Error updating user: ', error);
        res.status(500).json({
            error: 'Internal server error.'
        });
    }
}

// Refresh token
const refreshToken = (req, res) => {
    const { refreshToken } = req.body;

    if(!refreshToken){
        return res.status(401).json({
            error: 'Refresh token is required.'
        });
    }

    jwt.verify(refreshToken, process.env.JWT_SECRET, (err, decoded) => {
        if(err){
            return res.status(403).json({
                error: 'Invalid refresh token.'
            });
        }

        const payload = {
            userId: decoded.userId,
            username: decoded.username,
            email: decoded.email
        }

        const newToken = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });

        res.status(200).json({
            message: 'Token refreshed successfully.',
            token: newToken
        });
    });
}

// Revoke token
const revokeToken = (req, res) => {

}

// Forgot password
const forgotPassword = (req, res) => {
    const { email } = req.body;

    if(!email){
        return res.status(400).json({
            error: 'Email is required.'
        });
    }

    // Check if user exists
    const userQuery = 'SELECT user_id FROM users WHERE email = $1';
    pool.query(userQuery, [email], (err, result) => {
        if(err){
            console.error('Error checking user: ', err);
            return res.status(500).json({
                error: 'Internal server error.'
            });
        }

        if(result.rows.length === 0){
            return res.status(404).json({
                error: 'User not found.'
            });
        }

        // Generate reset token and send email (not implemented)
        res.status(200).json({
            message: 'Password reset link sent to your email.'
        });
    });
}

// Reset password
const resetPassword = (req, res) => {

}

// Logout
const logout = (req, res) => {

}

module.exports = {
    register, login, logout,
    me, update,
    refreshToken, revokeToken,
    forgotPassword, resetPassword,
}