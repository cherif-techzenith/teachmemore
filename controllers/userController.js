// Dependencies
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { validationResult } = require('express-validator');
const { pool } = require('../config/database');
const jwt = require('jsonwebtoken')

// User registration
const registerUser = async(req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array()
        });
    }

    const { username, email, password } = req.body;

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
const loginUser = async(req, res) => {
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
            user: {
                username: user.username,
                email: user.email,
            }
        })

    } catch (error) {
        console.error('Error during login: ', error);
        res.status(500).json({
            error: 'Internal server error.'
        })
    }
}

// Get user by ID
const getUserById = async(req, res) => {
    const { userId } = req.params;
    
    try {
    
        const userQuery = 'SELECT user_id, username, email, created_at, FROM users WHERE user_id = $1';
        const userResult = await pool.query(userQuery, [userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        const user = userResult.rows[0]
        res.status(200).json(user);
        
    } catch (error) {
        console.error('Error fetching user: ', error);
        res.status(500).json({
            error: 'Internal server error.'
        });
    }
}

// Update user by ID
const updateUser = async(req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array()
        })
    }

    const { userId } = req.params;
    const { username, email } = req.body;

    try {
        const checkUserQuery = 'SELECT user_id FROM users WHERE user_id = $1';
        const userResult = await pool.query(checkUserQuery, [userId]);
        if(userResult.rows.length === 0){
            return res.status(404).json({
                error: 'User not found',
            });
        }

        let updateQuery = 'UPDATE users SET';
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

        updateQuery = updateQuery.slice(0, -2);
        updateQuery += ` WHERE user_id = $${valueIndex}`;
        values.push(userId);

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

// Delete user by ID
const deleteUser = async(req, res) => {
    const { userId } = req.params
    
    try {
        const checkUserQuery = 'SELECT user_id FROM users WHERE user_id = $1';
        const userResult = await pool.query(checkUserQuery, [userId]);
        if(userResult.rows.length === 0){
            return res.status(404).json({
                error: 'User not found.'
            })
        }

        const deleteUserQuery = 'DELETE FROM users WHERE user_id = $1';
        await pool.query(deleteUserQuery, [userId]);

        res.status(200).json({
            message: 'User deleted successfully'
        })
        
    } catch (error) {
        console.error('Error deleting user: ', error);
        res.status(500).json({
            error: 'Internal server error.'
        });
    }
}

module.exports = {
    registerUser,
    loginUser,
    getUserById,
    updateUser,
    deleteUser
}