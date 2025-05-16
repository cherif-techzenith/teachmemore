// Dependencies
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { validationResult } = require('express-validator');
const { pool } = require('../config/database');
const jwt = require('jsonwebtoken')

// Create user
const createUser = async(req, res) => {
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

// Get users
const getUsers = async(req, res) => {
    try {
        const usersQuery = 'SELECT user_id, username, email, created_at, updated_at, last_login FROM users';
        const usersResult = await pool.query(usersQuery);

        res.status(200).json({
            users: usersResult.rows
        })
        
    } catch (error) {
        console.error('Error fetching users: ', error);
        res.status(500).json('Internal server error.')
    }
}

// Get user by username
const getUser = async(req, res) => {
    const { user } = req.params;
    
    try {
    
        const userQuery = 'SELECT user_id, username, email, created_at, updated_at, last_login FROM users WHERE username = $1';
        const userResult = await pool.query(userQuery, [user]);

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

// Update user by ID
const updateUser = async(req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array()
        })
    }

    const { user } = req.params;
    const { username, email } = req.body;

    try {
        const checkUserQuery = 'SELECT user_id FROM users WHERE username = $1';
        const userResult = await pool.query(checkUserQuery, [user]);
        if(userResult.rows.length === 0){
            return res.status(404).json({
                error: 'User not found',
            });
        }

        const existingUserQuery = 'SELECT user_id, username FROM users WHERE username = $1 OR email = $2';
        const existingUserResult = await pool.query(existingUserQuery, [username, email]);
        const existingUser = existingUserResult.rows[0];

        if (existingUserResult.rows.length > 0 && existingUser.username !== user) {
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
        updateQuery += ` WHERE username = $${valueIndex}`;
        values.push(user);

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
    const { user } = req.params
    
    try {
        const checkUserQuery = 'SELECT user_id FROM users WHERE username = $1';
        const userResult = await pool.query(checkUserQuery, [user]);
        if(userResult.rows.length === 0){
            return res.status(404).json({
                error: 'User not found.'
            })
        }

        const deleteUserQuery = 'DELETE FROM users WHERE username = $1';
        await pool.query(deleteUserQuery, [user]);

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
    createUser, updateUser,
    getUser, getUsers,
    deleteUser
}