// Dependencies
const { validationResult } = require('express-validator')
const { pool } = require('../config/database')

// Create role
const createRole = async(req, res) => {
    try {
        const errors = validationResult(req);
        if(!errors.isEmpty()){
            return res.status(400).json({
                errors: errors.array()
            });
        }

        const { name } = req.body;

        const existingRoleQuery = 'SELECT role_id FROM roles WHERE name = $1';
        const existingRoleResult = await pool.query(existingRoleQuery, [name]);

        if(existingRoleResult.rows.length > 0){
            return res.status(409).json({
                error: 'Role already exists'
            });
        }

        const insertRoleQuery = 'INSERT INTO roles (name) VALUES ($1)';
        await pool.query(insertRoleQuery, [name]);

        res.status(201).json({
            message: 'Role added successfully.'
        });

    } catch (error) {
        console.error('Error creating a role: ', error);
        res.status(500).json('Internal server error.');
    }
}

// Get roles
const getRoles = async(req, res) => {
    try {
        const rolesQuery = 'SELECT name FROM roles';
        const rolesResult = await pool.query(rolesQuery);

        res.status(200).json({
            roles: rolesResult.rows
        });
    } catch (error) {
        console.error('Error fetching roles: ', error);
        res.json(500).json('Internal server error.');
    }
}

// Get role by ID
const getRoleById = async(req, res) => {
    const { roleId } = req.params

    try {
        const roleQuery = 'SELECT role_id, name FROM roles WHERE role_id = $1';
        const roleResult = await pool.query(roleQuery, [roleId]);

        if(roleResult.rows.length === 0){
            return res.status(404).json({
                error: 'Role not found.'
            });
        }

        const role = roleResult.rows[0];

        res.status(200).json(role);
    } catch (error) {
        console.error('Error fetching role: ', error);
        res.status(500).json('Internal server error.');
    }
}

// Update role
const updateRole = async(req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array()
        });
    }

    const { roleId } = req.params;
    const { name } = req.body;

    try {
        const checkRole = 'SELECT role_id FROM roles WHERE role_id = $1';
        const roleResult = await pool.query(checkRole, [roleId]);
        if(roleResult.rows.length === 0){
            return res.status(404).json({
                error: 'Role not found.'
            });
        }

        let updateQuery = 'UPDATE roles SET ';
        const values = [];
        let valueIndex = 1;

        if(name){
            updateQuery += ` name = $${valueIndex} `
            values.push(name);
            valueIndex++
        }

        updateQuery = updateQuery.slice(0, -2);
        updateQuery += ` WHERE role_id = $1`;
        values.push(roleId);

        const result = await pool.query(updateQuery, values);

        if(result.rowCount === 0){
            return res.status(404).json({
                error: 'Failed to update role. No changes were made.'
            });
        }

        res.status(200).json({
            message: 'Role updated successfully.'
        });
    } catch (error) {
        console.error('Error updating role: ', error);
        res.status(500).json('Internal server error.');
    }
}

const deleteRole = async(req, res) => {
    const { roleId } = req.params

    try {
        const checkRoleQuery = 'SELECT role_id FROM roles WHERE role_id = $1';
        const roleResult = await pool.query(checkRoleQuery, [roleId]);

        if(roleResult.rows.length === 0){
            return res.status(404).json({
                error: 'Role not found.'
            })
        }

        const deleteRoleQuery = 'DELETE FROM roles WHERE role_id = $1';
        await pool.query(deleteRoleQuery, [roleId]);

        res.status(200).json({
            message: 'Role deleted successfully.'
        })

    } catch (error) {
        console.error('Error deleting role: ', error);
        res.status(500).json('Internal server error');
    }
}

module.exports = {
    createRole,
    getRoles,
    getRoleById,
    updateRole,
    deleteRole
}