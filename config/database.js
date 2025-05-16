// Dependencies
require('dotenv').config()

const { Pool } = require('pg')

// Database connection configuration
const connectionConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'usersdb',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'password',
    max: 20,
    idleTimeoutMillis: process.env.DB_IDLE_TIMEOUT_MILLIS,
    connectionTimeoutMillis: process.env.DB_CONNECTION_TIMEOUT_MILLIS
}
const pool = new Pool(connectionConfig)

// Check database connection and create tables if they don't exist
async function initializeDatabase() {
    let client;
    try {
        client = await pool.connect();

        // Enable the uuid-ossp extension if it's not already enabled.
        await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

        // Check if the users table exists
        const userTableExistsResult = await client.query(
            "SELECT to_regclass('users') as table_exists"
        );
        const userTableExists = userTableExistsResult.rows[0].table_exists;

        if (!userTableExists) {
            // Create the users table with the user_id as a UUID and set the default value.
            await client.query(`
                CREATE TABLE users (
                    user_id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    updated_at TIMESTAMP WITH TIME ZONE,
                    last_login TIMESTAMP WITH TIME ZONE
                );
            `);
            console.log('Users table created');
        } else {
            console.log('Users table already exists');
        }

        // Check if roles table exists
        const rolesTableExistsResult = await client.query(
            "SELECT to_regclass('roles') as table_exists"
        );
        const rolesTableExists = rolesTableExistsResult.rows[0].table_exists;

        if (!rolesTableExists) {
          // Create the roles table
            await client.query(`
                CREATE TABLE roles (
                    role_id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL UNIQUE
                );
            `);
            console.log('Roles table created');

             // Insert some default roles
            await client.query("INSERT INTO roles (name) VALUES ('admin'), ('user')");
            console.log('Roles inserted');
        } else {
            console.log('Roles table already exists');
        }

        // Check if the user_roles table exists
        const userRolesTableExistsResult = await client.query(
            "SELECT to_regclass('user_roles') as table_exists"
        );
        const userRolesTableExists = userRolesTableExistsResult.rows[0].table_exists;

        if (!userRolesTableExists) {
            // Create the user_roles table
            await client.query(`
                CREATE TABLE user_roles (
                    user_id uuid REFERENCES users(user_id) ON DELETE CASCADE,
                    role_id INT REFERENCES roles(role_id) ON DELETE CASCADE,
                    PRIMARY KEY (user_id, role_id)
                );
            `);
            console.log('User_roles table created');
        } else {
            console.log('User_roles table already exists');
        }

        // Check if the password_reset_tokens table exists.
        const passwordResetTokenTableExistsResult = await client.query(
            "SELECT to_regclass('password_reset_tokens') as table_exists"
        );
        const passwordResetTokenTableExists = passwordResetTokenTableExistsResult.rows[0].table_exists;

        if (!passwordResetTokenTableExists) {
            // Create the password_reset_tokens table.
            await client.query(`
                CREATE TABLE password_reset_tokens (
                    token_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    token VARCHAR(255) NOT NULL,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL
                );
            `);
            console.log('password_reset_tokens table created');
        } else {
            console.log('password_reset_tokens table already exists');
        }

        console.log('Database initialization complete');
    } catch (error) {
        console.error('Error initializing database:', error);
        process.exit(1);
    } finally {
        if (client) {
            client.release();
        }
    }
}

module.exports = { pool, initializeDatabase }
