// Dependencies
require('dotenv').config()
const bcrypt = require('bcryptjs'); // Added for hashing superadmin password

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

const initialPermissions = [
    // User Management
    { name: 'user:create', description: 'Allow creating users' },
    { name: 'user:read_all', description: 'Allow reading all users' },
    { name: 'user:read_one', description: 'Allow reading a single user' },
    { name: 'user:update_any', description: 'Allow updating any user\'s profile' }, // For admins
    { name: 'user:update_own', description: 'Allow updating own profile' }, // For regular users
    { name: 'user:delete', description: 'Allow deleting users' },
    { name: 'user:assign_role', description: 'Allow assigning roles to users' },
    { name: 'user:remove_role', description: 'Allow removing roles from users' },

    // Role Management
    { name: 'role:create', description: 'Allow creating roles' },
    { name: 'role:read_all', description: 'Allow reading all roles' },
    { name: 'role:read_one', description: 'Allow reading a single role' },
    { name: 'role:update', description: 'Allow updating roles' },
    { name: 'role:delete', description: 'Allow deleting roles' },
    { name: 'role:manage_permissions', description: 'Allow assigning/removing permissions to/from roles' },

    // Permission Management
    { name: 'permission:read_all', description: 'Allow reading all available permissions' },
];

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
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    is_verified BOOLEAN NOT NULL DEFAULT false,
                    last_login TIMESTAMP WITH TIME ZONE
                );
            `);
            console.log('Table des utilisateurs créée');
        } else {
            console.log('La table des utilisateurs existe déjà');
            // Ensure is_verified defaults to false if table exists from previous state
            await client.query(`
                ALTER TABLE users ALTER COLUMN is_verified SET DEFAULT false;
            `);
            // Remove old email verification columns if they exist
            const oldTokenColExists = await client.query("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='email_verification_token'");
            if (oldTokenColExists.rows.length > 0) {
                await client.query('ALTER TABLE users DROP COLUMN IF EXISTS email_verification_token, DROP COLUMN IF EXISTS email_verification_expires;');
                console.log('Anciennes colonnes de vérification d\'e-mail supprimées de la table des utilisateurs.');
            }
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
            console.log('Table des rôles créée');

            // Insert some default roles
            await client.query("INSERT INTO roles (name) VALUES ('admin'), ('user')");
            console.log('Rôles insérés');
        } else {
            console.log('La table des rôles existe déjà');
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
            console.log('Table des user_roles créée');
        } else {
            console.log('La table des user_roles existe déjà');
        }

        // Ensure 'superadmin' role exists
        const superadminRoleName = process.env.SUPERADMIN_ROLE_NAME || 'superadmin';
        let superadminRoleResult = await client.query("SELECT role_id FROM roles WHERE name = $1", [superadminRoleName]);
        let superadminRoleId;

        if (superadminRoleResult.rows.length === 0) {
            const insertSuperadminRoleResult = await client.query("INSERT INTO roles (name) VALUES ($1) RETURNING role_id", [superadminRoleName]);
            superadminRoleId = insertSuperadminRoleResult.rows[0].role_id;
            console.log(`Rôle '${superadminRoleName}' créé avec ID: ${superadminRoleId}`);
        } else {
            superadminRoleId = superadminRoleResult.rows[0].role_id;
            console.log(`Le rôle '${superadminRoleName}' existe déjà avec ID: ${superadminRoleId}`);
        }

        // Create superadmin user if it doesn't exist
        const superadminUsername = process.env.SUPERADMIN_USERNAME;
        const superadminEmail = process.env.SUPERADMIN_EMAIL;
        const superadminPassword = process.env.SUPERADMIN_PASSWORD;

        if (superadminUsername && superadminEmail && superadminPassword) {
            let superadminUserResult = await client.query("SELECT user_id FROM users WHERE username = $1 OR email = $2", [superadminUsername, superadminEmail]);
            let superadminUserId;

            if (superadminUserResult.rows.length === 0) {
                const hashedSuperadminPassword = await bcrypt.hash(superadminPassword, 10);
                const insertSuperadminUserResult = await client.query(
                    `INSERT INTO users (username, email, password, created_at, updated_at, is_verified, is_active)
                     VALUES ($1, $2, $3, NOW(), NOW(), true, true)
                     RETURNING user_id`,
                    [superadminUsername, superadminEmail, hashedSuperadminPassword]
                );
                superadminUserId = insertSuperadminUserResult.rows[0].user_id;
                console.log(`Utilisateur superadministrateur '${superadminUsername}' créé avec ID: ${superadminUserId}. Il est conseillé de changer le mot de passe par défaut.`);

                // Assign superadmin role to the superadmin user
                await client.query(
                    "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING",
                    [superadminUserId, superadminRoleId]
                );
                console.log(`Rôle '${superadminRoleName}' assigné à l'utilisateur superadministrateur '${superadminUsername}'.`);
            } else {
                superadminUserId = superadminUserResult.rows[0].user_id;
                console.log(`L'utilisateur superadministrateur '${superadminUsername}' ou l'e-mail '${superadminEmail}' existe déjà avec ID: ${superadminUserId}. Vérification de l'assignation du rôle.`);
                // Ensure the existing superadmin has the superadmin role
                await client.query(
                    "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING",
                    [superadminUserId, superadminRoleId]
                );
            }
        } else {
            console.warn("Les variables d'environnement SUPERADMIN_USERNAME, SUPERADMIN_EMAIL, et SUPERADMIN_PASSWORD ne sont pas toutes définies. Le compte superadministrateur ne sera pas créé automatiquement.");
        }

        // Check if the email_verification_tokens table exists
        const emailVerificationTableExistsResult = await client.query(
            "SELECT to_regclass('email_verification_tokens') as table_exists"
        );
        const emailVerificationTableExists = emailVerificationTableExistsResult.rows[0].table_exists;

        if (!emailVerificationTableExists) {
            await client.query(`
                CREATE TABLE email_verification_tokens (
                    token_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    token TEXT NOT NULL UNIQUE,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                );
            `);
            console.log('Table email_verification_tokens créée');
        } else {
            console.log('La table email_verification_tokens existe déjà');
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
            console.log('Table password_reset_tokens créée');
        } else {
            console.log('La table password_reset_tokens existe déjà');
        }

        // Check if the permissions table exists
        const permissionsTableExistsResult = await client.query(
            "SELECT to_regclass('permissions') as table_exists"
        );
        const permissionsTableExists = permissionsTableExistsResult.rows[0].table_exists;

        if (!permissionsTableExists) {
            await client.query(`
                CREATE TABLE permissions (
                    permission_id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL UNIQUE,
                    description TEXT
                );
            `);
            console.log('Table des permissions créée');

            // Seed initial permissions
            for (const perm of initialPermissions) {
                await client.query(
                    "INSERT INTO permissions (name, description) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING",
                    [perm.name, perm.description]
                );
            }
            console.log('Permissions initiales insérées/vérifiées.');
        } else {
            console.log('La table des permissions existe déjà');
        }

        // Check if the role_permissions table exists
        const rolePermissionsTableExistsResult = await client.query(
            "SELECT to_regclass('role_permissions') as table_exists"
        );
        const rolePermissionsTableExists = rolePermissionsTableExistsResult.rows[0].table_exists;

        if (!rolePermissionsTableExists) {
            await client.query(`
                CREATE TABLE role_permissions (
                    role_id INT REFERENCES roles(role_id) ON DELETE CASCADE,
                    permission_id INT REFERENCES permissions(permission_id) ON DELETE CASCADE,
                    PRIMARY KEY (role_id, permission_id)
                );
            `);
            console.log('Table des role_permissions créée');
        } else {
            console.log('La table des role_permissions existe déjà');
        }

        // Assign all defined permissions to the superadmin role
        const superadminRoleNameForPerms = process.env.SUPERADMIN_ROLE_NAME || 'superadmin';
        const superadminRoleForPermsResult = await client.query("SELECT role_id FROM roles WHERE name = $1", [superadminRoleNameForPerms]);
        if (superadminRoleForPermsResult.rows.length > 0) {
            const superadminRoleIdForPerms = superadminRoleForPermsResult.rows[0].role_id;
            const allPermissionsResult = await client.query("SELECT permission_id FROM permissions");
            for (const perm of allPermissionsResult.rows) {
                await client.query(
                    "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT (role_id, permission_id) DO NOTHING",
                    [superadminRoleIdForPerms, perm.permission_id]
                );
            }
            console.log(`Toutes les permissions définies ont été assignées/vérifiées pour le rôle '${superadminRoleNameForPerms}'.`);
        }

        console.log('Initialisation de la base de données terminée');
    } catch (error) {
        console.error('Erreur lors de l\'initialisation de la base de données :', error);
        process.exit(1);
    } finally {
        if (client) {
            client.release();
        }
    }
}

module.exports = { pool, initializeDatabase }
