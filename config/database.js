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

// Test database connection on startup
pool.connect()
    .then(() => console.log('Connected to users database'))
    .catch(err => {
        console.error('Error connecting to users database');
        process.exit(1);
    })

module.exports = { pool }
