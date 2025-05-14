// Dependencies
const { pool } = require('../config/database')


const isDatabaseConnected = async() => {
    try {
        const client = await pool.connect();
        client.release();
        return true;
    } catch (error) {
        return false;
    }
}

module.exports = {
    isDatabaseConnected
}