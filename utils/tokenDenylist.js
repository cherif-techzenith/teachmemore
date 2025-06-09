// In-memory store for revoked tokens.
// For production, we will use a persistent store like Redis or a database.
const revokedTokens = new Set();

/**
 * Adds a token to the denylist.
 * @param {string} token - The JWT to revoke.
 */
const add = (token) => {
    revokedTokens.add(token);
    // we should add an expiry mechanism to tokens in the denylist
};

// Checks if a token is in the denylist.
const has = (token) => {
    return revokedTokens.has(token);
};

module.exports = { add, has };