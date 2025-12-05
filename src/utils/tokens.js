const crypto = require('crypto');

function generateRandomToken(size = 32) {
    return crypto.randomBytes(size).toString('hex');
}

module.exports = { generateRandomToken };
