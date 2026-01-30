const jwt = require('jsonwebtoken');

const generateToken = (id, role) => {
    // Generates a token valid for 24 hours
    return jwt.sign({ id, role }, process.env.JWT_SECRET, {
        expiresIn: '1d',
    });
};

module.exports = generateToken;