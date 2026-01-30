const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.protect = async (req, res, next) => {
    let token;

    // --- DEBUG LOGGING ---
    console.log("--- Auth Debug ---");
    console.log("1. Cookies Received:", req.cookies); 
    // ---------------------

    if (req.cookies && req.cookies.token) {
        token = req.cookies.token;
    }

    // FALLBACK: Check Authorization Header (Bearer Token)
    // This allows you to manually paste the token in Postman if cookies fail
    if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
        console.log("2. Found token in Header");
    }

    if (!token) {
        console.log("3. No token found in Cookie or Header");
        return res.status(401).json({ message: 'Not authorized, no token' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id).select('-password');
        next();
    } catch (error) {
        console.error("Token Verification Failed:", error.message);
        res.status(401).json({ message: 'Not authorized, token failed' });
    }
};