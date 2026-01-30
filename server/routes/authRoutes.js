const express = require('express');
const { check } = require('express-validator');
const { register, login, logout, verifyEmail, resendVerification, getMe, forgotPassword, resetPassword, googleLogin, deleteAccount } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');
const router = express.Router();

const registerValidation = [
    check('fullName', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password must be 6+ chars').isLength({ min: 6 }),
    check('aadhaarId', 'Aadhaar must be 12 digits').matches(/^\d{12}$/)
];

const loginValidation = [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
];

router.post('/register', registerValidation, register);
router.post('/login', loginValidation, login);
router.post('/logout', logout);
router.put('/verifyemail/:token', verifyEmail);
router.post('/resend-verification', resendVerification);
router.get('/me', protect, getMe);
router.post('/forgotpassword', forgotPassword);
router.put('/resetpassword/:token', resetPassword);
router.delete('/me', protect, deleteAccount);
router.post('/google', googleLogin);

module.exports = router;