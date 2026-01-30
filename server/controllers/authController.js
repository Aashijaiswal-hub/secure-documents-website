const User = require('../models/User');
const Document = require('../models/Document');
const { verifyAadhaar } = require('../utils/mockAadhaar');
const generateToken = require('../utils/generateToken');
const { validationResult } = require('express-validator');
const logAudit = require('../utils/audit');
const sendEmail = require('../utils/sendEmail');
const crypto = require('crypto');
const mongoose = require('mongoose');
const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { fullName, email, password, aadhaarId } = req.body;

        if (!verifyAadhaar(aadhaarId)) {
            return res.status(400).json({ message: 'Invalid Aadhaar Number' });
        }

        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ message: 'User already exists' });

        user = new User({
            fullName,
            email,
            password,
            aadhaarId,
            isVerified: false
        });

        const verificationToken = crypto.randomBytes(20).toString('hex');
        user.verificationToken = crypto.createHash('sha256').update(verificationToken).digest('hex');
        user.verificationTokenExpire = Date.now() + 24 * 60 * 60 * 1000; // 24 Hours

        await user.save();

        const verifyUrl = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;

        const message = `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>Verify Identity</h2>
                <p>Hello ${fullName},</p>
                <p>You registered for a Secure Vault account. Please click below to verify your email:</p>
                <a href="${verifyUrl}" style="background-color: #0F172A; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
                <p style="margin-top: 20px; font-size: 12px; color: #666;">If you did not request this, please ignore this email.</p>
            </div>
        `;

        try {
            await sendEmail({
                email: user.email,
                subject: 'Action Required: Verify your Government ID',
                message
            });

            // Log Audit
            logAudit({
                action: 'REGISTER',
                actor: user._id,
                ip: req.ip,
                status: 'PENDING_VERIFICATION',
                details: 'User registered, verification email sent'
            });

            res.status(200).json({
                success: true,
                message: `Verification email sent to ${user.email}`
            });

        } catch (emailError) {
            await user.deleteOne(); // Rollback user creation
            console.error("Email sending failed:", emailError);
            return res.status(500).json({ message: 'Email service failed. Please try again.' });
        }

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Verify User Email
// @route   PUT /api/auth/verifyemail/:token
// @access  Public
exports.verifyEmail = async (req, res) => {
    try {
        const token = crypto
            .createHash('sha256')
            .update(req.params.token)
            .digest('hex');

        const user = await User.findOne({
            verificationToken: token,
            verificationTokenExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or Expired Token' });
        }

        // Verify User
        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpire = undefined;

        await user.save();

        // Log Audit
        logAudit({
            action: 'VERIFY_EMAIL',
            actor: user._id,
            ip: req.ip,
            status: 'SUCCESS',
            details: 'Email verification successful'
        });

        const jwtToken = generateToken(user._id, user.role);
        sendTokenResponse(user, jwtToken, res, 200);

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email }).select('+password'); // Ensure password is selected if it's hidden by default

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const isMatch = await user.matchPassword(password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (!user.isVerified) {
            return res.status(401).json({
                message: 'Email not verified. Please check your inbox.'
            });
        }
        const token = generateToken(user._id, user.role);

        // Log Audit
        logAudit({
            action: 'LOGIN',
            actor: user._id,
            ip: req.ip,
            status: 'SUCCESS',
            details: 'User logged in via Password'
        });

        sendTokenResponse(user, token, res, 200);

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Logout user
// @route   POST /api/auth/logout
exports.logout = (req, res) => {
    res.cookie('token', 'none', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true,
    });
    res.status(200).json({ message: 'User logged out' });
};

const sendTokenResponse = (user, token, res, statusCode) => {
    const options = {
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        secure: process.env.NODE_ENV === 'production' ? true : false
    };

    res.status(statusCode)
        .cookie('token', token, options)
        .json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.fullName,
                email: user.email,
                role: user.role
            }
        });
};

exports.resendVerification = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        if (user.isVerified) {
            return res.status(400).json({ message: 'This account is already verified' });
        }
        const verificationToken = crypto.randomBytes(20).toString('hex');
        user.verificationToken = crypto.createHash('sha256').update(verificationToken).digest('hex');
        user.verificationTokenExpire = Date.now() + 24 * 60 * 60 * 1000; // 24 Hours

        await user.save();

        const verifyUrl = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;
        const message = `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>Verify Identity (Resent)</h2>
                <p>Hello ${user.fullName},</p>
                <p>You requested a new verification link. Click below to activate your account:</p>
                <a href="${verifyUrl}" style="background-color: #0F172A; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
                <p style="margin-top: 20px; font-size: 12px; color: #666;">This link expires in 24 hours.</p>
            </div>
        `;

        try {
            await sendEmail({
                email: user.email,
                subject: 'New Verification Link - Secure Vault',
                message
            });
            res.status(200).json({ message: 'Verification link sent to your email.' });
        } catch (err) {
            return res.status(500).json({ message: 'Email could not be sent' });
        }

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Get User Profile & Stats
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        const docs = await Document.find({ owner: req.user.id });
        const totalFiles = docs.length;
        const totalSize = docs.reduce((acc, doc) => acc + doc.size, 0); // Sum of size in bytes

        res.status(200).json({
            user,
            stats: {
                totalFiles,
                usedStorage: totalSize,
                totalStorage: 100 * 1024 * 1024 // Hard limit: 100MB for MVP
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Forgot Password (Send Email)
// @route   POST /api/auth/forgotpassword
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const resetToken = crypto.randomBytes(20).toString('hex');

        user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 Minutes
        await user.save({ validateBeforeSave: false });

        const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

        const message = `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>Password Reset Request</h2>
                <p>You requested a password reset. Click the button below to set a new password:</p>
                <a href="${resetUrl}" style="background-color: #DC2626; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
                <p style="margin-top: 20px; font-size: 12px; color: #666;">This link expires in 10 minutes.</p>
            </div>
        `;

        try {
            await sendEmail({
                email: user.email,
                subject: 'Password Reset - Secure Vault',
                message
            });

            res.status(200).json({ success: true, message: 'Email sent' });
        } catch (err) {
            user.resetPasswordToken = undefined;
            user.resetPasswordExpire = undefined;
            await user.save({ validateBeforeSave: false });
            return res.status(500).json({ message: 'Email could not be sent' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Reset Password
// @route   PUT /api/auth/resetpassword/:token
exports.resetPassword = async (req, res) => {
    try {
        const resetPasswordToken = crypto
            .createHash('sha256')
            .update(req.params.token)
            .digest('hex');

        const user = await User.findOne({
            resetPasswordToken,
            resetPasswordExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        await user.save();

        logAudit({
            action: 'PASSWORD_RESET',
            actor: user._id,
            ip: req.ip,
            status: 'SUCCESS',
            details: 'Password changed successfully'
        });

        res.status(200).json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Google Login / Signup
// @route   POST /api/auth/google
exports.googleLogin = async (req, res) => {
    const { token } = req.body;

    try {
        console.log("1. Received Google Token");
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        console.log("2. Token Verified. Payload:", ticket.getPayload());
        const { name, email, sub, picture } = ticket.getPayload();
        let user = await User.findOne({ email });

        if (user) {
            if (!user.isVerified) {
                return res.status(401).json({
                    message: 'Email not verified. Please check your inbox.'
                });
            }

            if (!user.googleId) {
                user.googleId = sub;
                user.authProvider = 'google';
                if (!user.avatar) user.avatar = picture;
                await user.save({ validateBeforeSave: false });
            }

            logAudit({
                action: 'LOGIN_GOOGLE',
                actor: user._id,
                ip: req.ip,
                status: 'SUCCESS',
                details: 'User logged in via Google OAuth'
            });

            const jwtToken = generateToken(user._id, user.role);
            sendTokenResponse(user, jwtToken, res, 200);
        }

        user = new User({
            fullName: name,
            email: email,
            googleId: sub,
            avatar: picture,
            authProvider: 'google',
            isVerified: false,
            password: null
        });
        const verificationToken = crypto.randomBytes(20).toString('hex');
        user.verificationToken = crypto.createHash('sha256').update(verificationToken).digest('hex');
        user.verificationTokenExpire = Date.now() + 24 * 60 * 60 * 1000; // 24 Hours

        await user.save();

        const verifyUrl = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;
        const message = `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>Verify Identity (Google Sign-up)</h2>
                <p>Hello ${name},</p>
                <p>You registered using Google. Please click below to complete your account setup:</p>
                <a href="${verifyUrl}" style="background-color: #0F172A; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
                <p style="margin-top: 20px; font-size: 12px; color: #666;">This link expires in 24 hours.</p>
            </div>
        `;

        try {
            await sendEmail({
                email: user.email,
                subject: 'Action Required: Verify your Government ID',
                message
            });

            logAudit({
                action: 'REGISTER_GOOGLE',
                actor: user._id,
                ip: req.ip,
                status: 'PENDING_VERIFICATION',
                details: 'New Google user registered, verification email sent'
            });
            res.status(200).json({
                success: true,
                message: `Registration successful! Verification email sent to ${email}.`
            });

        } catch (emailError) {
            await user.deleteOne(); // Rollback
            console.error("Email sending failed:", emailError);
            return res.status(500).json({ message: 'Email service failed. Please try again.' });
        }
    } catch (error) {
        console.error("GOOGLE AUTH ERROR:", error);
        console.error("Backend Expected ID:", process.env.GOOGLE_CLIENT_ID);
        res.status(401).json({ message: 'Google Authentication Failed' });
    }
};

// @desc    Delete User Account & All Data
// @route   DELETE /api/auth/me
// @access  Private
exports.deleteAccount = async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const docs = await Document.find({ owner: userId });

        const conn = mongoose.connection;
        let gridfsBucket = new mongoose.mongo.GridFSBucket(conn.db, {
            bucketName: 'uploads'
        });

        for (const doc of docs) {
            if (doc.gridFsId) {
                try {
                    await gridfsBucket.delete(new mongoose.Types.ObjectId(doc.gridFsId));
                } catch (err) {
                    console.warn(`Failed to delete GridFS file ${doc.gridFsId}:`, err.message);
                }
            }
        }
        await Document.deleteMany({ owner: userId });
        await require('../models/Folder').deleteMany({ owner: userId });
        await require('../models/AuditLog').deleteMany({ actor: userId });
        await User.findByIdAndDelete(userId);

        res.status(200).json({ message: 'Account and all data permanently deleted' });

    } catch (error) {
        console.error("Delete Account Error:", error);
        res.status(500).json({ message: 'Server Error during deletion' });
    }
};