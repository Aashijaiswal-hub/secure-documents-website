const AuditLog = require('../models/AuditLog');

// @desc    Get Logs for Current User
// @route   GET /api/audit
exports.getMyLogs = async (req, res) => {
    try {
        const logs = await AuditLog.find({ actor: req.user.id })
            .sort({ timestamp: -1 })
            .limit(50);

        res.status(200).json(logs);
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
};