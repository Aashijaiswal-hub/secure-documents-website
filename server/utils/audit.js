const AuditLog = require('../models/AuditLog');

const logAudit = async (data) => {
    try {
        await AuditLog.create({
            action: data.action,
            actor: data.actor,
            resource: data.resource || 'N/A',
            ipAddress: data.ip || 'Unknown',
            status: data.status || 'SUCCESS',
            details: data.details || ''
        });
    } catch (error) {
        console.error("Audit Log Failed:", error.message);
    }
};

module.exports = logAudit;