const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
    action: { 
        type: String, 
        required: true,
        enum: ['LOGIN', 'REGISTER', 'UPLOAD', 'VIEW', 'SHARE', 'LOGOUT'] 
    },
    actor: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    resource: { 
        type: String,
        required: false 
    },
    ipAddress: { 
        type: String 
    },
    status: { 
        type: String, 
        enum: ['SUCCESS', 'FAILURE', 'WARNING', 'PENDING_VERIFICATION'], 
        default: 'SUCCESS' 
    },
    details: { 
        type: String 
    },
    timestamp: { 
        type: Date, 
        default: Date.now,
        expires: 60 * 60 * 24 * 365
    }
});

module.exports = mongoose.model('AuditLog', auditLogSchema);