const mongoose = require('mongoose');

const documentSchema = new mongoose.Schema({
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    fileName: {
        type: String,
        required: true
    },
    fileType: {
        type: String,
        required: true
    },
    size: {
        type: Number,
        required: true
    },
    gridFsId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true
    },

    encryption: {
        iv: { type: String, required: true },       // Initialization Vector
        authTag: { type: String, required: true },  // Integrity Check
        wrappedKey: { type: String, required: true } // The Encrypted Key
    },
    folder: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Folder',
        default: null
    },

    acl: [{
        viewer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        permission: { type: String, enum: ['view', 'download'], default: 'view' },
        validUntil: { type: Date },
        grantedAt: { type: Date, default: Date.now }
    }],

    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Document', documentSchema);