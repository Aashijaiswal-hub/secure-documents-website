const mongoose = require('mongoose');

const folderSchema = new mongoose.Schema({
    name: { 
        type: String, 
        required: true 
    },
    owner: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    parent: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Folder',
        default: null
    },
    path: [{ 
        name: String, 
        id: mongoose.Schema.Types.ObjectId 
    }], // Breadcrumb trail (Home > Finance > 2023)
    createdAt: { 
        type: Date, 
        default: Date.now 
    }
});

folderSchema.index({ owner: 1, parent: 1, name: 1 }, { unique: true });

module.exports = mongoose.model('Folder', folderSchema);