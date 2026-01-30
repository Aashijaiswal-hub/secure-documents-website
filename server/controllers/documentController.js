const mongoose = require('mongoose');
const Document = require('../models/Document');
const User = require('../models/User');
const { encryptBuffer } = require('../utils/crypto');
const { Readable } = require('stream');
const { decryptBuffer } = require('../utils/crypto');
const logAudit = require('../utils/audit');

// Initialize GridFS Bucket
let bucket;
mongoose.connection.once('open', () => {
    bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
        bucketName: 'documents'
    });
});

// @desc    Upload and Encrypt Document
// @route   POST /api/documents/upload
// @access  Private
exports.uploadDocument = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        // 1. Encrypt the file buffer
        // Note: For very large files (hundreds of MBs), we would use stream transformation.
        // For this MVP (docs < 16MB-50MB), memory buffer is acceptable and simpler.
        const { encryptedBuffer, iv, authTag, wrappedKey } = encryptBuffer(req.file.buffer);

        // 2. Create a Readable Stream from the encrypted buffer
        const readableStream = new Readable();
        readableStream.push(encryptedBuffer);
        readableStream.push(null); // Signal end of stream

        // 3. Stream to GridFS
        const uploadStream = bucket.openUploadStream(req.file.originalname, {
            metadata: {
                contentType: req.file.mimetype,
                owner: req.user.id // purely for DB admin reference
            }
        });

        const gridFsId = uploadStream.id;
        readableStream.pipe(uploadStream);

        // 4. Handle Stream Events
        uploadStream.on('error', (error) => {
            console.error('GridFS Upload Error:', error);
            return res.status(500).json({ message: 'Error uploading file' });
        });

        uploadStream.on('finish', async () => {
            // 5. Save Metadata to "Documents" collection
            try {
                let folderId = req.body.folderId;
                if (folderId === 'root' || folderId === 'null') folderId = null;

                const newDoc = await Document.create({
                    owner: req.user.id,
                    fileName: req.file.originalname,
                    fileType: req.file.mimetype,
                    size: req.file.size,
                    gridFsId: gridFsId,
                    folder: folderId,
                    encryption: {
                        iv,
                        authTag,
                        wrappedKey
                    }
                });

                await newDoc.save();

                logAudit({
                    action: 'UPLOAD',
                    actor: req.user.id,
                    resource: newDoc.fileName,
                    ip: req.ip,
                    status: 'SUCCESS'
                });

                res.status(201).json({
                    message: 'Document encrypted and stored securely',
                    documentId: newDoc._id
                });
            } catch (dbError) {
                // If metadata save fails, we should ideally delete the GridFS orphan.
                // For MVP, we log it.
                console.error('Metadata Save Error:', dbError);
                res.status(500).json({ message: 'Database error' });
            }
        });

    } catch (error) {
        console.error('Upload Controller Error:', error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Download and Decrypt Document
// @route   GET /api/documents/:id
// @access  Private (Owner or Shared)
exports.getDocument = async (req, res) => {
    try {
        // 1. Fetch Metadata
        const doc = await Document.findById(req.params.id);

        if (!doc) {
            return res.status(404).json({ message: 'Document not found' });
        }

        const isOwner = doc.owner.toString() === req.user.id;

        const sharedPermission = doc.acl.find(entry =>
            entry.viewer.toString() === req.user.id &&
            new Date(entry.validUntil) > new Date()
        );

        if (!isOwner && !sharedPermission) {
            return res.status(403).json({ message: 'Access Denied or Permission Expired' });
        }

        // 3. Fetch Encrypted Chunks from GridFS
        const downloadStream = bucket.openDownloadStream(doc.gridFsId);
        let encryptedChunks = [];

        downloadStream.on('data', (chunk) => {
            encryptedChunks.push(chunk);
        });

        downloadStream.on('error', (error) => {
            console.error('GridFS Download Error:', error);
            res.status(404).json({ message: 'File not found in storage' });
        });

        downloadStream.on('end', async () => {
            try {
                // Combine chunks into a single buffer
                const encryptedBuffer = Buffer.concat(encryptedChunks);

                // 4. Decrypt
                const decryptedBuffer = decryptBuffer(
                    encryptedBuffer,
                    doc.encryption.iv,
                    doc.encryption.authTag,
                    doc.encryption.wrappedKey
                );

                // 5. Send Response
                res.set('Content-Type', doc.fileType);
                res.set('Content-Disposition', `inline; filename="${doc.fileName}"`);
                logAudit({
                    action: 'VIEW',
                    actor: req.user.id,
                    resource: doc.fileName,
                    ip: req.ip,
                    status: 'SUCCESS'
                });
                res.send(decryptedBuffer);

            } catch (cryptoError) {
                console.error('Decryption Failed:', cryptoError.message);
                // This usually means data corruption or tampering (AuthTag mismatch)
                res.status(500).json({ message: 'Integrity Check Failed: Document may be corrupted or tampered with.' });
            }
        });

    } catch (error) {
        console.error('Get Document Error:', error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Get all documents (Owned + Shared) with Search
// @route   GET /api/documents?search=...
// @access  Private
exports.getUserDocuments = async (req, res) => {
    try {
        const search = req.query.search || '';
        let query = {
            $or: [
                { owner: req.user.id },
                {
                    acl: {
                        $elemMatch: {
                            viewer: req.user.id,
                            validUntil: { $gt: new Date() }
                        }
                    }
                }
            ]
        };

        //Search Rule: If search term exists, match filename
        if (search) {
            query.fileName = { $regex: search, $options: 'i' };
        }

        const documents = await Document.find(query)
            .select('-encryption -gridFsId')
            .populate('owner', 'fullName email')
            .sort({ createdAt: -1 });

        res.status(200).json(documents);
    } catch (error) {
        console.error('Get All Docs Error:', error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Share Document with another user
// @route   POST /api/documents/:id/share
// @access  Private (Owner Only)
exports.shareDocument = async (req, res) => {
    const { email, durationInHours } = req.body;

    try {
        const doc = await Document.findById(req.params.id);

        if (!doc) {
            return res.status(404).json({ message: 'Document not found' });
        }

        // 1. Ownership Check (Only owner can share)
        if (doc.owner.toString() !== req.user.id) {
            return res.status(403).json({ message: 'Not authorized to share this document' });
        }

        // 2. Find the Target User
        const userToShareWith = await User.findOne({ email });
        if (!userToShareWith) {
            return res.status(404).json({ message: 'User with this email not found' });
        }

        // 3. Prevent sharing with self
        if (userToShareWith._id.toString() === req.user.id) {
            return res.status(400).json({ message: 'You already own this document' });
        }

        // 4. Calculate Expiry
        // Default to 24 hours if not specified
        const validUntil = new Date();
        validUntil.setHours(validUntil.getHours() + (durationInHours || 24));

        // 5. Update ACL (Add or Update entry)
        // Check if already shared
        const existingEntryIndex = doc.acl.findIndex(
            (entry) => entry.viewer.toString() === userToShareWith._id.toString()
        );

        const newEntry = {
            viewer: userToShareWith._id,
            permission: 'view',
            validUntil: validUntil,
            grantedAt: new Date()
        };

        if (existingEntryIndex > -1) {
            // Update existing permission
            doc.acl[existingEntryIndex] = newEntry;
        } else {
            // Add new permission
            doc.acl.push(newEntry);
        }

        await doc.save();
        logAudit({
            action: 'SHARE',
            actor: req.user.id,
            resource: doc.fileName,
            ip: req.ip,
            details: `Shared with ${email} for ${durationInHours}h`
        });
        res.status(200).json({
            message: `Document shared with ${email}`,
            validUntil: validUntil
        });

    } catch (error) {
        console.error('Share Error:', error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Rename Document
// @route   PUT /api/documents/:id/rename
// @access  Private (Owner Only)
exports.renameDocument = async (req, res) => {
    try {
        const { newName } = req.body;
        const doc = await Document.findById(req.params.id);

        if (!doc) return res.status(404).json({ message: 'Document not found' });

        if (doc.owner.toString() !== req.user.id) {
            return res.status(403).json({ message: 'Not authorized to rename' });
        }

        const oldExt = doc.fileName.split('.').pop();
        const newExt = newName.split('.').pop();

        if (oldExt !== newExt) {
            return res.status(400).json({ message: `You cannot change the file extension (.${oldExt})` });
        }

        doc.fileName = newName;
        await doc.save();

        res.status(200).json({ message: 'Document renamed', fileName: newName });
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Move Document to a different folder
// @route   PUT /api/documents/:id/move
// @access  Private (Owner Only)
exports.moveDocument = async (req, res) => {
    try {
        const { destinationFolderId } = req.body;

        const doc = await Document.findById(req.params.id);

        if (!doc) return res.status(404).json({ message: 'Document not found' });
        if (doc.owner.toString() !== req.user.id) {
            return res.status(403).json({ message: 'Not authorized to move this file' });
        }
        doc.folder = destinationFolderId || null;

        await doc.save();

        res.status(200).json({ message: 'Document moved successfully' });
    } catch (error) {
        console.error("Move Error:", error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Bulk Move Documents
// @route   PUT /api/documents/bulk/move
// @access  Private
exports.bulkMoveDocuments = async (req, res) => {
    try {
        const { docIds, destinationFolderId } = req.body;
        await Document.updateMany(
            { _id: { $in: docIds }, owner: req.user.id },
            { folder: destinationFolderId || null }
        );

        res.status(200).json({ message: 'Documents moved successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Bulk Delete Documents
// @route   DELETE /api/documents/bulk/delete
// @access  Private
exports.bulkDeleteDocuments = async (req, res) => {
    try {
        const { docIds } = req.body;
        const docs = await Document.find({ _id: { $in: docIds }, owner: req.user.id });

        const bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
            bucketName: 'documents'
        });

        for (const doc of docs) {
            try {
                if (doc.gridFsId) await bucket.delete(doc.gridFsId);
            } catch (err) {
                console.warn(`Failed to delete GridFS file ${doc.gridFsId}:`, err.message);
            }
        }
        await Document.deleteMany({ _id: { $in: docIds }, owner: req.user.id });
        res.status(200).json({ message: 'Documents deleted successfully' });
    } catch (error) {
        console.error("Bulk Delete Error:", error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Get ONLY documents shared with the user
// @route   GET /api/documents/shared
// @access  Private
exports.getSharedDocuments = async (req, res) => {
    try {
        const docs = await Document.find({
            'acl.viewer': req.user.id,
            owner: { $ne: req.user.id }
        })
            .select('-encryption -gridFsId')
            .populate('owner', 'fullName email')
            .sort({ createdAt: -1 });

        res.status(200).json(docs);
    } catch (error) {
        console.error('Get Shared Docs Error:', error);
        res.status(500).json({ message: 'Server Error' });
    }
};