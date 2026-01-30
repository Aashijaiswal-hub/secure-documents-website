const express = require('express');
const multer = require('multer');
const { uploadDocument, getDocument, shareDocument, getUserDocuments, getSharedDocuments, renameDocument, moveDocument, bulkMoveDocuments, bulkDeleteDocuments } = require('../controllers/documentController');
const { protect } = require('../middleware/authMiddleware');

const router = express.Router();

const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }
});

router.get('/', protect, getUserDocuments);

router.get('/shared', protect, getSharedDocuments);

router.post('/upload', protect, upload.single('file'), uploadDocument);

router.put('/bulk/move', protect, bulkMoveDocuments);

router.delete('/bulk/delete', protect, bulkDeleteDocuments);

router.get('/:id', protect, getDocument);

router.post('/:id/share', protect, shareDocument);

router.put('/:id/rename', protect, renameDocument);

router.put('/:id/move', protect, moveDocument);

module.exports = router;