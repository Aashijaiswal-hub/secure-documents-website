const express = require('express');
const { createFolder, getFolderContent, getAllFolders } = require('../controllers/folderController');
const { protect } = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/', protect, createFolder);

router.get('/all', protect, getAllFolders);

router.get('/:id', protect, getFolderContent);

module.exports = router;