const express = require('express');
const { protect } = require('../middleware/authMiddleware');
const { createFolder, getFolderContent, getAllFolders } = require('../controllers/folderController');

const router = express.Router();

router.use(protect); 

router.post('/', createFolder);

router.get('/all', getAllFolders); 

router.get('/:id', getFolderContent);

module.exports = router;