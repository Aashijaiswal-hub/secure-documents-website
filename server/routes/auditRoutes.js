const express = require('express');
const { getMyLogs } = require('../controllers/auditController');
const { protect } = require('../middleware/authMiddleware');
const router = express.Router();

router.get('/', protect, getMyLogs);

module.exports = router;