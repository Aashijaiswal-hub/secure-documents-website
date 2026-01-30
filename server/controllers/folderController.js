const Folder = require('../models/Folder');
const Document = require('../models/Document');

// @desc    Create New Folder
// @route   POST /api/folders
exports.createFolder = async (req, res) => {
    try {
        const { name, parentId } = req.body;

        const newFolder = await Folder.create({
            name,
            owner: req.user.id,
            parent: parentId || null
        });

        res.status(201).json(newFolder);
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ message: 'Folder with this name already exists here' });
        }
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Get Content of a Folder (Subfolders + Files)
// @route   GET /api/folders/:id (or /api/folders/root)
exports.getFolderContent = async (req, res) => {
    try {
        const folderId = req.params.id === 'root' ? null : req.params.id;
        const folders = await Folder.find({
            owner: req.user.id,
            parent: folderId
        }).sort({ name: 1 });

        const documents = await Document.find({
            owner: req.user.id,
            folder: folderId
        })
            .select('-encryption -gridFsId')
            .populate('owner', 'fullName email')
            .sort({ createdAt: -1 });

        let currentFolder = null;
        if (folderId) {
            currentFolder = await Folder.findById(folderId);
        }

        res.status(200).json({ folders, documents, currentFolder });
    } catch (error) {
        console.error("Folder Fetch Error:", error);
        res.status(500).json({ message: 'Server Error' });
    }
};

// @desc    Get ALL folders (flat list for tree building)
// @route   GET /api/folders/all
exports.getAllFolders = async (req, res) => {
    try {
        const folders = await Folder.find({ owner: req.user.id })
            .select('name parent _id')
            .sort({ name: 1 });

        res.status(200).json(folders);
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
};