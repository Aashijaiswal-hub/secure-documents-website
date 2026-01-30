import { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { PiFileArrowUpDuotone } from "react-icons/pi";
import { LuUpload } from "react-icons/lu";
import api from '../utils/api';
import FolderTree from './FolderTree';

const UploadModal = ({ isOpen, onClose, currentFolderId, onSuccess }) => {
    const [file, setFile] = useState(null);
    const [allFolders, setAllFolders] = useState([]);
    const [selectedFolder, setSelectedFolder] = useState(currentFolderId || 'root');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (isOpen) {
            setFile(null);
            setSelectedFolder(currentFolderId || 'root');
            fetchFolders();
        }
    }, [isOpen, currentFolderId]);

    const fetchFolders = async () => {
        try {
            const { data } = await api.get('/folders/all');
            setAllFolders(data);
        } catch (error) {
            console.error("Failed to load folders");
        }
    };

    const handleUpload = async () => {
        if (!file) return;

        setLoading(true);
        const formData = new FormData();
        formData.append('file', file);
        const destination = selectedFolder === 'root' ? null : selectedFolder;
        formData.append('folderId', destination);

        try {
            await api.post('/documents/upload', formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            onSuccess();
            onClose();
        } catch (error) {
            alert('Upload failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="sm:max-w-[500px]">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <LuUpload className="h-5 w-5 text-blue-600" />
                        Secure Upload
                    </DialogTitle>
                </DialogHeader>

                <div className="py-4 space-y-6">
                    <div className="border-2 border-dashed border-slate-300 rounded-lg p-6 text-center hover:bg-slate-50 transition cursor-pointer relative">
                        <input
                            type="file"
                            className="absolute inset-0 opacity-0 cursor-pointer"
                            onChange={(e) => setFile(e.target.files[0])}
                        />
                        <div className="flex flex-col items-center gap-2 pointer-events-none">
                            <PiFileArrowUpDuotone className="h-8 w-8 text-slate-400" />
                            {file ? (
                                <span className="text-sm font-semibold text-blue-600 truncate max-w-[200px]">
                                    {file.name}
                                </span>
                            ) : (
                                <>
                                    <span className="text-sm font-medium text-slate-700">Click to select a file</span>
                                    <span className="text-xs text-slate-500">Max size: 50MB</span>
                                </>
                            )}
                        </div>
                    </div>
                    <div>
                        <p className="text-sm font-medium text-slate-700 mb-2">Upload Destination:</p>
                        <FolderTree
                            folders={allFolders}
                            selectedId={selectedFolder}
                            onSelect={setSelectedFolder}
                        />
                    </div>
                </div>

                <DialogFooter>
                    <Button variant="outline" onClick={onClose}>Cancel</Button>
                    <Button onClick={handleUpload} disabled={!file || loading}>
                        {loading ? 'Encrypting & Uploading...' : 'Upload Securely'}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
};

export default UploadModal;