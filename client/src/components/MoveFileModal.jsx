import { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { LuFolderInput } from "react-icons/lu";
import api from '../utils/api';
import FolderTree from './FolderTree';

const MoveFileModal = ({ isOpen, onClose, doc, docIds, onSuccess }) => {
    const [allFolders, setAllFolders] = useState([]);
    const [selectedFolder, setSelectedFolder] = useState('root');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        const fetchFolders = async () => {
            if (isOpen) {
                try {
                    const { data } = await api.get('/folders/all');
                    setAllFolders(data);
                } catch (error) {
                    console.error("Failed to load folders");
                }
            }
        };
        fetchFolders();
    }, [isOpen]);

    const handleMove = async () => {
        setLoading(true);
        try {
            const destination = selectedFolder === 'root' ? null : selectedFolder;

            if (docIds && docIds.length > 0) {
                await api.put('/documents/bulk/move', {
                    docIds,
                    destinationFolderId: destination
                });
            } else if (doc) {
                await api.put(`/documents/${doc._id}/move`, {
                    destinationFolderId: destination
                });
            }

            onSuccess();
            onClose();
        } catch (error) {
            alert("Failed to move file");
        } finally {
            setLoading(false);
        }
    };

    const titleText = docIds?.length > 0
        ? `Move ${docIds.length} items`
        : `Move "${doc?.fileName}"`;

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="sm:max-w-[500px]">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <LuFolderInput className="h-5 w-5 text-blue-600" />
                        Move {titleText}
                    </DialogTitle>
                </DialogHeader>

                <div className="py-4">
                    <p className="text-sm text-slate-500 mb-3">Select a destination:</p>
                    <FolderTree
                        folders={allFolders}
                        selectedId={selectedFolder}
                        onSelect={setSelectedFolder}
                    />
                </div>

                <DialogFooter>
                    <Button variant="outline" onClick={onClose}>Cancel</Button>
                    <Button onClick={handleMove} disabled={loading}>
                        {loading ? 'Moving...' : 'Move Here'}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
};

export default MoveFileModal;