import { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TbFolderPlus } from "react-icons/tb";
import api from '../utils/api';
import FolderTree from './FolderTree';

const CreateFolderModal = ({ isOpen, onClose, parentId, onSuccess }) => {
    const [name, setName] = useState('');
    const [loading, setLoading] = useState(false);
    const [allFolders, setAllFolders] = useState([]);
    const [selectedParent, setSelectedParent] = useState(parentId || 'root');

    useEffect(() => {
        if (isOpen) {
            setSelectedParent(parentId || 'root');
            const fetchFolders = async () => {
                try {
                    const { data } = await api.get('/folders/all');
                    setAllFolders(data);
                } catch (error) {
                    console.error("Failed to load folders");
                }
            };
            fetchFolders();
        }
    }, [isOpen, parentId]);

    const handleCreate = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const finalParentId = selectedParent === 'root' ? null : selectedParent;
            await api.post('/folders', { name, parentId: finalParentId });
            setName('');
            onSuccess();
            onClose();
        } catch (error) {
            alert(error.response?.data?.message || "Failed to create folder");
        } finally {
            setLoading(false);
        }
    };

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <TbFolderPlus className="h-5 w-5 text-blue-600" />
                        Create New Folder
                    </DialogTitle>
                </DialogHeader>
                <form onSubmit={handleCreate}>
                    <div className="grid gap-4 py-4">
                        <div className="grid grid-cols-4 items-center gap-4">
                            <Label htmlFor="folderName" className="text-right">Name</Label>
                            <Input
                                id="folderName"
                                value={name}
                                onChange={(e) => setName(e.target.value)}
                                className="col-span-3"
                                placeholder="e.g. Finance"
                                required
                            />
                        </div>
                        <div className="grid grid-cols-4 items-start gap-4 mt-2">
                            <Label className="text-right mt-2">Location</Label>
                            <div className="col-span-3">
                                <FolderTree
                                    folders={allFolders}
                                    selectedId={selectedParent}
                                    onSelect={setSelectedParent}
                                />
                            </div>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
                        <Button type="submit" disabled={loading}>
                            {loading ? 'Creating...' : 'Create Folder'}
                        </Button>
                    </DialogFooter>
                </form>
            </DialogContent>
        </Dialog>
    );
};

export default CreateFolderModal;