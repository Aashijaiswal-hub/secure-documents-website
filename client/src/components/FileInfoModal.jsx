import { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RiFileTextLine } from "react-icons/ri";
import { BsCalendarEvent } from "react-icons/bs";
import { PiHardDrives } from "react-icons/pi";
import api from '../utils/api';

const FileInfoModal = ({ isOpen, onClose, doc, onRenameSuccess }) => {
    const [name, setName] = useState('');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (doc) setName(doc.fileName);
    }, [doc]);

    const handleRename = async () => {
        if (!doc || name === doc.fileName) return;
        
        setLoading(true);
        try {
            await api.put(`/documents/${doc._id}/rename`, { newName: name });
            onRenameSuccess();
            onClose();
        } catch (error) {
            alert(error.response?.data?.message || "Rename failed");
        } finally {
            setLoading(false);
        }
    };

    if (!doc) return null;

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                    <DialogTitle>File Details</DialogTitle>
                </DialogHeader>
                
                <div className="grid gap-4 py-4">
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="name" className="text-right">Name</Label>
                        <Input 
                            id="name" 
                            value={name} 
                            onChange={(e) => setName(e.target.value)} 
                            className="col-span-3" 
                        />
                    </div>
                    <div className="space-y-3 mt-2 border-t pt-4">
                        <div className="flex items-center gap-3 text-sm text-slate-600">
                            <PiHardDrives className="h-4 w-4" />
                            <span>Size: {(doc.size / 1024).toFixed(2)} KB</span>
                        </div>
                        <div className="flex items-center gap-3 text-sm text-slate-600">
                            <RiFileTextLine className="h-4 w-4" />
                            <span>Type: {doc.fileType}</span>
                        </div>
                        <div className="flex items-center gap-3 text-sm text-slate-600">
                            <BsCalendarEvent className="h-4 w-4" />
                            <span>Uploaded: {new Date(doc.createdAt).toLocaleString()}</span>
                        </div>
                    </div>
                </div>

                <DialogFooter>
                    <Button variant="outline" onClick={onClose}>Cancel</Button>
                    <Button onClick={handleRename} disabled={loading || name === doc.fileName}>
                        {loading ? 'Saving...' : 'Save Changes'}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
};

export default FileInfoModal;