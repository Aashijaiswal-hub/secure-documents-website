import { useEffect, useState, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import api from '../utils/api';
import ProfileMenu from '../components/ProfileMenu';
import { toast } from "sonner";
import SkeletonLoader from '../components/SkeletonLoader';
import FileInfoModal from '@/components/FileInfoModal';
import ShareModal from '../components/ShareModal';
import CreateFolderModal from '../components/CreateFolderModal';
import UploadModal from '../components/UploadModal';
import MoveFileModal from '@/components/MoveFileModal';
import { useNavigate } from 'react-router-dom';
import { GoShieldLock, GoEye } from "react-icons/go";
import { ImFileText2 } from "react-icons/im";
import { MdOutlineShare, MdClose } from "react-icons/md";
import { BsInfoCircle } from "react-icons/bs";
import { AiOutlineFileSearch } from "react-icons/ai";
import { HiOutlineChevronRight } from "react-icons/hi2";
import { IoFolderOutline, IoShareSocialOutline } from "react-icons/io5";
import { RiHome9Line } from "react-icons/ri";
import { TbFolderPlus } from "react-icons/tb";
import { LuFolderInput, LuTrash2, LuUpload } from "react-icons/lu";


const Dashboard = () => {
    const { user, logout } = useContext(AuthContext);
    const [documents, setDocuments] = useState([]);
    const [loading, setLoading] = useState(true);
    const [isShareOpen, setIsShareOpen] = useState(false);
    const [selectedDoc, setSelectedDoc] = useState(null);
    const [showLogs, setShowLogs] = useState(false);
    const [isInfoOpen, setIsInfoOpen] = useState(false);
    const [logs, setLogs] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');

    const [folders, setFolders] = useState([]);
    const [currentFolder, setCurrentFolder] = useState(null);
    const [folderPath, setFolderPath] = useState([]);
    const [isCreateFolderOpen, setIsCreateFolderOpen] = useState(false);

    const [isMoveOpen, setIsMoveOpen] = useState(false);
    const [isUploadOpen, setIsUploadOpen] = useState(false);

    const [selectedIds, setSelectedIds] = useState([]);
    const navigate = useNavigate();

    const fetchLogs = async () => {
        const { data } = await api.get('/audit');
        setLogs(data);
        setShowLogs(true);
    };

    const openInfoModal = (doc) => {
        setSelectedDoc(doc);
        setIsInfoOpen(true);
    };

    const openMoveModal = (doc) => {
        setSelectedDoc(doc);
        setIsMoveOpen(true);
    };

    const fetchContent = async (folderId = currentFolder?._id) => {
        try {
            setLoading(true);

            if (searchTerm) {
                const { data } = await api.get(`/documents?search=${searchTerm}`);
                setDocuments(data);
                setFolders([]);
                return;
            }

            if (folderId === 'shared-virtual') {
                const { data } = await api.get('/documents/shared');
                setDocuments(data);
                setFolders([]);
                return;
            }

            const endpoint = folderId ? `/folders/${folderId}` : '/folders/root';
            const { data } = await api.get(endpoint);

            let folderList = data.folders;
            if (!folderId) {
                const sharedFolder = {
                    _id: 'shared-virtual',
                    name: 'Shared with Me',
                    isVirtual: true
                };
                folderList = [sharedFolder, ...data.folders];
            }

            setFolders(folderList);
            setDocuments(data.documents);
        } catch (error) {
            console.error("Failed to fetch content", error);
        } finally {
            setLoading(false);
        }
    };
    useEffect(() => {
        fetchContent();
    }, [currentFolder, searchTerm]);

    const openShareModal = (doc) => {
        setSelectedDoc(doc);
        setIsShareOpen(true);
    };

    const handleView = async (id) => {
        try {
            const response = await api.get(`/documents/${id}`, {
                responseType: 'blob' // Important: Expect binary data
            });

            // Create a blob URL to view in new tab
            const fileURL = window.URL.createObjectURL(new Blob([response.data], { type: response.headers['content-type'] }));
            window.open(fileURL, '_blank');
        } catch (error) {
            alert('Failed to decrypt document');
        }
    };

    const handleShare = async (email, duration) => {
        try {
            const toastId = toast.loading("Granting access...");

            await api.post(`/documents/${selectedDoc._id}/share`, {
                email,
                durationInHours: duration
            });
            toast.dismiss(toastId);
            toast.success(`Successfully shared with ${email}`);
            setIsShareOpen(false);
        } catch (error) {
            toast.error(error.response?.data?.message || 'Sharing failed');
        }
    }

    const handleEnterFolder = (folder) => {
        if (currentFolder) {
            setFolderPath([...folderPath, currentFolder]);
        } else {
            setFolderPath([]);
        }
        setCurrentFolder(folder);
        setSearchTerm('');
    };

    const handleNavigateUp = (index) => {
        if (index === -1) {
            setCurrentFolder(null); // Go to Root
            setFolderPath([]);
        } else {
            const newFolder = folderPath[index];
            setCurrentFolder(newFolder);
            setFolderPath(folderPath.slice(0, index));
        }
    };

    // Toggle single row
    const toggleSelect = (id) => {
        setSelectedIds(prev =>
            prev.includes(id) ? prev.filter(item => item !== id) : [...prev, id]
        );
    };

    // Toggle "Select All"
    const toggleSelectAll = () => {
        if (selectedIds.length === documents.length) {
            setSelectedIds([]); // Uncheck all
        } else {
            setSelectedIds(documents.map(d => d._id)); // Check all
        }
    };

    // Bulk Delete Handler
    const handleBulkDelete = async () => {
        if (!window.confirm(`Are you sure you want to delete ${selectedIds.length} items?`)) return;

        try {
            const toastId = toast.loading("Deleting files...");
            await api.delete('/documents/bulk/delete', { data: { docIds: selectedIds } }); // Note: DELETE sends data in 'data' key
            toast.dismiss(toastId);
            toast.success("Files deleted permanently");

            setSelectedIds([]);
            fetchContent();
        } catch (error) {
            toast.error('Delete failed');
        }
    };

    return (
        <div className="min-h-screen bg-slate-50">
            {/* Navbar */}
            <nav className="bg-white border-b border-slate-200 px-8 py-4 flex justify-between items-center">
                <div className="flex items-center gap-2 text-slate-800">
                    <GoShieldLock className="h-8 w-8 text-blue-900" />
                    <span className="text-xl font-bold tracking-tight">SecureVault</span>
                </div>
                <div className="flex items-center gap-6">
                    <ProfileMenu
                        user={user}
                        onLogout={async () => {
                            await logout();
                            navigate('/login');
                        }}
                        onOpenLogs={() => {
                            fetchLogs();
                        }}
                    />
                </div>
            </nav>

            {/* Main Content */}
            <main className="max-w-6xl mx-auto px-8 py-6">
                {/* Breadcrumbs */}
                <div className="mb-6 p-3 bg-slate-100 rounded-lg border border-slate-200 flex items-center gap-2 text-sm text-slate-600 overflow-x-auto">
                    <button
                        onClick={() => handleNavigateUp(-1)}
                        className={`flex items-center hover:text-blue-600 ${!currentFolder ? 'font-bold text-slate-900' : ''}`}
                    >
                        <RiHome9Line className="h-4 w-4 mr-1" /> Home
                    </button>

                    {folderPath.map((folder, index) => (
                        <div key={folder._id} className="flex items-center gap-2 shrink-0">
                            <HiOutlineChevronRight className="h-4 w-4 text-slate-400" />
                            <button
                                onClick={() => handleNavigateUp(index)}
                                className="hover:text-blue-600 transition font-medium"
                            >
                                {folder.name}
                            </button>
                        </div>
                    ))}

                    {currentFolder && (
                        <div className="flex items-center gap-2 shrink-0">
                            <HiOutlineChevronRight className="h-4 w-4 text-slate-400" />
                            <span className="font-bold text-slate-900">{currentFolder.name}</span>
                        </div>
                    )}
                </div>
                <div className="flex justify-between items-center mb-8">
                    <h1 className="text-2xl font-bold text-slate-900">
                        {currentFolder?.isVirtual ? 'Shared with Me' : 'My Documents'}
                    </h1>

                    <div className="relative w-96 mx-4">
                        <AiOutlineFileSearch className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                        <input
                            type="text"
                            placeholder="Search files..."
                            className="w-full pl-10 pr-4 py-2 border rounded-md focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                    {!currentFolder?.isVirtual && (
                        <>
                            <button
                                onClick={() => setIsUploadOpen(true)}
                                className="flex items-center gap-2 px-4 py-2 bg-blue-900 text-white rounded-md hover:bg-blue-800 transition shadow-sm"
                            >
                                <LuUpload className="h-4 w-4" />
                                Secure Upload
                            </button>
                            <button
                                onClick={() => setIsCreateFolderOpen(true)}
                                className="ml-3 px-4 py-2 bg-white border border-slate-300 text-slate-700 rounded-md hover:bg-slate-50 transition flex items-center gap-2"
                            >
                                <TbFolderPlus className="h-4 w-4" /> New Folder
                            </button>
                        </>
                    )}
                </div>

                {/* Document Table */}
                {loading ? (
                    <>
                        <SkeletonLoader mode="grid" />
                        <SkeletonLoader mode="table" />
                    </>
                ) : (
                    <>
                        {/* Folder Grid */}
                        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
                            {folders.length > 0 && !searchTerm && (
                                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-6 mb-10 p-6 pb-0">
                                    {folders.map(folder => (
                                        <div
                                            key={folder._id}
                                            onClick={() => handleEnterFolder(folder)}
                                            // --- VIRTUAL FOLDER STYLE ---
                                            className={`group p-5 border rounded-xl hover:shadow-md cursor-pointer transition-all flex flex-col items-center justify-center text-center aspect-square
                                        ${folder.isVirtual
                                                    ? 'bg-blue-50 border-blue-200 hover:border-blue-400'
                                                    : 'bg-white border-slate-200 hover:border-blue-300'
                                                }`}
                                        >
                                            {folder.isVirtual ? (
                                                <IoShareSocialOutline className="h-12 w-12 text-blue-600 mb-3" />
                                            ) : (
                                                <IoFolderOutline className="h-12 w-12 text-blue-100 fill-blue-50 group-hover:text-blue-600 group-hover:fill-blue-100 transition-colors mb-3" />
                                            )}
                                            <span className={`text-sm font-semibold truncate w-full px-2 ${folder.isVirtual ? 'text-blue-800' : 'text-slate-700'}`}>
                                                {folder.name}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            )}
                            <table className="w-full text-left">
                                <thead className="bg-slate-50 text-slate-500 text-sm uppercase">
                                    <tr>
                                        <th className="px-6 py-4 w-12">
                                            <input
                                                type="checkbox"
                                                className="rounded border-slate-300"
                                                checked={documents.length > 0 && selectedIds.length === documents.length}
                                                onChange={toggleSelectAll}
                                            />
                                        </th>
                                        <th className="px-6 py-4 font-medium">Document Name</th>
                                        <th className="px-6 py-4 font-medium">Size</th>
                                        <th className="px-6 py-4 font-medium">Date Uploaded</th>
                                        <th className="px-6 py-4 font-medium text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100">
                                    {documents.length === 0 && !loading && (
                                        <tr>
                                            <td colSpan="4" className="px-6 py-10 text-center text-slate-400">
                                                No documents found. Upload one to get started.
                                            </td>
                                        </tr>
                                    )}

                                    {documents.map((doc) => (
                                        <tr key={doc._id} className="hover:bg-slate-50 transition">
                                            <td className="px-6 py-4">
                                                <input
                                                    type="checkbox"
                                                    className="rounded border-slate-300"
                                                    checked={selectedIds.includes(doc._id)}
                                                    onChange={() => toggleSelect(doc._id)}
                                                />
                                            </td>
                                            <td className="px-6 py-4 flex items-center gap-3">
                                                <div className="flex items-center gap-3">
                                                    <div className="p-2 bg-blue-50 text-blue-600 rounded">
                                                        <ImFileText2 className="h-5 w-5" />
                                                    </div>
                                                    <div className="flex flex-col">
                                                        <span className="font-medium text-slate-700">{doc.fileName}</span>
                                                        {currentFolder?.isVirtual && doc.owner && doc.owner._id !== user?.id && (
                                                            <span className="text-xs text-blue-600 flex items-center gap-1">
                                                                <IoShareSocialOutline className="h-3 w-3" />
                                                                Shared by {doc.owner.email}
                                                            </span>
                                                        )}
                                                    </div>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 text-slate-500 text-sm">
                                                {(doc.size / 1024).toFixed(2)} KB
                                            </td>
                                            <td className="px-6 py-4 text-slate-500 text-sm">
                                                {new Date(doc.createdAt).toLocaleDateString()}
                                            </td>
                                            <td className="px-6 py-4 text-right flex justify-end gap-3">
                                                <button
                                                    onClick={() => handleView(doc._id)}
                                                    className="p-2 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-full transition"
                                                    title="View Decrypted"
                                                >
                                                    <GoEye className="h-4 w-4" />
                                                </button>
                                                {!currentFolder?.isVirtual && (
                                                    <>
                                                        <button
                                                            onClick={() => openMoveModal(doc)}
                                                            className="p-2 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-full transition"
                                                            title="Move to Folder"
                                                        >
                                                            <LuFolderInput className="h-4 w-4" />
                                                        </button>
                                                        <button
                                                            onClick={() => openInfoModal(doc)}
                                                            className="p-2 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-full transition"
                                                            title="File Info & Rename"
                                                        >
                                                            <BsInfoCircle className="h-4 w-4" />
                                                        </button>
                                                        <button
                                                            onClick={() => openShareModal(doc)}
                                                            className="p-2 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-full transition"
                                                            title="Share Access"
                                                        >
                                                            <MdOutlineShare className="h-4 w-4" />
                                                        </button>
                                                    </>
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </>
                )}


                {showLogs && (
                    <div className="mt-10 bg-white p-6 rounded-xl border border-slate-200">
                        <h2 className="text-lg font-bold mb-4">Security Audit Trail</h2>
                        <button
                            onClick={() => setShowLogs(false)}
                            className="text-slate-400 hover:text-slate-600 p-2 rounded-full hover:bg-slate-100 transition"
                        >
                            <MdClose className="h-5 w-5" />
                        </button>
                        <div className="overflow-auto max-h-60">
                            <table className="w-full text-xs text-left">
                                <thead className="bg-slate-50 uppercase text-slate-500">
                                    <tr>
                                        <th className="px-4 py-2">Time</th>
                                        <th className="px-4 py-2">Action</th>
                                        <th className="px-4 py-2">Resource</th>
                                        <th className="px-4 py-2">Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {logs.map(log => (
                                        <tr key={log._id} className="border-b">
                                            <td className="px-4 py-2">{new Date(log.timestamp).toLocaleString()}</td>
                                            <td className="px-4 py-2 font-bold text-blue-800">{log.action}</td>
                                            <td className="px-4 py-2">{log.resource}</td>
                                            <td className="px-4 py-2 text-slate-500">{log.details}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}

                {selectedIds.length > 0 && (
                    <div className="fixed bottom-8 left-1/2 transform -translate-x-1/2 bg-slate-900 text-white px-6 py-3 rounded-full shadow-xl flex items-center gap-6 z-50 animate-in slide-in-from-bottom-4">
                        <span className="font-medium text-sm">{selectedIds.length} selected</span>

                        <div className="h-4 w-px bg-slate-700"></div> {/* Divider */}

                        <button
                            onClick={() => setIsMoveOpen(true)} // Re-uses your existing state!
                            className="flex items-center gap-2 text-sm hover:text-blue-300 transition"
                        >
                            <LuFolderInput className="h-4 w-4" /> Move
                        </button>

                        <button
                            onClick={handleBulkDelete}
                            className="flex items-center gap-2 text-sm hover:text-red-300 transition"
                        >
                            <LuTrash2 className="h-4 w-4" /> Delete
                        </button>

                        {/* Cancel Button */}
                        <button
                            onClick={() => setSelectedIds([])}
                            className="ml-2 text-slate-400 hover:text-white"
                        >
                            <MdClose className="h-4 w-4" />
                        </button>
                    </div>
                )}
            </main>
            <FileInfoModal
                isOpen={isInfoOpen}
                onClose={() => setIsInfoOpen(false)}
                doc={selectedDoc}
                onRenameSuccess={fetchContent}
            />
            <ShareModal
                isOpen={isShareOpen}
                onClose={() => setIsShareOpen(false)}
                onShare={handleShare}
                docName={selectedDoc?.fileName}
            />
            <CreateFolderModal
                isOpen={isCreateFolderOpen}
                onClose={() => setIsCreateFolderOpen(false)}
                parentId={currentFolder?._id}
                onSuccess={() => fetchContent()}
            />
            <MoveFileModal
                isOpen={isMoveOpen}
                onClose={() => setIsMoveOpen(false)}
                doc={selectedDoc}
                docIds={selectedIds}
                onSuccess={() => {
                    fetchContent();
                    setSelectedIds([]);
                }}
            />
            <UploadModal
                isOpen={isUploadOpen}
                onClose={() => setIsUploadOpen(false)}
                currentFolderId={currentFolder?._id}
                onSuccess={() => fetchContent()}
            />

        </div>
    );
};

export default Dashboard;