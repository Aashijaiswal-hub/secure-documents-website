import { useState } from 'react';
import { AiOutlineClose } from "react-icons/ai";
import { TbMailShare } from "react-icons/tb";
import { TfiTimer } from "react-icons/tfi";

const ShareModal = ({ isOpen, onClose, onShare, docName }) => {
    const [email, setEmail] = useState('');
    const [duration, setDuration] = useState(24); 
    const [loading, setLoading] = useState(false);

    if (!isOpen) return null;

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        await onShare(email, duration);
        setLoading(false);
        onClose();
        setEmail('');
    };

    return (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 backdrop-blur-sm">
            <div className="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in duration-200">
                {/* Header */}
                <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50">
                    <h3 className="font-semibold text-slate-800">Share Securely</h3>
                    <button onClick={onClose} className="text-slate-400 hover:text-red-500 transition">
                        <AiOutlineClose  className="h-5 w-5" />
                    </button>
                </div>

                {/* Body */}
                <div className="p-6">
                    <p className="text-sm text-slate-500 mb-4">
                        Sharing <span className="font-bold text-slate-800">{docName}</span>. 
                        Access will be automatically revoked after the time limit.
                    </p>

                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div>
                            <label className="block text-xs font-medium text-slate-700 uppercase mb-1">Recipient Email</label>
                            <div className="relative">
                                <TbMailShare className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                                <input 
                                    type="email" 
                                    required
                                    className="w-full pl-9 pr-3 py-2 border rounded-md focus:ring-2 focus:ring-blue-500 outline-none"
                                    placeholder="officer@agency.gov.in"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-xs font-medium text-slate-700 uppercase mb-1">Access Duration (Hours)</label>
                            <div className="relative">
                                <TfiTimer className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                                <input 
                                    type="number" 
                                    min="1"
                                    max="72"
                                    required
                                    className="w-full pl-9 pr-3 py-2 border rounded-md focus:ring-2 focus:ring-blue-500 outline-none"
                                    value={duration}
                                    onChange={(e) => setDuration(e.target.value)}
                                />
                            </div>
                        </div>

                        <button 
                            type="submit" 
                            disabled={loading}
                            className="w-full mt-2 bg-blue-900 hover:bg-blue-800 text-white font-medium py-2 rounded-md transition disabled:opacity-50"
                        >
                            {loading ? 'Granting Access...' : 'Generate Secure Link'}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
};

export default ShareModal;