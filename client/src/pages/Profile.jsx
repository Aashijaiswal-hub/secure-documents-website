import { useEffect, useState, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import api from '../utils/api';
import { toast } from "sonner";
// import { GoShieldLock } from "react-icons/go";
import { HiOutlineArrowLeft } from "react-icons/hi";
import { FaUserCheck, FaHdd, FaFileAlt } from "react-icons/fa";
import SkeletonLoader from '../components/SkeletonLoader';

const Profile = () => {
    const [profile, setProfile] = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();
    const { logout } = useContext(AuthContext);

    useEffect(() => {
        const fetchProfile = async () => {
            try {
                const { data } = await api.get('/auth/me');
                setProfile(data);
            } catch (error) {
                console.error("Failed to load profile");
            } finally {
                setLoading(false);
            }
        };
        fetchProfile();
    }, []);

    if (loading) return <div className="p-10"><SkeletonLoader mode="table" /></div>;
    if (!profile) return null;

    const { user, stats } = profile;
    const usedPercent = (stats.usedStorage / stats.totalStorage) * 100;

    const formatSize = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const handleDeleteAccount = async () => {
        const confirmMessage = "Are you sure? This action is IRREVERSIBLE. All your documents and data will be permanently erased.";
        if (!window.confirm(confirmMessage)) return;
        if (!window.confirm("Really delete? This is your last chance.")) return;
        try {
            await api.delete('/auth/me');
            toast.success("Account deleted successfully");
            logout();
            navigate('/login');
        } catch (error) {
            console.error(error);
            toast.error(error.response?.data?.message || "Failed to delete account");
        }
    };

    return (
        <div className="min-h-screen bg-slate-50 p-8">
            <div className="max-w-2xl mx-auto">
                <button
                    onClick={() => navigate('/dashboard')}
                    className="flex items-center text-slate-500 hover:text-blue-900 mb-6 transition"
                >
                    <HiOutlineArrowLeft className="mr-2" /> Back to Vault
                </button>

                {/* Identity Card */}
                <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden mb-6">
                    <div className="bg-slate-900 p-6 flex items-center justify-between">
                        <div className="flex items-center gap-4">
                            <div className="h-16 w-16 rounded-full overflow-hidden border-2 border-white/20">
                                {user.avatar ? (
                                    <img
                                        src={user.avatar}
                                        alt="Profile"
                                        className="h-full w-full object-cover"
                                        referrerPolicy="no-referrer"
                                    />
                                ) : (
                                    <div className="h-full w-full bg-blue-600 flex items-center justify-center text-2xl font-bold text-white">
                                        {user.fullName.charAt(0)}
                                    </div>
                                )}
                            </div>
                            <div>
                                <h1 className="text-2xl font-bold text-white">{user.fullName}</h1>
                                <p className="text-slate-400">{user.email}</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-2 bg-green-500/20 text-green-400 px-3 py-1 rounded-full text-sm font-medium border border-green-500/30">
                            <FaUserCheck /> Verified Citizen
                        </div>
                    </div>

                    <div className="p-6 grid grid-cols-2 gap-6">
                        <div>
                            <label className="text-xs uppercase text-slate-500 font-bold">Aadhaar ID</label>
                            <p className="font-mono text-slate-800 text-lg">
                                {user.aadhaarId
                                    ? `XXXX-XXXX-${user.aadhaarId.slice(-4)}`
                                    : <span className="text-slate-400 text-sm italic">Not Linked</span>
                                }
                            </p>
                        </div>
                        <div>
                            <label className="text-xs uppercase text-slate-500 font-bold">Account Role</label>
                            <p className="capitalize text-slate-800 text-lg">{user.role}</p>
                        </div>
                    </div>
                </div>

                {/* Storage Stats */}
                <div className="grid grid-cols-2 gap-6">
                    <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
                        <div className="flex items-center gap-3 mb-2">
                            <div className="p-2 bg-blue-50 text-blue-600 rounded-lg">
                                <FaHdd />
                            </div>
                            <span className="font-semibold text-slate-700">Storage Used</span>
                        </div>
                        <h2 className="text-3xl font-bold text-slate-900">{formatSize(stats.usedStorage)}</h2>
                        <div className="w-full bg-slate-100 rounded-full h-2 mt-4">
                            <div
                                className="bg-blue-600 h-2 rounded-full transition-all duration-500"
                                style={{ width: `${usedPercent}%` }}
                            ></div>
                        </div>
                        <p className="text-xs text-slate-400 mt-2 text-right">
                            of {formatSize(stats.totalStorage)} used
                        </p>
                    </div>

                    <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
                        <div className="flex items-center gap-3 mb-2">
                            <div className="p-2 bg-purple-50 text-purple-600 rounded-lg">
                                <FaFileAlt />
                            </div>
                            <span className="font-semibold text-slate-700">Total Documents</span>
                        </div>
                        <h2 className="text-3xl font-bold text-slate-900">{stats.totalFiles}</h2>
                        <p className="text-sm text-slate-500 mt-1">Encrypted & Secured</p>
                    </div>
                </div>

                <div className="mt-12 border-t border-red-200 pt-6">
                    <h3 className="text-red-800 font-bold mb-2">Danger Zone</h3>
                    <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center justify-between">
                        <div>
                            <p className="text-red-900 font-medium">Delete Account</p>
                            <p className="text-red-700 text-sm">
                                Permanently remove your account and all {stats.totalFiles} documents.
                            </p>
                        </div>
                        <button
                            onClick={handleDeleteAccount}
                            className="bg-white border border-red-300 text-red-600 hover:bg-red-600 hover:text-white px-4 py-2 rounded-md transition font-medium text-sm"
                        >
                            Delete Forever
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Profile;