import { useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../utils/api';
import { toast } from "sonner";
import { GoShieldLock } from "react-icons/go";

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            await api.post('/auth/forgotpassword', { email });
            toast.success('Reset link sent! Check your email.');
        } catch (error) {
            toast.error(error.response?.data?.message || 'Request failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
            <div className="max-w-md w-full bg-white rounded-xl shadow-lg border border-slate-200 p-8">
                <div className="flex justify-center mb-6">
                    <GoShieldLock className="h-12 w-12 text-blue-900" />
                </div>
                <h2 className="text-2xl font-bold text-center text-slate-900 mb-2">Forgot Password?</h2>
                <p className="text-center text-slate-500 mb-8 text-sm">
                    Enter your email address and we'll send you a link to reset your password.
                </p>

                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">Email Address</label>
                        <input
                            type="email"
                            required
                            className="w-full px-4 py-2 border border-slate-300 rounded-md focus:ring-2 focus:ring-blue-500 outline-none"
                            placeholder="you@example.com"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                        />
                    </div>
                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full bg-blue-900 text-white py-2 rounded-md hover:bg-blue-800 transition font-medium disabled:opacity-50"
                    >
                        {loading ? 'Sending...' : 'Send Reset Link'}
                    </button>
                </form>

                <div className="mt-6 text-center">
                    <Link to="/login" className="text-sm text-slate-600 hover:text-blue-600 font-medium">
                        ← Back to Login
                    </Link>
                </div>
            </div>
        </div>
    );
};

export default ForgotPassword;