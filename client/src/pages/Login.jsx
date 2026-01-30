import { useState, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import api from '../utils/api';
import { GoogleLogin } from '@react-oauth/google';

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');

    const [resendStatus, setResendStatus] = useState('');
    const [loadingResend, setLoadingResend] = useState(false);

    const { login } = useContext(AuthContext);
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const { data } = await api.post('/auth/login', { email, password });
            login(data.token, data.user);
            navigate('/dashboard');
        } catch (err) {
            setError(err.response?.data?.message || 'Login failed');
        }
    };

    const handleGoogleSuccess = async (credentialResponse) => {
        try {
            const { data } = await api.post('/auth/google', {
                token: credentialResponse.credential
            });
            
            if (data.token) {
                login(data.token, data.user);
                navigate('/dashboard');
            } else {
                setResendStatus(data.message || 'Verification email sent. Please check your inbox.');
                setError('');
            }
        } catch (error) {
            console.error("Google Login Error:", error);
            setError(error.response?.data?.message || 'Google Login failed');
        }
    };

    const handleResendLink = async () => {
        if (!email) return alert("Please enter your email first");

        try {
            setLoadingResend(true);
            await api.post('/auth/resend-verification', { email });
            setResendStatus('New verification link sent! Check your inbox.');
            setError('');
        } catch (err) {
            alert(err.response?.data?.message || "Failed to resend link");
        } finally {
            setLoadingResend(false);
        }
    };

    return (
        <div className="flex min-h-screen items-center justify-center bg-slate-50">
            <div className="w-full max-w-md space-y-8 p-8 bg-white rounded-xl shadow-lg border border-slate-200">
                <div className="text-center">
                    <h2 className="text-3xl font-bold text-slate-900">Secure Vault</h2>
                    <p className="mt-2 text-sm text-slate-600">Enter your credentials to access the archive</p>
                </div>

                {error && (
                    <div className="p-3 bg-red-100 border border-red-400 text-red-700 rounded text-sm flex flex-col gap-2">
                        <span>{error}</span>
                        {error.includes('verified') && (
                            <button
                                onClick={handleResendLink}
                                disabled={loadingResend}
                                className="text-xs font-bold underline text-red-800 hover:text-red-900 text-left"
                            >
                                {loadingResend ? "Sending..." : "Click here to resend verification link"}
                            </button>
                        )}
                    </div>
                )}

                {resendStatus && (
                    <div className="p-3 bg-green-100 border border-green-400 text-green-700 rounded text-sm">
                        {resendStatus}
                    </div>
                )}

                <div className="flex justify-center w-full my-4">
                    <GoogleLogin
                        onSuccess={handleGoogleSuccess}
                        onError={() => setError('Google Login Failed')}
                        theme="filled_blue"
                        shape="pill"
                        text="signin_with"
                        width="300"
                    />
                </div>

                <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                        <span className="w-full border-t border-slate-300" />
                    </div>
                    <div className="relative flex justify-center text-xs uppercase">
                        <span className="bg-white px-2 text-slate-500">Or continue with</span>
                    </div>
                </div>
                {/* --------------------------- */}

                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    <div className="space-y-4">
                        <div>
                            <label className="text-sm font-medium text-slate-700">Email Address</label>
                            <input
                                type="email"
                                required
                                className="w-full px-3 py-2 mt-1 border rounded-md focus:outline-none focus:ring-2 focus:ring-slate-500 bg-slate-50"
                                placeholder="official@gov.in"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                            />
                        </div>
                        <div>
                            <label className="text-sm font-medium text-slate-700">Password</label>
                            <Link to="/forgot-password" className="text-xs font-medium text-blue-600 hover:text-blue-500">
                                Forgot password?
                            </Link>
                            <input
                                type="password"
                                required
                                className="w-full px-3 py-2 mt-1 border rounded-md focus:outline-none focus:ring-2 focus:ring-slate-500 bg-slate-50"
                                placeholder="••••••••"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        className="w-full py-2 px-4 bg-slate-900 hover:bg-slate-800 text-white font-medium rounded-md transition duration-150"
                    >
                        Sign In
                    </button>
                </form>

                <div className="text-center text-sm">
                    <span className="text-slate-600">New User? </span>
                    <Link to="/register" className="font-medium text-blue-600 hover:text-blue-500">
                        Register Identity
                    </Link>
                </div>
            </div>
        </div>
    );
};

export default Login;