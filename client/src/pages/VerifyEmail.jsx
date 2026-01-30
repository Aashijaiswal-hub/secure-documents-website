import { useEffect, useState, useContext, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../utils/api';
import { AuthContext } from '../context/AuthContext';
import { LiaCheckCircle } from "react-icons/lia";
import { PiXCircle } from "react-icons/pi";
import { BiLoader } from "react-icons/bi";

const VerifyEmail = () => {
    const { token } = useParams();
    const navigate = useNavigate();
    const { setUser } = useContext(AuthContext);
    const [status, setStatus] = useState('verifying');

    const verificationAttempted = useRef(false);

    useEffect(() => {
        if (verificationAttempted.current) return;
        verificationAttempted.current = true;

        const verify = async () => {
            try {
                const { data } = await api.put(`/auth/verifyemail/${token}`);
                if (data.user) {
                    setUser(data.user);
                    localStorage.setItem('userInfo', JSON.stringify(data.user));
                }

                setStatus('success');
                setTimeout(() => navigate('/dashboard'), 3000);
            } catch (error) {
                console.error("Verification error:", error);
                setStatus('error');
            }
        };
        verify();
    }, [token, navigate, setUser]);

    return (
        <div className="min-h-screen flex items-center justify-center bg-slate-50">
            <div className="bg-white p-8 rounded-xl shadow-lg max-w-md text-center w-full">
                {status === 'verifying' && (
                    <div className="flex flex-col items-center">
                        <BiLoader className="h-10 w-10 text-blue-600 animate-spin mb-4" />
                        <h2 className="text-xl font-semibold">Verifying Identity...</h2>
                    </div>
                )}

                {status === 'success' && (
                    <div className="flex flex-col items-center">
                        <LiaCheckCircle className="h-12 w-12 text-green-500 mb-4" />
                        <h2 className="text-xl font-bold text-slate-900">Verification Successful!</h2>
                        <p className="text-slate-600 mt-2">Redirecting to dashboard...</p>
                    </div>
                )}

                {status === 'error' && (
                    <div className="flex flex-col items-center">
                        <PiXCircle className="h-12 w-12 text-red-500 mb-4" />
                        <h2 className="text-xl font-bold text-slate-900">Verification Failed</h2>
                        <p className="text-slate-600 mt-2">The link is invalid or expired.</p>
                        <button
                            onClick={() => navigate('/login')}
                            className="mt-6 px-4 py-2 bg-slate-900 text-white rounded-md"
                        >
                            Back to Login
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default VerifyEmail;