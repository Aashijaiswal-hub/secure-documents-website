import { useState, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';

const Register = () => {
    const [formData, setFormData] = useState({ fullName: '', email: '', password: '', aadhaarId: '' });
    const [error, setError] = useState('');
    const { register } = useContext(AuthContext);
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            await register(formData);
            navigate('/email-sent');
        } catch (err) {
            setError(err.response?.data?.message || err.response?.data?.errors?.[0]?.msg || 'Registration failed');
        }
    };

    return (
        <div className="flex min-h-screen items-center justify-center bg-slate-50">
            <div className="w-full max-w-md space-y-8 p-8 bg-white rounded-xl shadow-lg border border-slate-200">
                <div className="text-center">
                    <h2 className="text-3xl font-bold text-slate-900">Identity Registration</h2>
                    <p className="mt-2 text-sm text-slate-600">Create a secure government account</p>
                </div>

                {error && (
                    <div className="p-3 bg-red-100 border border-red-400 text-red-700 rounded text-sm">
                        {error}
                    </div>
                )}

                <form className="mt-8 space-y-4" onSubmit={handleSubmit}>
                    <input
                        type="text"
                        placeholder="Full Name"
                        className="w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-slate-500 bg-slate-50"
                        onChange={(e) => setFormData({...formData, fullName: e.target.value})}
                    />
                    <input
                        type="email"
                        placeholder="Email Address"
                        className="w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-slate-500 bg-slate-50"
                        onChange={(e) => setFormData({...formData, email: e.target.value})}
                    />
                    <input
                        type="text"
                        placeholder="Aadhaar Number (12 Digits)"
                        className="w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-slate-500 bg-slate-50"
                        onChange={(e) => setFormData({...formData, aadhaarId: e.target.value})}
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        className="w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-slate-500 bg-slate-50"
                        onChange={(e) => setFormData({...formData, password: e.target.value})}
                    />

                    <button
                        type="submit"
                        className="w-full py-2 px-4 bg-slate-900 hover:bg-slate-800 text-white font-medium rounded-md transition duration-150"
                    >
                        Verify & Register
                    </button>
                </form>
                
                <div className="text-center text-sm">
                    <Link to="/login" className="font-medium text-blue-600 hover:text-blue-500">
                        Already have an account? Login
                    </Link>
                </div>
            </div>
        </div>
    );
};

export default Register;