import { HiOutlineMail } from "react-icons/hi";
import { Link } from 'react-router-dom';

const EmailSent = () => {
    return (
        <div className="min-h-screen flex items-center justify-center bg-slate-50">
            <div className="bg-white p-8 rounded-xl shadow-lg max-w-md text-center border border-slate-200">
                <div className="mx-auto w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                    <HiOutlineMail className="h-6 w-6 text-blue-600" />
                </div>
                <h2 className="text-2xl font-bold text-slate-900 mb-2">Check your Inbox</h2>
                <p className="text-slate-600 mb-6">
                    We've sent a verification link to your email address. Please click it to activate your account.
                </p>
                <Link to="/login" className="text-blue-600 hover:underline font-medium">
                    Back to Login
                </Link>
            </div>
        </div>
    );
};

export default EmailSent;