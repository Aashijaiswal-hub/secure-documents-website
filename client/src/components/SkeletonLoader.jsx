import { IoFolderOutline } from "react-icons/io5";

const SkeletonLoader = ({ mode }) => {
    if (mode === 'grid') {
        return (
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-6 mb-10">
                {[...Array(5)].map((_, i) => (
                    <div key={i} className="animate-pulse p-5 border border-slate-100 rounded-xl flex flex-col items-center justify-center aspect-square bg-slate-50">
                        <div className="h-12 w-12 bg-slate-200 rounded-lg mb-3"></div>
                        <div className="h-4 w-20 bg-slate-200 rounded"></div>
                    </div>
                ))}
            </div>
        );
    }

    // Table Mode
    return (
        <div className="w-full bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
            <div className="p-4 border-b border-slate-100 bg-slate-50 flex gap-4">
                 <div className="h-4 w-4 bg-slate-200 rounded"></div>
                 <div className="h-4 w-32 bg-slate-200 rounded"></div>
            </div>
            {[...Array(5)].map((_, i) => (
                <div key={i} className="p-4 border-b border-slate-50 flex items-center gap-4 animate-pulse">
                    <div className="h-4 w-4 bg-slate-200 rounded"></div>
                    <div className="h-8 w-8 bg-slate-200 rounded"></div>
                    <div className="h-4 w-48 bg-slate-200 rounded flex-1"></div>
                    <div className="h-4 w-24 bg-slate-200 rounded hidden md:block"></div>
                    <div className="h-4 w-24 bg-slate-200 rounded hidden md:block"></div>
                </div>
            ))}
        </div>
    );
};

export default SkeletonLoader;