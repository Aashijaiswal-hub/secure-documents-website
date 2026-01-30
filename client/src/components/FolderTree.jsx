import { useState } from 'react';
import { HiOutlineChevronRight, HiOutlineChevronDown, HiOutlineFolderOpen  } from "react-icons/hi2";
import { IoFolderOutline } from "react-icons/io5";
import { cn } from "@/lib/utils"; 


const TreeNode = ({ folder, allFolders, selectedId, onSelect, level = 0 }) => {
    const [isOpen, setIsOpen] = useState(false);
    
    const children = allFolders.filter(f => f.parent === folder._id);
    const hasChildren = children.length > 0;
    const isSelected = selectedId === folder._id;

    return (
        <div>
            <div 
                className={cn(
                    "flex items-center gap-2 py-1.5 px-2 rounded-md cursor-pointer transition select-none text-sm",
                    isSelected ? "bg-blue-100 text-blue-700 font-medium" : "hover:bg-slate-100 text-slate-700",
                )}
                style={{ paddingLeft: `${level * 16 + 8}px` }} // Indentation
                onClick={() => onSelect(folder._id)}
            >
                <div 
                    className="p-1 rounded-sm hover:bg-slate-200 text-slate-400"
                    onClick={(e) => {
                        e.stopPropagation();
                        setIsOpen(!isOpen);
                    }}
                >
                    {hasChildren ? (
                        isOpen ? <HiOutlineChevronDown className="h-3 w-3" /> : <HiOutlineChevronRight className="h-3 w-3" />
                    ) : (
                        <span className="w-3 h-3 block" /> // Spacer
                    )}
                </div>

                {isOpen ? (
                    <HiOutlineFolderOpen  className={cn("h-4 w-4", isSelected ? "text-blue-600" : "text-blue-400")} />
                ) : (
                    <IoFolderOutline className={cn("h-4 w-4", isSelected ? "text-blue-600" : "text-blue-400")} />
                )}

                <span>{folder.name}</span>
            </div>

            {isOpen && children.map(child => (
                <TreeNode 
                    key={child._id} 
                    folder={child} 
                    allFolders={allFolders} 
                    selectedId={selectedId}
                    onSelect={onSelect}
                    level={level + 1}
                />
            ))}
        </div>
    );
};


const FolderTree = ({ folders, selectedId, onSelect }) => {
    const rootFolders = folders.filter(f => f.parent === null);

    return (
        <div className="border border-slate-200 rounded-md p-2 h-64 overflow-y-auto bg-slate-50">
            <div 
                className={cn(
                    "flex items-center gap-2 py-1.5 px-2 rounded-md cursor-pointer transition select-none text-sm pl-8 mb-1",
                    selectedId === 'root' ? "bg-blue-100 text-blue-700 font-medium" : "hover:bg-slate-100 text-slate-700",
                )}
                onClick={() => onSelect('root')}
            >
                <IoFolderOutline className="h-4 w-4 text-slate-500" />
                <span>Home (Root)</span>
            </div>

            {rootFolders.map(folder => (
                <TreeNode 
                    key={folder._id} 
                    folder={folder} 
                    allFolders={folders} 
                    selectedId={selectedId}
                    onSelect={onSelect}
                />
            ))}
        </div>
    );
};

export default FolderTree;