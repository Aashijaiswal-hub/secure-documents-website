import { useNavigate } from 'react-router-dom';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger
} from "@/components/ui/dropdown-menu";
import { FaUserTie } from "react-icons/fa";
import { LuHistory } from "react-icons/lu";
import { HiOutlineLogout } from "react-icons/hi";


const ProfileMenu = ({ user, onLogout, onOpenLogs }) => {
    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <button className="relative h-10 w-10 rounded-full overflow-hidden border border-slate-200 hover:ring-2 hover:ring-slate-400 transition focus:outline-none bg-slate-100">
                    {user?.avatar ? (
                        <img
                            src={user.avatar}
                            alt={user.fullName}
                            className="h-full w-full object-cover"
                            referrerPolicy="no-referrer"
                        />
                    ) : (
                        <div className="h-full w-full bg-slate-900 flex items-center justify-center text-white font-medium">
                            {user?.fullName?.charAt(0).toUpperCase() || 'U'}
                        </div>
                    )}
                </button>
            </DropdownMenuTrigger>

            <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel>
                    <div className="flex flex-col space-y-1">
                        <p className="text-sm font-medium leading-none">{user?.fullName}</p>
                        <p className="text-xs leading-none text-muted-foreground text-slate-500">
                            {user?.email}
                        </p>
                    </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />

                <DropdownMenuItem onClick={() => window.location.href = '/profile'} className="cursor-pointer">
                    <FaUserTie className="mr-2 h-4 w-4" />
                    <span>Profile Settings</span>
                </DropdownMenuItem>

                {onOpenLogs && (
                    <DropdownMenuItem onClick={onOpenLogs} className="cursor-pointer">
                        <LuHistory className="mr-2 h-4 w-4" />
                        <span>Audit Logs</span>
                    </DropdownMenuItem>
                )}

                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={onLogout} className="cursor-pointer text-red-600 focus:text-red-600">
                    <HiOutlineLogout className="mr-2 h-4 w-4" />
                    <span>Log out</span>
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    );
};

export default ProfileMenu;