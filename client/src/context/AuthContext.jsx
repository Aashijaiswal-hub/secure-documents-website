import { createContext, useState, useEffect } from 'react';
import api from '../utils/api';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const loadUser = async () => {
            const token = localStorage.getItem('token');
            if (!token) {
                setLoading(false);
                return;
            }
            try {
                const { data } = await api.get('/auth/me');
                const fullUser = data.user ? data.user : data;
                setUser(fullUser);
            } catch (error) {
                console.error("Auth Load Error:", error);
                localStorage.removeItem('token');
            } finally {
                setLoading(false);
            }
        };

        loadUser();
    }, []);

    const login = (token, userData) => {
        localStorage.setItem('token', token);
        if (userData) {
            setUser(userData);
        } else {
            window.location.reload();
        }
    };

    const register = async (userData) => {
        const { data } = await api.post('/auth/register', userData);
        setUser(data.user);
        localStorage.setItem('userInfo', JSON.stringify(data.user));
    };

    const logout = () => {
        localStorage.removeItem('token');
        setUser(null);
        window.location.href = '/login';
    };
    return (
        <AuthContext.Provider value={{ user, setUser, login, register, logout, loading }}>
            {children}
        </AuthContext.Provider>
    );
};