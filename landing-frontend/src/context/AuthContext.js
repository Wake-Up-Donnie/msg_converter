import React, { createContext, useState, useContext, useEffect } from 'react';
import axios from 'axios';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState(localStorage.getItem('token'));

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

  // Set up axios interceptor for auth token
  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
      delete axios.defaults.headers.common['Authorization'];
    }
  }, [token]);

  // Verify token on mount
  useEffect(() => {
    const verifyToken = async () => {
      if (token) {
        try {
          const response = await axios.get(`${API_URL}/api/auth/verify`);
          setUser(response.data.user);
        } catch (error) {
          console.error('Token verification failed:', error);
          localStorage.removeItem('token');
          setToken(null);
        }
      }
      setLoading(false);
    };

    verifyToken();
  }, [token, API_URL]);

  const register = async (email, password) => {
    try {
      const response = await axios.post(`${API_URL}/api/auth/register`, {
        email,
        password
      });
      const { token: newToken, user: newUser } = response.data;
      localStorage.setItem('token', newToken);
      setToken(newToken);
      setUser(newUser);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.error || 'Registration failed'
      };
    }
  };

  const login = async (email, password) => {
    try {
      const response = await axios.post(`${API_URL}/api/auth/login`, {
        email,
        password
      });
      const { token: newToken, user: newUser } = response.data;
      localStorage.setItem('token', newToken);
      setToken(newToken);
      setUser(newUser);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.error || 'Login failed'
      };
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  };

  const refreshUser = async () => {
    if (token) {
      try {
        const response = await axios.get(`${API_URL}/api/auth/verify`);
        setUser(response.data.user);
      } catch (error) {
        console.error('User refresh failed:', error);
      }
    }
  };

  const getUsage = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/auth/usage`);
      return response.data;
    } catch (error) {
      console.error('Usage fetch failed:', error);
      return null;
    }
  };

  const createCheckoutSession = async (planType) => {
    try {
      const response = await axios.post(`${API_URL}/api/stripe/create-checkout-session`, {
        planType
      });
      return response.data;
    } catch (error) {
      console.error('Checkout session creation failed:', error);
      throw error;
    }
  };

  const createPortalSession = async () => {
    try {
      const response = await axios.post(`${API_URL}/api/stripe/create-portal-session`);
      return response.data;
    } catch (error) {
      console.error('Portal session creation failed:', error);
      throw error;
    }
  };

  const value = {
    user,
    loading,
    token,
    register,
    login,
    logout,
    refreshUser,
    getUsage,
    createCheckoutSession,
    createPortalSession,
    API_URL
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
