import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import './Profile.css';

const Profile = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [userInfo, setUserInfo] = useState({
    username: '',
    email: '',
    accessToken: ''
  });

  useEffect(() => {
    const accessToken = searchParams.get('access_token');
    const username = searchParams.get('username');
    const email = searchParams.get('email');

    if (accessToken && username && email) {
      setUserInfo({ username, email, accessToken });
      // Store the token in localStorage for future use
      localStorage.setItem('accessToken', accessToken);
    } else {
      // Redirect to login if no user info is found
      navigate('/');
    }
  }, [searchParams, navigate]);

  const handleLogout = () => {
    // Clear user data and redirect to login
    localStorage.removeItem('accessToken');
    navigate('/');
  };

  return (
    <div className="profile-container">
      <h1>Welcome to Website X</h1>
      <div className="user-info">
        <h3>Logged in!</h3>
        <p><strong>Username:</strong> {userInfo.username}</p>
        <p><strong>Email:</strong> {userInfo.email}</p>
        <p className="token-display">
          <strong>Access Token:</strong> 
          <span className="token">{userInfo.accessToken}</span>
        </p>
        <button onClick={handleLogout} className="logout-button">
          Logout
        </button>
      </div>
    </div>
  );
};

export default Profile;
