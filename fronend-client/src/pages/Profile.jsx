import React, { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import "./Profile.css";

const Profile = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [userInfo, setUserInfo] = useState({
    username: "",
    email: "",
    accessToken: "",
  });

  useEffect(() => {
    const accessToken = searchParams.get("access_token");
    const username = searchParams.get("username");
    const email = searchParams.get("email");

    console.log("Access Token:", accessToken);
    console.log("Username:", username);
    console.log("Email:", email);

    if (accessToken && username && email) {
      setUserInfo({ username, email, accessToken });
      localStorage.setItem("accessToken", accessToken);
    } else {
      // Only redirect if we don't have a stored token
      const storedToken = localStorage.getItem("accessToken");
      if (!storedToken) {
        navigate("/");
      }
    }
  }, [searchParams, navigate]);

  const handleLogout = () => {
    // Clear user data and redirect to login
    localStorage.removeItem("accessToken");
    navigate("/");
  };

  return (
    <div className="profile-container">
      <h1>Welcome to Website X</h1>
      <div className="user-info">
        <h3>Logged in!</h3>
        <p>
          <strong>Username:</strong> {userInfo.username}
        </p>
        <p>
          <strong>Email:</strong> {userInfo.email}
        </p>
        <button onClick={handleLogout} className="logout-button">
          Logout
        </button>
      </div>
    </div>
  );
};

export default Profile;
