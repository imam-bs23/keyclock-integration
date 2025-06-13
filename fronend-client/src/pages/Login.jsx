import React from "react";
import "./Login.css";

const Login = () => {
  const loginWithKUP = () => {
    const KUP_AUTH_URL = "http://localhost:3001/login";
    const CLIENT_ID = "myclient";
    const CLIENT_SECRET = "2SseUT2bMZe5ArTVYDiKmYWUEKsIcPoQ";
    const REDIRECT_URI = `${window.location.origin}/profile`;

    const url = `${KUP_AUTH_URL}?client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&redirect_uri=${encodeURIComponent(
      REDIRECT_URI
    )}`;
    window.location.href = url;
  };

  return (
    <div className="login-container">
      <h1>Welcome to Website X</h1>
      <button onClick={loginWithKUP} className="login-button">
        Login with KUP
      </button>
    </div>
  );
};

export default Login;
