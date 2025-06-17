import React from "react";
import "./Login.css";

const Login = () => {
  const loginWithKUP = async () => {
    // Generate a random state
    const state = Math.random().toString(36).substring(2);
    sessionStorage.setItem("oauth_state", state);

    // Redirect to the backend's authorize endpoint
    const params = new URLSearchParams({
      client_id: "testclient",
      response_type: "code",
      scope: "openid email profile",
      state: state,
      // Let the backend handle PKCE
    });
    window.location.href = `http://0.0.0.0:3001/auth/authorize?${params.toString()}`;
  };

  return (
    <div className="login-container">
      <h1>Welcome to Website X</h1>
      <button onClick={loginWithKUP} className="login-button">
        Login with ONEID
      </button>
    </div>
  );
};

export default Login;
