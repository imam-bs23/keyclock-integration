import React from "react";
import "./Login.css";

// Helper function to generate a secure random string
const generateRandomString = (length) => {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
    ""
  );
};

// Function to generate code challenge from verifier
const generateCodeChallenge = async (codeVerifier) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await window.crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

const Login = () => {
  const loginWithKUP = async () => {
    // Generate code verifier and state
    const codeVerifier = generateRandomString(64);
    const state = generateRandomString(16);

    // Store code verifier and state in localStorage
    localStorage.setItem("code_verifier", codeVerifier);
    localStorage.setItem("oauth_state", state);

    // Generate code challenge
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Build authorization URL
    const params = new URLSearchParams({
      client_id: process.env.REACT_APP_KEYCLOAK_CLIENT_ID, // Your client ID
      response_type: "code", // Authorization code flow
      scope: "openid email profile",
      redirect_uri: window.location.origin + "/profile",
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });

    // Use full Keycloak URL for the authorization endpoint
    const keycloakUrl = process.env.REACT_APP_KEYCLOAK_URL;
    const realm = process.env.REACT_APP_KEYCLOAK_REALM;
    const authUrl = `${keycloakUrl}/realms/${realm}/protocol/openid-connect/auth`;
    console.log("Redirecting to:", authUrl);
    window.location.href = `${authUrl}?${params.toString()}`;
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
