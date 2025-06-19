import React, { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import "./Profile.css";

const Profile = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const hasCheckedAuth = useRef(false);
  const [userInfo, setUserInfo] = useState({
    username: "",
    email: "",
    accessToken: "",
    isAuthenticated: false,
    isLoading: true,
  });

  const exchangeCodeForToken = useCallback(
    async (code, codeVerifier) => {
      const tokenUrl = `/keycloak/realms/${process.env.REACT_APP_KEYCLOAK_REALM}/protocol/openid-connect/token`;
      console.log("Using token URL:", tokenUrl);

      const params = new URLSearchParams();
      params.append("grant_type", "authorization_code");
      params.append("client_id", process.env.REACT_APP_KEYCLOAK_CLIENT_ID);
      params.append("code", code);
      params.append("redirect_uri", window.location.origin + "/profile");
      params.append("code_verifier", codeVerifier);

      try {
        console.log("Initiating token exchange...");
        const response = await fetch(tokenUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: params.toString(),
          credentials: "include", // Important for session cookies
        });

        if (!response.ok) {
          const errorData = await response.text();
          console.error("Token exchange failed:", errorData);
          throw new Error("Token exchange failed");
        }

        const tokens = await response.json();
        console.log("Successfully obtained tokens");

        // Store tokens immediately
        localStorage.setItem("accessToken", tokens.access_token);
        if (tokens.refresh_token) {
          localStorage.setItem("refreshToken", tokens.refresh_token);
        }

        // Get user info with the new token
        const userInfoResponse = await fetch(
          `/keycloak/realms/${process.env.REACT_APP_KEYCLOAK_REALM}/protocol/openid-connect/userinfo`,
          {
            headers: {
              Authorization: `Bearer ${tokens.access_token}`,
            },
            credentials: "include", // Important for session cookies
          }
        );

        if (!userInfoResponse.ok) {
          throw new Error("Failed to fetch user info");
        }

        const userInfo = await userInfoResponse.json();

        setUserInfo({
          username: userInfo.preferred_username || "",
          email: userInfo.email || "",
          accessToken: tokens.access_token,
          isAuthenticated: true,
          isLoading: false,
        });

        // Clean up URL
        window.history.replaceState(
          {},
          document.title,
          window.location.pathname
        );
      } catch (error) {
        console.error("Authentication error:", error);
        // Clear any potentially invalid tokens
        localStorage.removeItem("accessToken");
        localStorage.removeItem("refreshToken");
        setUserInfo((prev) => ({ ...prev, isLoading: false }));
        navigate("/");
      }
    },
    [navigate]
  );

  useEffect(() => {
    if (hasCheckedAuth.current) return;

    const checkAuth = async () => {
      hasCheckedAuth.current = true;
      console.log("Running auth check...");

      const code = searchParams.get("code");
      const state = searchParams.get("state");
      const error = searchParams.get("error");
      const storedState = localStorage.getItem("oauth_state");
      const storedCodeVerifier = localStorage.getItem("code_verifier");

      if (error) {
        console.error("Authentication error:", error);
        localStorage.removeItem("accessToken");
        localStorage.removeItem("refreshToken");
        setUserInfo((prev) => ({ ...prev, isLoading: false }));
        navigate("/");
        return;
      }

      try {
        if (code && state && storedState === state && storedCodeVerifier) {
          console.log("Exchanging code for token...");
          await exchangeCodeForToken(code, storedCodeVerifier);
          // Clean up
          localStorage.removeItem("oauth_state");
          localStorage.removeItem("code_verifier");
        } else if (localStorage.getItem("accessToken")) {
          // Verify the existing token
          console.log("Verifying existing token...");
          const token = localStorage.getItem("accessToken");
          const response = await fetch(
            `/keycloak/realms/${process.env.REACT_APP_KEYCLOAK_REALM}/protocol/openid-connect/userinfo`,
            {
              headers: { Authorization: `Bearer ${token}` },
              credentials: "include",
            }
          );

          if (response.ok) {
            const userInfo = await response.json();
            setUserInfo({
              username: userInfo.preferred_username || "",
              email: userInfo.email || "",
              accessToken: token,
              isAuthenticated: true,
              isLoading: false,
            });
          } else {
            // Token is invalid, clear it and redirect to login
            throw new Error("Invalid token");
          }
        } else {
          throw new Error("No valid session");
        }
      } catch (error) {
        console.error("Session check failed:", error);
        localStorage.removeItem("accessToken");
        localStorage.removeItem("refreshToken");
        setUserInfo((prev) => ({ ...prev, isLoading: false }));
        navigate("/");
      }
    };

    checkAuth();

    // return () => {
    //   hasCheckedAuth.current = false;
    // };
  }, [navigate, searchParams, exchangeCodeForToken]);

  const handleLogout = async () => {
    try {
      const refreshToken = localStorage.getItem("refreshToken");
      if (refreshToken) {
        // Revoke the refresh token
        await fetch(
          `/keycloak/realms/${process.env.REACT_APP_KEYCLOAK_REALM}/protocol/openid-connect/revoke`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              client_id: process.env.REACT_APP_KEYCLOAK_CLIENT_ID,
              refresh_token: refreshToken,
            }).toString(),
          }
        );
      }
    } catch (error) {
      console.error("Error during logout:", error);
    } finally {
      // Clear all auth data
      localStorage.removeItem("accessToken");
      localStorage.removeItem("refreshToken");
      localStorage.removeItem("oauth_state");
      localStorage.removeItem("code_verifier");

      // Redirect to Keycloak logout
      const logoutUrl = `${process.env.REACT_APP_KEYCLOAK_URL}/realms/${process.env.REACT_APP_KEYCLOAK_REALM}/protocol/openid-connect/logout`;
      const redirectUri = encodeURIComponent(window.location.origin);
      window.location.href = `${logoutUrl}?post_logout_redirect_uri=${redirectUri}`;
    }
  };

  if (userInfo.isLoading) {
    return (
      <div className="profile-container">
        <h1>Loading...</h1>
      </div>
    );
  }

  return (
    <div className="profile-container">
      <h1>Welcome to Website X</h1>
      {userInfo.isAuthenticated ? (
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
      ) : (
        <div>Not authenticated</div>
      )}
    </div>
  );
};

export default Profile;
