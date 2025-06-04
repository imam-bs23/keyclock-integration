import { useCallback, useEffect, useState } from "react";
import { getUserProfile, refreshToken } from "../services/authService";
import AuthContext from "./AuthContextInstance";

// Auth provider component
export const AuthProvider = ({ children }) => {
  const [initialized, setInitialized] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [userProfile, setUserProfile] = useState(null);

  // Function to update auth state
  const updateAuthState = useCallback(async (showLoading = true) => {
    if (showLoading) setLoading(true);
    setError(null);

    try {
      console.log(
        "Checking authentication state by attempting to fetch user profile..."
      );
      await getUserProfile(); // If this succeeds, token is valid
      console.log(
        "User profile successfully fetched, considering user authenticated."
      );
      setAuthenticated(true);
      return true;
    } catch (error) {
      console.error("Failed to update auth state:", error);
      setError("Authentication check failed");
      setAuthenticated(false);
      return false;
    } finally {
      if (showLoading) setLoading(false);
    }
  }, []);

  // Function to fetch user profile
  const fetchUserProfile = useCallback(async (showLoading = true) => {
    if (showLoading) setLoading(true);
    setError(null);

    try {
      console.log("Fetching user profile from AuthContext...");
      const profile = await getUserProfile();
      console.log("User profile received in AuthContext:", profile);
      setUserProfile(profile);
      setAuthenticated(true); // Also set authenticated here
      return profile;
    } catch (error) {
      console.error("Failed to fetch user profile:", error);
      setError(error.error_description || "Failed to fetch user profile");

      // If unauthorized, update authentication state
      if (error.error === "unauthorized") {
        console.log("Unauthorized error, clearing authentication state");
        setAuthenticated(false);
        setUserProfile(null);
      }

      return null;
    } finally {
      if (showLoading) setLoading(false);
    }
  }, []);

  // Initialize authentication on component mount
  useEffect(() => {
    const initAuth = async () => {
      try {
        // Check authentication status with the backend
        const isAuthenticated = await updateAuthState(false);

        // If authenticated, fetch user profile
        if (isAuthenticated) {
          await fetchUserProfile(false);
        }

        setInitialized(true);
      } catch (error) {
        console.error("Failed to initialize authentication:", error);
        setError("Failed to initialize authentication");
      } finally {
        setLoading(false);
      }
    };

    initAuth();

    // Set up periodic token refresh if needed
    // This helps maintain the session without requiring user to re-login
    const refreshInterval = setInterval(() => {
      if (authenticated) {
        // Try to refresh the token silently
        refreshToken().catch((err) => {
          console.warn("Token refresh failed:", err);
          // If refresh fails, we'll check auth state on next interval
          // No need to show errors to user for background refresh
        });
      }
    }, 5 * 60 * 1000); // Check every 5 minutes

    return () => clearInterval(refreshInterval);
  }, []);

  // Context value
  const value = {
    initialized,
    authenticated,
    loading,
    error,
    userProfile,
    updateAuthState,
    fetchUserProfile,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export default AuthProvider;
