import axios from "axios";

// Auth service configuration
const API_URL = "http://localhost:3001/api/auth";

// Attempt to load token from localStorage to persist session
// The in-memory authToken is used by the interceptor.
// localStorage is the source of truth on app load.
let authToken = localStorage.getItem("access_token");

// Create axios instance with interceptors for better error handling
const api = axios.create({
  baseURL: API_URL,
  withCredentials: true,
});

// Add request interceptor for authentication and logging
api.interceptors.request.use(
  (config) => {
    console.debug(`Auth request: ${config.method.toUpperCase()} ${config.url}`);

    // Add authorization header if we have a token
    if (authToken) {
      // Handle both token formats (object with access_token or direct string token)
      const tokenValue = authToken.access_token || authToken;
      console.log("Adding auth token to request:", config.url);
      config.headers.Authorization = `Bearer ${tokenValue}`;
    } else {
      console.log("No auth token available for request:", config.url);
    }

    return config;
  },
  (error) => {
    console.error("Auth request error:", error);
    return Promise.reject(error);
  }
);

// Add response interceptor for logging and error handling
api.interceptors.response.use(
  (response) => {
    console.debug(
      `Auth response: ${response.status} from ${response.config.url}`
    );
    return response;
  },
  (error) => {
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.error(
        `Auth error ${error.response.status}: ${JSON.stringify(
          error.response.data
        )}`
      );
    } else if (error.request) {
      // The request was made but no response was received
      console.error("Auth error: No response received", error.request);
    } else {
      // Something happened in setting up the request that triggered an Error
      console.error("Auth error:", error.message);
    }
    return Promise.reject(error);
  }
);

// Login with username and password
export const login = async (username, password) => {
  try {
    console.log("Attempting login with username:", username);

    // Try Keycloak login first, then fall back to simple JWT if it fails
    try {
      console.log("Trying Keycloak login...");
      const keycloakResponse = await api.post("/login", { username, password });
      console.log(
        "Keycloak login successful, response:",
        keycloakResponse.data
      );

      // Store tokens in memory and localStorage
      if (keycloakResponse.data && keycloakResponse.data.access_token) {
        console.log("Storing Keycloak tokens");
        authToken = keycloakResponse.data.access_token;

        // Store tokens in localStorage
        localStorage.setItem(
          "access_token",
          keycloakResponse.data.access_token
        );
        if (keycloakResponse.data.refresh_token) {
          localStorage.setItem(
            "refresh_token",
            keycloakResponse.data.refresh_token
          );
        }

        // Store token expiration if available
        if (keycloakResponse.data.expires_in) {
          const expiresAt =
            Date.now() + keycloakResponse.data.expires_in * 1000;
          localStorage.setItem("expires_at", expiresAt.toString());
        }

        // Log the first few characters of the token for debugging
        const tokenPreview = authToken.substring(0, 20) + "...";
        console.log("Access token preview:", tokenPreview);
        if (keycloakResponse.data.refresh_token) {
          console.log("Refresh token stored");
        }

        return keycloakResponse.data;
      }
    } catch (keycloakError) {
      console.log(
        "Keycloak login failed, trying simple JWT:",
        keycloakError.message
      );
      // Fall through to simple JWT login
    }
  } catch (error) {
    // Handle specific error cases
    if (error.response) {
      const status = error.response.status;
      const data = error.response.data;

      if (status === 401) {
        console.error("Login failed: Invalid credentials");
        throw {
          error: "invalid_grant",
          error_description: "Invalid username or password",
        };
      } else if (status === 403) {
        console.error("Login failed: Access forbidden", data);
        throw {
          error: "access_denied",
          error_description:
            "Access denied. Direct grant may not be enabled for this client.",
        };
      } else if (status === 400) {
        console.error("Login failed: Bad request", data);
        throw (
          data || {
            error: "bad_request",
            error_description: "Invalid request parameters",
          }
        );
      } else {
        console.error(`Login failed: Server error (${status})`, data);
        throw (
          data || {
            error: "server_error",
            error_description: `Server error (${status})`,
          }
        );
      }
    } else if (error.request) {
      console.error("Login failed: No response from server");
      throw {
        error: "network_error",
        error_description: "Could not connect to authentication server",
      };
    } else {
      console.error("Login error:", error.message);
      throw {
        error: "unknown_error",
        error_description: error.message || "Authentication failed",
      };
    }
  }
};

// Logout
export const logout = async () => {
  try {
    // Get the refresh token from storage or current session
    const refreshToken = localStorage.getItem("refresh_token");

    // Only attempt to call the logout endpoint if we have a refresh token
    if (refreshToken) {
      try {
        const response = await api.post("/logout", {
          refresh_token: refreshToken,
        });
        console.log(`Logout successful:`, response.data);
      } catch (error) {
        // Log the error but continue with client-side cleanup
        console.error("Logout API error:", error.message);
      }
    }

    // Clear tokens and auth data from memory and storage
    authToken = null;
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("auth_timestamp");

    // Clear any other auth-related data
    sessionStorage.clear();

    // Redirect to home page
    window.location.href = "/";
    return true;
  } catch (error) {
    console.error("Logout error:", error);

    // Even if logout fails, ensure we clean up and redirect
    authToken = null;
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("auth_timestamp");
    window.location.href = "/";
    return false;
  }
};

// Direct user registration with Keycloak
export const registerUser = async (userData) => {
  try {
    // Log user registration attempt without exposing password
    console.log("Registering user:", {
      username: userData.username,
      email: userData.email,
      firstName: userData.firstName,
      lastName: userData.lastName,
    });

    const response = await api.post("/register", userData);
    console.log("Registration successful");
    return response.data;
  } catch (error) {
    if (error.response) {
      const status = error.response.status;
      const data = error.response.data;

      console.error(`Registration error (${status}):`, data);

      // Handle specific error cases
      if (status === 409) {
        // Conflict - username or email already exists
        if (data.error_description?.includes("username")) {
          throw {
            error: "username_exists",
            error_description:
              "Username already exists. Please choose another username.",
          };
        } else if (data.error_description?.includes("email")) {
          throw {
            error: "email_exists",
            error_description:
              "Email already in use. Please use another email address.",
          };
        } else {
          throw (
            data || {
              error: "conflict",
              error_description: "User already exists.",
            }
          );
        }
      } else if (status === 400) {
        // Bad request - validation error
        throw (
          data || {
            error: "validation_error",
            error_description:
              "Invalid registration data. Please check your inputs.",
          }
        );
      } else if (status === 403) {
        // Forbidden - registration not enabled
        throw {
          error: "registration_not_enabled",
          error_description:
            "Registration is not enabled in this Keycloak realm.",
        };
      } else {
        throw (
          data || {
            error: "server_error",
            error_description: `Server error (${status}). Please try again later.`,
          }
        );
      }
    } else if (error.request) {
      console.error("Registration error: No response from server");
      throw {
        error: "network_error",
        error_description:
          "Could not connect to authentication server. Please check your internet connection.",
      };
    } else {
      console.error("Registration error:", error.message);
      throw {
        error: "unknown_error",
        error_description:
          error.message || "Registration failed. Please try again later.",
      };
    }
  }
};

// Get user profile from auth system (tries both Keycloak and Simple JWT)
export const getUserProfile = async () => {
  try {
    console.log("Fetching user profile");
    console.log("Current auth token:", authToken ? "Token exists" : "No token");

    // Make sure we have a token before trying to get the profile
    if (!authToken) {
      console.error("No authentication token available");
      throw new Error("Not authenticated");
    }

    // First try the Keycloak endpoint
    try {
      console.log("Trying Keycloak endpoint /me");
      const response = await api.get("/me");
      console.log(
        "User profile fetched successfully from Keycloak:",
        response.data
      );
      return response.data;
    } catch (keycloakError) {
      console.log(
        "Keycloak profile fetch failed, trying simple JWT endpoint",
        keycloakError
      );
    }
  } catch (error) {
    if (error.response) {
      const status = error.response.status;
      const data = error.response.data;

      console.error(`Get profile error (${status}):`, data);

      if (status === 401) {
        // Token expired or invalid
        authToken = null;
        throw {
          error: "unauthorized",
          error_description: "Session expired. Please log in again.",
        };
      } else {
        throw (
          data || {
            error: "profile_error",
            error_description: `Failed to get user profile (${status})`,
          }
        );
      }
    } else if (error.request) {
      console.error("Get profile error: No response from server");
      throw {
        error: "network_error",
        error_description: "Could not connect to authentication server",
      };
    } else {
      console.error("Get profile error:", error.message);
      throw {
        error: "unknown_error",
        error_description: error.message || "Failed to get user profile",
      };
    }
  }
};

// Refresh token
export const refreshToken = async () => {
  try {
    // Only attempt to refresh if we have a token with refresh_token
    if (!authToken || !authToken.refresh_token) {
      throw {
        error: "no_refresh_token",
        error_description: "No refresh token available",
      };
    }

    // Send refresh token to server
    const response = await api.post("/refresh", {
      refresh_token: authToken.refresh_token,
    });

    // Update token in memory
    if (response.data.token) {
      authToken = response.data.token;
    }

    return response.data;
  } catch (error) {
    console.error("Token refresh error:", error);

    // If refresh fails, clear token and force re-login
    if (error.response && error.response.status === 401) {
      authToken = null;
    }

    throw error;
  }
};

export default {
  login,
  logout,
  registerUser,
  refreshToken,
  getUserProfile,
};
