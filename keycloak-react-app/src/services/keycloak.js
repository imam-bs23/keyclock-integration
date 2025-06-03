import Keycloak from "keycloak-js";

// Keycloak configuration
const keycloakConfig = {
  url: "http://localhost:8080",
  realm: "myrealm",
  clientId: "myclient",
};

// Initialize Keycloak instance
const keycloak = new Keycloak(keycloakConfig);

// Initialize Keycloak
export const initKeycloak = () => {
  return keycloak.init({
    onLoad: "check-sso",
    silentCheckSsoRedirectUri:
      window.location.origin + "/silent-check-sso.html",
    checkLoginIframe: false,
    enableLogging: true,
  });
};

// Login function
export const login = () => {
  keycloak.login({
    redirectUri: window.location.origin + "/success",
  });
};

// Registration function
export const register = () => {
  keycloak.register({
    redirectUri: window.location.origin + "/success",
  });
};

// Logout function
export const logout = () => {
  keycloak.logout({
    redirectUri: window.location.origin,
  });
};

// Check if authenticated
export const isAuthenticated = () => {
  return keycloak.authenticated;
};

// Get user profile
// export const getUserProfile = () => {
//   if (keycloak.authenticated && keycloak.tokenParsed) {
//     return {
//       username: keycloak.tokenParsed.preferred_username || "Not provided",
//       name: keycloak.tokenParsed.name || "Not provided",
//       email: keycloak.tokenParsed.email || "Not provided",
//       emailVerified: keycloak.tokenParsed.email_verified ? "Yes" : "No",
//     };
//   }
//   return null;
// };

// Get token
export const getToken = () => {
  return keycloak.token;
};

// Update token
export const updateToken = (minValidity = 5) => {
  return keycloak.updateToken(minValidity);
};

export default keycloak;
