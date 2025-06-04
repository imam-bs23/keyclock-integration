# Keycloak Configuration Guide

This guide provides step-by-step instructions for configuring Keycloak to work with our FastAPI and React application.

## Prerequisites

- Keycloak server running (default: http://localhost:8080/auth)
- Admin access to Keycloak

## 1. Create a New Realm

1. Log in to the Keycloak Admin Console
2. Hover over the realm dropdown in the top-left corner
3. Click "Add realm"
4. Enter "myrealm" as the name
5. Click "Create"

## 2. Create a Client

1. In your new realm, go to "Clients" in the left sidebar
2. Click "Create"
3. Enter the following details:
   - Client ID: `myclient`
   - Client Protocol: `openid-connect`
   - Root URL: `http://localhost:5173` (your frontend URL)
4. Click "Save"

## 3. Configure the Client

After creating the client, configure the following settings:

1. **Access Type**: Change from "public" to "confidential"
2. **Service Accounts Enabled**: Turn ON
3. **Authorization Enabled**: Turn ON
4. **Direct Access Grants Enabled**: Turn ON (this enables password flow)
5. **Valid Redirect URIs**: Add the following URLs:
   - `http://localhost:5173/*`
   - `http://localhost:3001/*`
   - `http://localhost:5173/callback`
6. **Web Origins**: Add `+` to allow all origins, or specify:
   - `http://localhost:5173`
   - `http://localhost:3001`
7. Click "Save"

## 4. Get Client Secret

1. After saving, go to the "Credentials" tab
2. Copy the "Secret" value - this is your `KEYCLOAK_CLIENT_SECRET`
3. Update this value in your `.env` files

## 5. Configure Realm Login Settings

1. Go to "Realm Settings" in the left sidebar.
2. Click on the "Login" tab.
3. Configure the following settings:
   - **User registration**: Set to ON to allow users to create their own accounts.
   - **Login with email**: Set to ON if you want users to be able to log in using their email address instead of just their username.
   - **Forgot password / Reset password**: Ensure "Reset password allowed" (or similar wording depending on your Keycloak version) is set to ON to allow users to reset their passwords.
   - **Remember me**: Set to ON to enable the "Remember me" functionality on the login page.
   - **Email as username**: Set this based on your preference. If ON, the email address will be used as the username.
4. Click "Save" to apply the changes.

## 6. Configure Service Account Roles

1. Go to "Clients" and select your client ("myclient")
2. Go to the "Service Account Roles" tab
3. Under "Client Roles", select "realm-management" from the dropdown
4. Add the following roles:
   - `manage-users`
   - `view-users`
5. Click "Add Selected"

## 7. Create Test User (Optional)

1. Go to "Users" in the left sidebar
2. Click "Add user"
3. Fill in the details:
   - Username: `testuser`
   - Email: `test@example.com`
   - First Name: `Test`
   - Last Name: `User`
   - Email Verified: ON
4. Click "Save"
5. Go to the "Credentials" tab
6. Set a password and turn OFF "Temporary"
7. Click "Set Password"

## Common Issues and Solutions

### 1. "Invalid parameter: redirect_uri" Error

**Solution:**
- Ensure the exact redirect URI is added to the client configuration
- Add `http://localhost:5173/callback` as a valid redirect URI
- Make sure the URI in your code exactly matches what's configured in Keycloak

### 2. "Registration not allowed" Error

**Solution:**
- Enable user registration in realm settings (Login tab)
- Verify the client has proper permissions

### 3. "403 Forbidden" Error During Authentication

**Solution:**
- Ensure "Direct Access Grants Enabled" is ON for the client
- Verify all Keycloak URLs include the `/auth` path
- Check that redirect URIs are correctly configured

### 4. "Invalid client credentials" Error

**Solution:**
- Verify the client secret in your .env file matches the one in Keycloak
- Ensure the client is set to "confidential" access type

## Testing Your Configuration

1. Start your FastAPI backend:
   ```
   cd fastapi-auth-server
   ./start.sh
   ```

2. Start your React frontend:
   ```
   cd keycloak-react-app
   npm run dev
   ```

3. Try to register a new user and then log in
4. If you encounter any issues, check the server logs and browser console for specific error messages
