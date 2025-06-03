# FastAPI Keycloak Authentication Server

This is a FastAPI-based authentication server that integrates with Keycloak for user registration and authentication.

## Features

- Direct user registration via Keycloak Admin API
- User login with username and password
- Token refresh
- Logout functionality
- Authentication status check
- CORS support for frontend integration

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure environment variables in `.env` file:
```
KEYCLOAK_URL=http://localhost:8080/auth
KEYCLOAK_REALM=myrealm
KEYCLOAK_CLIENT_ID=myclient
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin
SECRET_KEY=your-secret-key
PORT=3001
FRONTEND_URL=http://localhost:5173
```

3. Run the server:
```bash
./start.sh
```
Or manually with:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 3001 --reload
```

## API Endpoints

- `GET /` - Check if the API is running
- `GET /api/auth/check` - Check authentication status
- `POST /api/auth/login` - Login with username and password
- `POST /api/auth/register/direct` - Register a new user
- `POST /api/auth/logout` - Logout the current user
- `POST /api/auth/refresh` - Refresh the access token
- `GET /api/auth/register` - Get Keycloak registration URL (legacy redirect method)

## Keycloak Configuration Requirements

1. Create a new client in Keycloak:
   - Client ID: `myclient`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Service Accounts Enabled: `ON`
   - Direct Access Grants Enabled: `ON`
   - Valid Redirect URIs: Include your frontend URL (e.g., `http://localhost:5173/*`)

2. Enable user registration in realm settings:
   - Go to Realm Settings > Login
   - Set "User Registration" to ON

3. Assign necessary roles to the client:
   - Go to Clients > myclient > Service Account Roles
   - Assign "manage-users" role from "realm-management" client

## Frontend Integration

To integrate with a frontend application, make API calls to the endpoints above. Example:

```javascript
// Login
const login = async (username, password) => {
  const response = await fetch('http://localhost:3001/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    credentials: 'include',
    body: JSON.stringify({ username, password }),
  });
  return await response.json();
};

// Register
const register = async (userData) => {
  const response = await fetch('http://localhost:3001/api/auth/register/direct', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(userData),
  });
  return await response.json();
};
```

## Security Considerations

- The server uses HTTPS in production
- Tokens are never exposed to the frontend directly
- Password validation is handled by Keycloak
- Error messages are sanitized to prevent information leakage
