import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.exceptions import KeycloakError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

# Load environment variables from .env file
load_dotenv()


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="FastAPI Keycloak Auth", version="1.0.0")

# JWT Settings
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory user database (for demonstration purposes)
users_db = {}

# Helper functions for JWT authentication
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    if username in users_db:
        return users_db[username]
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Keycloak configuration
KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_URL")
if KEYCLOAK_SERVER_URL and not KEYCLOAK_SERVER_URL.endswith("/"):
    KEYCLOAK_SERVER_URL += "/"

KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_ADMIN_USERNAME = os.getenv("KEYCLOAK_ADMIN_USERNAME")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")

logger.info(f"Keycloak configuration: URL={KEYCLOAK_SERVER_URL}, Realm={KEYCLOAK_REALM}, Client={KEYCLOAK_CLIENT_ID}")


try:
    logger.info(f"Attempting to connect to Keycloak admin API at {KEYCLOAK_SERVER_URL}")
    # Initialize Keycloak admin client directly
    keycloak_admin = KeycloakAdmin(
        server_url=KEYCLOAK_SERVER_URL,
        username=KEYCLOAK_ADMIN_USERNAME,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name="myrealm",  # Admin operations are typically performed in master realm
        client_id="admin-cli",  # Use admin-cli for admin operations
        verify=True
    )
    
    # Set the target realm for operations
    keycloak_admin.realm_name = KEYCLOAK_REALM
    
    # Test connection by getting realm info
    try:
        realm_info = keycloak_admin.get_realm(KEYCLOAK_REALM)
        logger.info(f"Successfully connected to Keycloak admin API and verified realm {KEYCLOAK_REALM} exists")
    except Exception as e:
        logger.warning(f"Connected to Keycloak admin API but realm {KEYCLOAK_REALM} might not exist: {str(e)}")
    
except Exception as e:
    logger.error(f"Failed to connect to Keycloak admin API: {str(e)}")
    keycloak_admin = None

# Initialize Keycloak OpenID client
try:
    logger.info(f"Attempting to connect to Keycloak OpenID at {KEYCLOAK_SERVER_URL} with realm {KEYCLOAK_REALM}")
    keycloak_openid = KeycloakOpenID(
        server_url=KEYCLOAK_SERVER_URL,
        client_id=KEYCLOAK_CLIENT_ID,
        realm_name=KEYCLOAK_REALM,
        client_secret_key=KEYCLOAK_CLIENT_SECRET,
    )
    
    # Test connection by getting well-known endpoint
    try:
        well_known = keycloak_openid.well_known()
        logger.info(f"Successfully connected to Keycloak OpenID at {KEYCLOAK_SERVER_URL}")
        logger.info(f"Token endpoint: {well_known.get('token_endpoint')}")
        logger.info(f"Available grant types: {well_known.get('grant_types_supported')}")
        
        # Check if password grant type is supported
        if 'password' in well_known.get('grant_types_supported', []):
            logger.info("Password grant type is supported by this Keycloak server")
        else:
            logger.warning("Password grant type is NOT supported by this Keycloak server!")
            
    except Exception as e:
        logger.error(f"Connected to Keycloak OpenID but failed to get well-known config: {str(e)}")
        keycloak_openid = None
        
except Exception as e:
    logger.error(f"Failed to connect to Keycloak OpenID: {str(e)}")
    keycloak_openid = None

# Security scheme
security = HTTPBearer()

# Pydantic models
class UserRegistration(BaseModel):
    username: str
    email: EmailStr
    password: str
    firstName: str
    lastName: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int

class UserInfo(BaseModel):
    sub: str
    username: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    roles: list[str] = []

class RefreshTokenRequest(BaseModel):
    refresh_token: str

# Dependency to get current user from JWT token
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    try:
        token = credentials.credentials
        # Decode and validate token
        user_info = keycloak_openid.introspect(token)
        
        if not user_info.get('active'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is not active"
            )
        
        return user_info
    except KeycloakError as e:
        logger.error(f"Keycloak error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

@app.post("/api/auth/register/direct", response_model=dict)
async def register_user(user_data: UserRegistration):
    """Register a new user directly in Keycloak"""
    logger.info(f"Attempting to register user: {user_data.username}")
    
    if not keycloak_admin:
        raise HTTPException(status_code=503, detail="Keycloak admin client not available")
    
    try:
        # Make sure we're targeting the correct realm
        current_realm = keycloak_admin.realm_name
        logger.info(f"Current admin realm before user registration: {current_realm}")
        
        # Explicitly set the realm to myrealm for user registration
        keycloak_admin.realm_name = KEYCLOAK_REALM
        logger.info(f"Set admin realm for user registration to: {keycloak_admin.realm_name}")
        
        # Check if user already exists
        try:
            existing_users = keycloak_admin.get_users({"username": user_data.username})
            if existing_users:
                logger.warning(f"User with username {user_data.username} already exists")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this username already exists"
                )
                
            existing_users = keycloak_admin.get_users({"email": user_data.email})
            if existing_users:
                logger.warning(f"User with email {user_data.email} already exists")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this email already exists"
                )
        except KeycloakError as e:
            logger.warning(f"Could not check for existing users: {str(e)}")
            # Continue with registration attempt
        
        # Create user payload
        user_payload = {
            "username": user_data.username,
            "email": user_data.email,
            "firstName": user_data.firstName,
            "lastName": user_data.lastName,
            "enabled": True,
            "emailVerified": True,
            "credentials": [{
                "type": "password",
                "value": user_data.password,
                "temporary": False
            }]
        }

        logger.debug(f'User payload prepared: {user_data.username}')
        
        # Make sure we're targeting the correct realm
        keycloak_admin.realm_name = KEYCLOAK_REALM  # Explicitly set the realm name again to ensure it's correct
        current_realm = keycloak_admin.realm_name
        logger.info(f"Creating user in realm: {current_realm}")
        
        # Create user in Keycloak
        user_id = keycloak_admin.create_user(user_payload)
        logger.info(f"User created successfully with ID: {user_id} in realm {current_realm}")
        
        # Set password for the user
        keycloak_admin.set_user_password(user_id, user_data.password, temporary=False)
        logger.info(f"Password set for user with ID: {user_id}")
        
        # Enable the user account
        keycloak_admin.update_user(user_id, {"enabled": True, "emailVerified": True})
        logger.info(f"User account enabled and email verified for user with ID: {user_id}")
        
        return {
            "message": "User registered successfully",
            "user_id": user_id
        }
        
    except KeycloakError as e:
        logger.error(f"Keycloak registration error: {str(e)}")
        error_message = str(e).lower()
        
        if "user exists" in error_message:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this username or email already exists"
            )
        elif "forbidden" in error_message or "403" in error_message:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Registration is not allowed. Please contact the administrator."
            )
        elif "can't connect" in error_message:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cannot connect to Keycloak server. Please try again later."
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Registration failed: {str(e)}"
            )
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during registration"
        )

@app.post("/api/auth/login", response_model=TokenResponse)
async def login_user(login_data: UserLogin):
    """Authenticate user and return JWT tokens"""
    logger.info(f"Login attempt for user: {login_data.username}")
    
    # Check if Keycloak OpenID client is available
    if keycloak_openid is None:
        logger.error("Keycloak OpenID client is not available")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is currently unavailable. Please try again later."
        )
    
    try:
        # Log Keycloak OpenID configuration
        logger.info(f"Attempting login for user {login_data.username} with client {KEYCLOAK_CLIENT_ID} in realm {KEYCLOAK_REALM}")
        
        # Get token from Keycloak using password grant type
        token_response = keycloak_openid.token(
            grant_type="password",
            username=login_data.username,
            password=login_data.password,
            scope="openid"
        )
        
        # Log token response keys (not the actual tokens)
        if token_response:
            logger.info(f"Token response received with keys: {', '.join(token_response.keys())}")
            logger.info(f"Token type: {token_response.get('token_type', 'unknown')}")
            logger.info(f"Expires in: {token_response.get('expires_in', 'unknown')} seconds")
        
        logger.info(f"User {login_data.username} logged in successfully")
        
        return TokenResponse(
            access_token=token_response["access_token"],
            refresh_token=token_response["refresh_token"],
            expires_in=token_response["expires_in"]
        )
        
    except KeycloakError as e:
        error_message = str(e).lower()
        logger.error(f"Keycloak login error: {error_message}")
        
        if "invalid_grant" in error_message or "invalid user credentials" in error_message:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        elif "invalid_client" in error_message:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client credentials. Please contact the administrator."
            )
        elif "unauthorized_client" in error_message or "not allowed" in error_message:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Client is not authorized for direct access grants. Please contact the administrator."
            )
        elif "can't connect" in error_message:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cannot connect to authentication server. Please try again later."
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: {str(e)}"
            )
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during login"
        )

@app.post("/api/auth/refresh", response_model=TokenResponse)
async def refresh_token(refresh_data: RefreshTokenRequest):
    """Refresh access token using refresh token"""
    try:
        token_response = keycloak_openid.refresh_token(refresh_data.refresh_token)
        
        return TokenResponse(
            access_token=token_response["access_token"],
            refresh_token=token_response["refresh_token"],
            expires_in=token_response["expires_in"]
        )
        
    except KeycloakError as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during token refresh"
        )

@app.get("/api/auth/me", response_model=UserInfo)
async def get_user_profile(request: Request):
    auth_header = request.headers.get("Authorization")
    
    if auth_header and auth_header.startswith("Bearer ") and keycloak_openid is not None:
        token = auth_header.split(" ")[1]
    try:
        current_user = keycloak_openid.userinfo(token)
        # Extract user information from token
        user_info = UserInfo(
            sub=current_user.get("sub", ""),
            username=current_user.get("preferred_username", ""),
            email=current_user.get("email", ""),
            first_name=current_user.get("given_name"),
            last_name=current_user.get("family_name"),
            roles=current_user.get("realm_access", {}).get("roles", [])
        )
        
        return user_info
    except Exception as e:
        logger.error(f"Error getting user profile: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving user profile"
        )

@app.get("/api/auth/simple/me", response_model=UserInfo)
async def get_user_profile_simple(token: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    """Get current user information using simple JWT authentication"""
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = get_user(username)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # Convert simple user data to UserInfo format
        user_info = UserInfo(
            sub=username,
            username=username,
            email=user["email"],
            first_name=user["first_name"],
            last_name=user["last_name"],
            roles=["user"]  # Default role for simple auth
        )
        
        return user_info
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Error getting user profile: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving user profile"
        )

@app.post("/api/auth/logout")
async def logout_user(
    refresh_data: RefreshTokenRequest,
):
    """Logout user and invalidate tokens"""
    try:
        # Logout from Keycloak
        keycloak_openid.logout(refresh_data.refresh_token)
        
        return {"message": "Successfully logged out"}
        
    except KeycloakError as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Error during logout"
        )
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during logout"
        )

@app.get("/api/auth/protected")
async def protected_route(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Example protected route that requires authentication"""
    return {
        "message": "This is a protected route",
        "user": current_user.get("preferred_username"),
        "roles": current_user.get("realm_access", {}).get("roles", [])
    }

@app.get("/api/auth/check")
async def health_check(request: Request):
    """Health check endpoint with Keycloak connection status"""
    # Check if Authorization header is present
    auth_header = request.headers.get("Authorization")
    user_info = None
    auth_status = False
    
    if auth_header and auth_header.startswith("Bearer ") and keycloak_openid is not None:
        token = auth_header.split(" ")[1]
        try:
            # Verify token
            # keycloak_openid.decode_token(
            #     token,
            #     key=None,
            #     options={
            #         "verify_signature": True,
            #         "verify_aud": True,
            #         "verify_exp": True
            #     }
            # )
            
            # Get user info
            try:
                user_info = keycloak_openid.userinfo(token)
                auth_status = True
            except Exception as e:
                logger.warning(f"Error getting userinfo: {str(e)}")
                # Token is valid but userinfo failed
                auth_status = True
        except Exception as e:
            logger.warning(f"Token validation failed: {str(e)}")
    
    # Check Keycloak connection status
    keycloak_status = {
        "admin_api": keycloak_admin is not None,
        "openid_api": keycloak_openid is not None,
        "server_url": KEYCLOAK_SERVER_URL,
        "realm": KEYCLOAK_REALM
    }
    
    return {
        "status": "healthy", 
        "service": "FastAPI Keycloak Auth",
        "authenticated": auth_status,
        "user": user_info,
        "keycloak_connection": keycloak_status
    }

@app.get("/api/auth/debug/client")
async def debug_client_info():
    """Debug endpoint to get client information"""
    try:
        # Make sure we're targeting the correct realm
        current_realm = keycloak_admin.realm_name
        logger.info(f"Current admin realm: {current_realm}")
        
        # Explicitly set the realm to myrealm
        keycloak_admin.realm_name = KEYCLOAK_REALM
        logger.info(f"Set admin realm to: {keycloak_admin.realm_name}")
        
        # Get client information in the correct realm
        clients = keycloak_admin.get_clients()
        client_info = None
        
        # Find our client
        for client in clients:
            if client.get("clientId") == KEYCLOAK_CLIENT_ID:
                client_info = client
                break
        
        if client_info:
            # Get client secret if available
            try:
                client_id = client_info.get("id")
                client_secret = keycloak_admin.get_client_secrets(client_id)
                client_info["secret"] = client_secret
            except Exception as e:
                logger.warning(f"Could not get client secret: {str(e)}")
            
            return {
                "client": client_info,
                "realm": KEYCLOAK_REALM,
                "server_url": KEYCLOAK_SERVER_URL
            }
        else:
            return {
                "error": f"Client {KEYCLOAK_CLIENT_ID} not found",
                "available_clients": [c.get("clientId") for c in clients if "clientId" in c]
            }
    except Exception as e:
        logger.error(f"Error getting client info: {str(e)}")
        return {"error": str(e)}


@app.post("/api/auth/debug/update-client")
async def update_client_config():
    """Debug endpoint to update client configuration"""
    try:
        # Make sure we're targeting the correct realm
        current_realm = keycloak_admin.realm_name
        logger.info(f"Current admin realm: {current_realm}")
        
        # Explicitly set the realm to myrealm
        keycloak_admin.realm_name = KEYCLOAK_REALM
        logger.info(f"Set admin realm to: {keycloak_admin.realm_name}")
        
        # Get client information in the correct realm
        clients = keycloak_admin.get_clients()
        client_info = None
        client_id = None
        
        # Find our client
        for client in clients:
            if client.get("clientId") == KEYCLOAK_CLIENT_ID:
                client_info = client
                client_id = client.get("id")
                break
        
        if not client_info or not client_id:
            return {"error": f"Client {KEYCLOAK_CLIENT_ID} not found in realm {KEYCLOAK_REALM}", "available_clients": [c.get("clientId") for c in clients if "clientId" in c]}
        
        # Update client configuration
        client_info["directAccessGrantsEnabled"] = True  # Enable password flow
        client_info["standardFlowEnabled"] = True  # Enable authorization code flow
        client_info["serviceAccountsEnabled"] = True  # Enable client credentials flow
        client_info["publicClient"] = True  # Set as public client (no client secret needed)
        client_info["implicitFlowEnabled"] = True  # Enable implicit flow
        
        # Update redirect URIs if needed
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
        backend_url = f"http://localhost:{os.getenv('PORT', '3001')}"
        
        redirect_uris = [
            f"{frontend_url}/*",
            f"{backend_url}/*",
            "http://localhost:*/*"
        ]
        client_info["redirectUris"] = redirect_uris
        
        # Update web origins
        client_info["webOrigins"] = [frontend_url, backend_url, "http://localhost:*"]
        
        # Update the client
        keycloak_admin.update_client(client_id, client_info)
        
        return {
            "success": True,
            "message": "Client configuration updated successfully",
            "client": client_info
        }
    except Exception as e:
        logger.error(f"Error updating client config: {str(e)}")
        return {"error": str(e)}


@app.get("/api/auth/debug/realm-settings")
async def debug_realm_settings():
    """Debug endpoint to check realm settings"""
    try:
        # Make sure we're targeting the correct realm
        keycloak_admin.realm_name = KEYCLOAK_REALM
        logger.info(f"Checking realm settings for: {keycloak_admin.realm_name}")
        
        # Get realm settings
        realm_info = keycloak_admin.get_realm(KEYCLOAK_REALM)
        
        # Check if user registration is enabled
        registration_allowed = realm_info.get("registrationAllowed", False)
        logger.info(f"User registration allowed: {registration_allowed}")
        
        # Get client info
        clients = keycloak_admin.get_clients()
        client_info = None
        for client in clients:
            if client.get("clientId") == KEYCLOAK_CLIENT_ID:
                client_info = client
                break
        
        # Check direct access grants
        direct_access_grants = client_info.get("directAccessGrantsEnabled", False) if client_info else False
        logger.info(f"Direct access grants enabled: {direct_access_grants}")
        
        # Return relevant settings
        return {
            "realm": {
                "name": KEYCLOAK_REALM,
                "registration_allowed": registration_allowed,
                "login_with_email_allowed": realm_info.get("loginWithEmailAllowed", False),
                "duplicate_emails_allowed": realm_info.get("duplicateEmailsAllowed", False),
                "reset_password_allowed": realm_info.get("resetPasswordAllowed", False),
                "remember_me": realm_info.get("rememberMe", False),
                "verify_email": realm_info.get("verifyEmail", False),
                "login_theme": realm_info.get("loginTheme", "keycloak"),
            },
            "client": {
                "id": client_info.get("id") if client_info else None,
                "client_id": KEYCLOAK_CLIENT_ID,
                "direct_access_grants_enabled": direct_access_grants,
                "standard_flow_enabled": client_info.get("standardFlowEnabled", False) if client_info else False,
                "implicit_flow_enabled": client_info.get("implicitFlowEnabled", False) if client_info else False,
                "service_accounts_enabled": client_info.get("serviceAccountsEnabled", False) if client_info else False,
                "redirect_uris": client_info.get("redirectUris", []) if client_info else [],
                "web_origins": client_info.get("webOrigins", []) if client_info else [],
            }
        }
    except Exception as e:
        logger.error(f"Error checking realm settings: {str(e)}")
        return {"error": str(e)}


@app.post("/api/auth/debug/update-realm")
async def update_realm_settings():
    """Debug endpoint to update realm settings"""
    try:
        # Make sure we're targeting the correct realm
        keycloak_admin.realm_name = KEYCLOAK_REALM
        logger.info(f"Updating realm settings for: {keycloak_admin.realm_name}")
        
        # Get current realm settings
        realm_info = keycloak_admin.get_realm(KEYCLOAK_REALM)
        
        # Enable user registration
        realm_info["registrationAllowed"] = True
        realm_info["loginWithEmailAllowed"] = True
        realm_info["resetPasswordAllowed"] = True
        realm_info["rememberMe"] = True
        
        # Update realm settings
        keycloak_admin.update_realm(KEYCLOAK_REALM, realm_info)
        logger.info(f"Realm settings updated successfully")
        
        return {
            "success": True,
            "message": "Realm settings updated successfully",
            "realm": {
                "name": KEYCLOAK_REALM,
                "registration_allowed": realm_info.get("registrationAllowed", False),
                "login_with_email_allowed": realm_info.get("loginWithEmailAllowed", False),
                "reset_password_allowed": realm_info.get("resetPasswordAllowed", False),
                "remember_me": realm_info.get("rememberMe", False),
            }
        }
    except Exception as e:
        logger.error(f"Error updating realm settings: {str(e)}")
        return {"error": str(e)}


# Simple JWT authentication endpoints
@app.post("/api/auth/simple/register")
async def register_user_simple(user_data: UserCreate):
    """Register a new user with simple JWT authentication"""
    if user_data.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    hashed_password = get_password_hash(user_data.password)
    users_db[user_data.username] = {
        "username": user_data.username,
        "email": user_data.email,
        "hashed_password": hashed_password,
        "first_name": user_data.first_name,
        "last_name": user_data.last_name,
        "disabled": False,
    }
    
    logger.info(f"User registered with simple auth: {user_data.username}")
    return {"message": "User registered successfully", "username": user_data.username}

@app.post("/api/auth/simple/login")
async def login_user_simple(login_data: UserLogin):
    """Login with simple JWT authentication"""
    user = authenticate_user(login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    logger.info(f"User logged in with simple auth: {login_data.username}")
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user["username"],
        "email": user["email"],
        "first_name": user["first_name"],
        "last_name": user["last_name"],
    }

@app.get("/api/auth/simple/me")
async def get_current_user_simple(token: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    """Get current user with simple JWT authentication"""
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = get_user(username)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {
            "authenticated": True,
            "username": user["username"],
            "email": user["email"],
            "first_name": user["first_name"],
            "last_name": user["last_name"],
        }
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)