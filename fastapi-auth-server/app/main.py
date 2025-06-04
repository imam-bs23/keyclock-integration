import logging
import os
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.exceptions import KeycloakError
from pydantic import BaseModel, EmailStr

# Load environment variables from .env file
load_dotenv()


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="FastAPI Keycloak Auth", version="1.0.0")

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
        realm_name=KEYCLOAK_REALM,  
        client_id="admin-cli",  # Use admin-cli for admin operations
        verify=True
    )

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

@app.post("/api/auth/register", response_model=dict)
async def register_user(user_data: UserRegistration):
    """Register a new user directly in Keycloak"""
    logger.info(f"Attempting to register user: {user_data.username}")
    
    if not keycloak_admin:
        raise HTTPException(status_code=503, detail="Keycloak admin client not available")
    
    try:        
        # Check if user already exists
        try:
            existing_users = keycloak_admin.get_users({"username": user_data.username, "email": user_data.email})
            if existing_users:
                logger.warning(f"User with username {user_data.username} or email {user_data.email} already exists")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this username or email already exists"
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
        
        # Create user in Keycloak
        user_id = keycloak_admin.create_user(user_payload)
        logger.info(f"User created successfully with ID: {user_id}")

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

@app.post("/api/auth/logout")
async def logout_user(refresh_data: RefreshTokenRequest):
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