import json
import logging
import os
from typing import Any, Dict, Optional

from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
REQUIRED_ENV_VARS = [
    "KEYCLOAK_URL",
    "KEYCLOAK_REALM",
    "KEYCLOAK_CLIENT_ID",
    "KEYCLOAK_CLIENT_SECRET"
]

# Validate environment variables
for var in REQUIRED_ENV_VARS:
    if not os.environ.get(var):
        raise ValueError(f"Missing required environment variable: {var}")

# Keycloak configuration
KEYCLOAK_SERVER_URL = os.environ["KEYCLOAK_URL"].rstrip('/') + "/"
KEYCLOAK_REALM = os.environ["KEYCLOAK_REALM"]
KEYCLOAK_CLIENT_ID = os.environ["KEYCLOAK_CLIENT_ID"]
KEYCLOAK_CLIENT_SECRET = os.environ["KEYCLOAK_CLIENT_SECRET"]

def get_keycloak_openid_client() -> Optional[KeycloakOpenID]:
    """Initialize and return a Keycloak OpenID client."""
    try:
        logger.info(f"Attempting to connect to Keycloak OpenID at {KEYCLOAK_SERVER_URL} with realm {KEYCLOAK_REALM}")
        keycloak_openid = KeycloakOpenID(
            server_url=KEYCLOAK_SERVER_URL,
            client_id=KEYCLOAK_CLIENT_ID,
            realm_name=KEYCLOAK_REALM,
            client_secret_key=KEYCLOAK_CLIENT_SECRET,
        )
        
        # Test connection by getting well-known endpoint
        keycloak_openid.well_known()
        logger.info("Successfully connected to Keycloak OpenID")
        return keycloak_openid
        
    except Exception as e:
        logger.error(f"Failed to connect to Keycloak OpenID: {str(e)}")
        return None

def create_response(status_code: int, message: str, data: Optional[Dict] = None) -> Dict:
    """Create a standardized API response."""
    logger.info(f"Creating response with status code {status_code} and message {message}")
    logger.info(f"Data: {data}")
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json'
        },
        'body': json.dumps({
            'success': 200 <= status_code < 300,
            'message': message,
            'data': data or {}
        })
    }

def get_bearer_token(event: Dict[str, Any]) -> Optional[str]:
    """Extract Bearer token from the Authorization header."""
    try:
        auth_header = event.get('headers', {}).get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return None
        return auth_header.split(' ')[1].strip()
    except Exception as e:
        logger.warning(f"Error extracting token: {str(e)}")
        return None

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict:
    """Handle user info requests through AWS Lambda."""
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Extract token from Authorization header
    token = get_bearer_token(event)
    if not token:
        return create_response(401, "Missing or invalid Authorization header")
    
    # Initialize Keycloak OpenID client
    keycloak_openid = get_keycloak_openid_client()
    if not keycloak_openid:
        return create_response(503, "Authentication service is currently unavailable. Please try again later.")
    
    try:
        # Get user info from Keycloak
        user_info = keycloak_openid.userinfo(token)
        
        # Format the response data
        response_data = {
            'sub': user_info.get('sub', ''),
            'username': user_info.get('preferred_username', ''),
            'email': user_info.get('email', ''),
            'firstName': user_info.get('given_name'),
            'lastName': user_info.get('family_name'),
            'emailVerified': user_info.get('email_verified', False),
            'roles': user_info.get('realm_access', {}).get('roles', [])
        }
        
        # Remove None values from response
        response_data = {k: v for k, v in response_data.items() if v is not None}
        
        logger.info(f"Successfully retrieved user info for {response_data.get('username')}")
        logger.info(f"User info: {response_data}")
        return create_response(200, "User info retrieved successfully", response_data)
        
    except KeycloakError as e:
        error_message = str(e).lower()
        logger.error(f"Keycloak error: {error_message}")
        
        if "invalid token" in error_message or "expired" in error_message:
            return create_response(401, "Invalid or expired token")
        elif "forbidden" in error_message:
            return create_response(403, "Insufficient permissions to access user info")
        else:
            return create_response(401, f"Authentication failed: {str(e)}")
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return create_response(500, "An internal server error occurred")
