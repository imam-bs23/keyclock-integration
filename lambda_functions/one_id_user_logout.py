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
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
        },
        'body': json.dumps({
            'success': 200 <= status_code < 300,
            'message': message,
            'data': data or {}
        })
    }

def validate_logout_input(event: Dict[str, Any]) -> Dict[str, str]:
    """Validate and extract logout data from the event."""
    try:
        # Handle both direct API Gateway and test event formats
        body = event.get('body', {})
        
        # If body is a string, parse it as JSON
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON in request body")
        
        # Ensure we have a dictionary at this point
        if not isinstance(body, dict):
            raise ValueError("Request body must be a JSON object")
            
        # Check required field
        if not body.get('refresh_token'):
            raise ValueError("Missing required field: refresh_token")
            
        return {
            'refresh_token': str(body['refresh_token'])
        }
    except Exception as e:
        raise ValueError(f"Invalid input: {str(e)}")

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict:
    """Handle user logout through AWS Lambda."""
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Parse and validate input
        logout_data = validate_logout_input(event)
        
        # Initialize Keycloak OpenID client
        keycloak_openid = get_keycloak_openid_client()
        if not keycloak_openid:
            return create_response(
                status_code=503,
                message="Authentication service is currently unavailable. Please try again later."
            )
        
        try:
            # Logout from Keycloak
            keycloak_openid.logout(logout_data['refresh_token'])
            logger.info("User logged out successfully")
            
            return create_response(
                status_code=200,
                message="Successfully logged out"
            )
            
        except KeycloakError as e:
            error_message = str(e).lower()
            logger.error(f"Keycloak logout error: {error_message}")
            
            if "invalid token" in error_message or "expired" in error_message:
                return create_response(400, "Invalid or expired refresh token")
            elif "forbidden" in error_message:
                return create_response(403, "Logout not allowed")
            else:
                return create_response(400, f"Logout failed: {str(e)}")
                
    except ValueError as e:
        logger.warning(f"Validation error: {str(e)}")
        return create_response(400, str(e))
        
    except Exception as e:
        logger.error(f"Unexpected error during logout: {str(e)}", exc_info=True)
        return create_response(500, "An internal server error occurred during logout")