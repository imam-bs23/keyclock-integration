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
KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET")

def get_keycloak_openid() -> KeycloakOpenID:
    """Initialize and return a KeycloakOpenID client."""
    try:
        logger.info(f"Initializing KeycloakOpenID for realm {KEYCLOAK_REALM}")
        return KeycloakOpenID(
            server_url=KEYCLOAK_SERVER_URL,
            client_id=KEYCLOAK_CLIENT_ID,
            client_secret_key=KEYCLOAK_CLIENT_SECRET,
            realm_name=KEYCLOAK_REALM,
            verify=True
        )
    except Exception as e:
        logger.error(f"Failed to initialize KeycloakOpenID: {str(e)}")
        raise Exception("Failed to connect to Keycloak")

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

def validate_refresh_input(event: Dict[str, Any]) -> Dict[str, str]:
    """Validate and extract refresh token from the event."""
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
            
        if not body.get('refresh_token'):
            raise ValueError("Missing required field: refresh_token")
            
        return {
            'refresh_token': str(body['refresh_token'])
        }
    except Exception as e:
        raise ValueError(f"Invalid input: {str(e)}")

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict:
    """Handle token refresh through AWS Lambda."""
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Parse and validate input
        token_data = validate_refresh_input(event)
        refresh_token = token_data['refresh_token']
        
        # Initialize Keycloak client
        keycloak_openid = get_keycloak_openid()
        
        # Refresh the token
        token_response = keycloak_openid.refresh_token(refresh_token)
        
        logger.info("Token refreshed successfully")
        return create_response(200, "Token refreshed successfully", {
            'access_token': token_response['access_token'],
            'refresh_token': token_response.get('refresh_token', refresh_token),  # Use new refresh token if provided, else use the old one
            'expires_in': token_response.get('expires_in', 300),
            'refresh_expires_in': token_response.get('refresh_expires_in', 1800)
        })
        
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return create_response(400, f"Invalid request: {str(e)}")
        
    except KeycloakError as e:
        error_msg = str(e).lower()
        logger.error(f"Keycloak error: {error_msg}")
        
        if "invalid refresh token" in error_msg or "invalid_grant" in error_msg:
            return create_response(401, "Invalid or expired refresh token")
        elif "connection" in error_msg or "can't connect" in error_msg:
            return create_response(503, "Cannot connect to authentication service. Please try again later.")
        else:
            return create_response(400, f"Token refresh failed: {str(e)}")
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return create_response(500, "An internal server error occurred during token refresh")