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
    "KEYCLOAK_ADMIN_USERNAME",
    "KEYCLOAK_ADMIN_PASSWORD",
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
KEYCLOAK_ADMIN_USERNAME = os.environ["KEYCLOAK_ADMIN_USERNAME"]
KEYCLOAK_ADMIN_PASSWORD = os.environ["KEYCLOAK_ADMIN_PASSWORD"]
KEYCLOAK_CLIENT_ID = os.environ["KEYCLOAK_CLIENT_ID"]
KEYCLOAK_CLIENT_SECRET = os.environ["KEYCLOAK_CLIENT_SECRET"]

def get_keycloak_openid_client() -> KeycloakOpenID:
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
        
        return keycloak_openid
    except Exception as e:
        logger.error(f"Failed to connect to Keycloak OpenID: {str(e)}")
        keycloak_openid = None
        
    return keycloak_openid


def create_response(status_code: int, message: str, data: Optional[Dict] = None) -> Dict:
    """Create a standardized API response.
    
    Args:
        status_code: HTTP status code
        message: Response message
        data: Optional response data
    Returns:
        Dict containing the API response with body as a JSON object
    """
    response = {
        'statusCode': status_code,
        'body': {
            'success': 200 <= status_code < 300,
            'message': message,
            'data': data or {}
        }
    }
    return response

def validate_login_input(event: Dict[str, Any]) -> Dict[str, str]:
    """Validate and extract login credentials from the event."""
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
            
        # Check required fields
        required_fields = ['username', 'password']
        missing = [field for field in required_fields if not body.get(field)]
        
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")
            
        return {
            'username': str(body['username']).strip(),
            'password': str(body['password'])
        }
    except Exception as e:
        raise ValueError(f"Invalid input: {str(e)}")

def lambda_handler(event, context):
    """Handle user login through AWS Lambda."""
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Parse and validate input
        login_data = validate_login_input(event)
        
        # Initialize Keycloak OpenID client
        keycloak_openid = get_keycloak_openid_client()
        
        if keycloak_openid is None:
            logger.error("Keycloak OpenID client initialization failed")
            return create_response(
                status_code=503,
                message="Authentication service is currently unavailable. Please try again later."
            )
        
        # Attempt to get tokens from Keycloak
        token_response = keycloak_openid.token(
            grant_type="password",
            username=login_data['username'],
            password=login_data['password'],
            scope="openid"
        )
        
        logger.info(f"User {login_data['username']} logged in successfully")
        
        # Prepare response data
        response_data = {
            'access_token': token_response['access_token'],
            'refresh_token': token_response['refresh_token'],
            'expires_in': token_response['expires_in'],
            'token_type': token_response.get('token_type', 'Bearer')
        }

        
        return create_response(
            status_code=200,
            message="Login successful",
            data=response_data,
        )
        
    except KeycloakError as e:
        error_message = str(e).lower()
        logger.error(f"Keycloak login error: {error_message}")
        
        if "invalid_grant" in error_message or "invalid user credentials" in error_message:
            return create_response(401, "Invalid username or password")
        elif "invalid_client" in error_message:
            return create_response(401, "Invalid client credentials. Please contact the administrator.")
        elif "unauthorized_client" in error_message or "not allowed" in error_message:
            return create_response(403, "Client is not authorized for direct access grants. Please contact the administrator.")
        elif "can't connect" in error_message:
            return create_response(503, "Cannot connect to authentication server. Please try again later.")
        else:
            return create_response(401, f"Authentication failed: {str(e)}")
            
    except ValueError as e:
        logger.warning(f"Validation error: {str(e)}")
        return create_response(400, str(e))
        
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}", exc_info=True)
        return create_response(500, "An internal server error occurred during login")