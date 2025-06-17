import json
import logging
import os
from typing import Any, Dict, Optional

from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
REQUIRED_ENV_VARS = [
    "KEYCLOAK_URL",
    "KEYCLOAK_REALM",
    "KEYCLOAK_ADMIN_USERNAME",
    "KEYCLOAK_ADMIN_PASSWORD"
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

def get_keycloak_admin() -> KeycloakAdmin:
    """Initialize and return a KeycloakAdmin client."""
    try:
        logger.info(f"Connecting to Keycloak admin API at {KEYCLOAK_SERVER_URL}")
        return KeycloakAdmin(
            server_url=KEYCLOAK_SERVER_URL,
            username=KEYCLOAK_ADMIN_USERNAME,
            password=KEYCLOAK_ADMIN_PASSWORD,
            realm_name=KEYCLOAK_REALM,
            client_id="admin-cli",
            verify=True
        )
    except Exception as e:
        logger.error(f"Failed to connect to Keycloak: {str(e)}")
        raise Exception("Failed to connect to Keycloak admin API")

def validate_input(event: Dict[str, Any]) -> Dict[str, str]:
    """Validate and extract user data from the event."""
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
            
        required_fields = ['username', 'email', 'password', 'firstName', 'lastName']
        missing = [field for field in required_fields if not body.get(field)]
        
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")
            
        return {
            'username': str(body['username']).strip(),
            'email': str(body['email']).strip().lower(),
            'password': str(body['password']),
            'firstName': str(body['firstName']).strip(),
            'lastName': str(body['lastName']).strip()
        }
    except Exception as e:
        raise ValueError(f"Invalid input: {str(e)}")

def create_response(status_code: int, message: str, data: Optional[Dict] = None) -> Dict:
    """Create a standardized API response.
    
    Args:
        status_code: HTTP status code
        message: Response message
        data: Optional response data
        
    Returns:
        Dict containing the API response with body as a JSON object
    """
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

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict:
    """Handle user registration through AWS Lambda."""
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Parse and validate input
        user_data = validate_input(event)
        
        # Initialize Keycloak admin client
        keycloak_admin = get_keycloak_admin()
        
        # Check if user exists
        try:
            existing_users = keycloak_admin.get_users({
                'username': user_data['username'],
                'email': user_data['email']
            })
            
            if existing_users:
                logger.warning(f"User {user_data['username']} or email {user_data['email']} already exists")
                return create_response(409, "User with this username or email already exists")
                
        except KeycloakError as e:
            logger.warning(f"Warning checking existing users: {str(e)}")
        
        # Create user
        user_payload = {
            'username': user_data['username'],
            'email': user_data['email'],
            'firstName': user_data['firstName'],
            'lastName': user_data['lastName'],
            'enabled': True,
            'emailVerified': True,
            'credentials': [{
                'type': 'password',
                'value': user_data['password'],
                'temporary': False
            }]
        }
        
        user_id = keycloak_admin.create_user(user_payload)
        logger.info(f"User {user_data['username']} created successfully with ID: {user_id}")
        
        return create_response(201, "User registered successfully", {'userId': user_id})
        
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return create_response(400, f"Invalid request: {str(e)}")
        
    except KeycloakError as e:
        error_msg = str(e).lower()
        logger.error(f"Keycloak error: {error_msg}")
        
        if "user exists" in error_msg:
            return create_response(409, "User with this username or email already exists")
        elif "forbidden" in error_msg or "403" in error_msg:
            return create_response(403, "Registration is not allowed. Please contact the administrator.")
        elif "connection" in error_msg or "can't connect" in error_msg:
            return create_response(503, "Cannot connect to authentication service. Please try again later.")
        else:
            return create_response(400, f"Registration failed: {str(e)}")
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return create_response(500, "An internal server error occurred")