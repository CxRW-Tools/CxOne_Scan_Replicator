import sys
import time
import requests

class AuthManager:
    def __init__(self, base_url, tenant_name, api_key, debug=False):
        """Initialize the authentication manager.
        
        Args:
            base_url (str): The base URL for the CxOne instance
            tenant_name (str): The tenant name
            api_key (str): The API key for authentication
            debug (bool, optional): Enable debug output. Defaults to False.
        """
        self.base_url = base_url
        self.tenant_name = tenant_name
        self.api_key = api_key
        self.debug = debug
        self.auth_token = None
        self.token_expiration = 0
        self.iam_base_url = self._generate_iam_url()
        self.auth_url = self._generate_auth_url()

    def _generate_iam_url(self):
        """Generate the IAM URL from the base URL."""
        return self.base_url.replace("ast.checkmarx.net", "iam.checkmarx.net")

    def _generate_auth_url(self):
        """Generate the authentication URL."""
        return f"{self.iam_base_url}/auth/realms/{self.tenant_name}/protocol/openid-connect/token"

    def ensure_authenticated(self):
        """Ensure we have a valid authentication token."""
        if time.time() >= self.token_expiration - 60:
            self._authenticate()
        return self.auth_token

    def _authenticate(self):
        """Authenticate with the API key and get a new token."""
        if self.debug:
            print("Authenticating with API key...")
            
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'grant_type': 'refresh_token',
            'client_id': 'ast-app',
            'refresh_token': self.api_key
        }
        
        try:
            response = requests.post(self.auth_url, headers=headers, data=data)
            response.raise_for_status()
            
            json_response = response.json()
            self.auth_token = json_response.get('access_token')
            if not self.auth_token:
                raise ValueError("No access token in response")
                
            expires_in = json_response.get('expires_in', 600)
            self.token_expiration = time.time() + expires_in

            if self.debug:
                print("Authentication successful")
                
        except requests.exceptions.RequestException as e:
            print(f"Authentication error: {e}")
            sys.exit(1)
        except ValueError as e:
            print(f"Authentication error: {e}")
            sys.exit(1)

    def get_headers(self):
        """Get headers with authentication token for API requests."""
        return {
            'Authorization': f'Bearer {self.ensure_authenticated()}',
            'Content-Type': 'application/json'
        } 