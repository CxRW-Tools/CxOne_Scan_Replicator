import os
from dotenv import load_dotenv

class Config:
    def __init__(self):
        """Initialize configuration with None values."""
        self.base_url = None
        self.tenant_name = None
        self.api_key = None
        self.debug = False

    @classmethod
    def from_args(cls, args):
        """Create configuration from command line arguments.
        
        Args:
            args: Parsed command line arguments
        """
        config = cls()
        config.base_url = args.base_url
        config.tenant_name = args.tenant_name
        config.api_key = args.api_key
        config.debug = args.debug
        return config

    @classmethod
    def from_env(cls):
        """Create configuration from environment variables."""
        load_dotenv()  # Load .env file if it exists
        
        config = cls()
        config.base_url = os.getenv('CXONE_BASE_URL')
        config.tenant_name = os.getenv('CXONE_TENANT')
        config.api_key = os.getenv('CXONE_API_KEY')
        config.debug = os.getenv('CXONE_DEBUG', '').lower() == 'true'
        return config

    def validate(self):
        """Validate the configuration.
        
        Returns:
            tuple: (bool, str) - (is_valid, error_message)
        """
        if not self.base_url:
            return False, "Base URL is required"
        if not self.tenant_name:
            return False, "Tenant name is required"
        if not self.api_key:
            return False, "API key is required"
        return True, None 