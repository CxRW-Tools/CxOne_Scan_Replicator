class Operation:
    """Base class for all operations."""
    
    def __init__(self, config, auth_manager):
        """Initialize the operation.
        
        Args:
            config (Config): Configuration instance
            auth_manager (AuthManager): Authentication manager instance
        """
        self.config = config
        self.auth = auth_manager

    def execute(self):
        """Execute the operation.
        
        This method should be overridden by specific operations.
        """
        raise NotImplementedError("Operation must implement execute method") 