class Operation:
    """Base class for operations (from the CxOne template)."""

    def __init__(self, config=None, auth_manager=None):
        self.config = config
        self.auth = auth_manager

    def execute(self):
        raise NotImplementedError("Operation must implement execute method")
