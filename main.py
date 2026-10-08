#!/usr/bin/env python3
"""
CxOne Tool Template - Main Entry Point

This template provides a foundation for building CxOne tools with proper authentication
and configuration management.
"""

import sys
import argparse
from src.utils.auth import AuthManager
from src.utils.config import Config

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CxOne Tool Template')
    parser.add_argument('--base-url', help='Region Base URL')
    parser.add_argument('--tenant-name', help='Tenant name')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    return parser.parse_args()

def main():
    """Main entry point."""
    # Parse arguments
    args = parse_args()
    
    # Initialize configuration (prefer args over env vars)
    config = Config.from_env()
    if args.base_url or args.tenant_name or args.api_key:
        config = Config.from_args(args)

    # Validate configuration
    is_valid, error = config.validate()
    if not is_valid:
        print(f"Configuration error: {error}")
        sys.exit(1)

    # Initialize auth manager
    auth_manager = AuthManager(
        base_url=config.base_url,
        tenant_name=config.tenant_name,
        api_key=config.api_key,
        debug=config.debug
    )

    try:
        # Verify authentication works
        auth_manager.ensure_authenticated()
        
        if config.debug:
            print("Successfully authenticated with CxOne")
            
        # TODO: Add your operations here
        # Example:
        # operation = YourOperation(config, auth_manager)
        # operation.execute()
        
    except Exception as e:
        print(f"Error: {e}")
        if config.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 