# CxOne Tool Template

A lightweight template for building tools that interact with CxOne APIs. This template provides a foundation with proper authentication and configuration management while keeping things simple and maintainable.

## Features

- Simple but robust authentication management
- Configuration from both environment variables and command line arguments
- Basic error handling and debugging support
- Clean, modular structure
- Easy to extend

## Project Structure

```
.
├── src/
│   ├── utils/
│   │   ├── auth.py        # Authentication management
│   │   └── config.py      # Configuration handling
│   └── operations/
│       └── base.py        # Base operation class
├── main.py                # Main entry point
├── requirements.txt       # Dependencies
└── README.md             # This file
```

## Setup

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Configuration can be provided either through environment variables or command line arguments:

### Environment Variables

- `CXONE_BASE_URL` - Region Base URL
- `CXONE_TENANT` - Tenant name
- `CXONE_API_KEY` - API key for authentication
- `CXONE_DEBUG` - Enable debug output (set to 'true' to enable)

### Command Line Arguments

- `--base_url` - Region Base URL
- `--tenant_name` - Tenant name
- `--api_key` - API key for authentication
- `--debug` - Enable debug output

Command line arguments take precedence over environment variables.

## Usage

1. Set up your configuration using either environment variables or prepare to use command line arguments

2. Run the tool:
   ```bash
   python main.py [arguments]
   ```

## Adding Operations

1. Create a new file in the `src/operations` directory
2. Subclass the `Operation` class from `src.operations.base`
3. Implement the `execute` method
4. Instantiate and run your operation in `main.py`

Example:
```python
from src.operations.base import Operation

class YourOperation(Operation):
    def execute(self):
        # Your operation logic here
        pass
```

## Development

To add new functionality:

1. Create new operation classes in `src/operations/`
2. Add any utility functions to `src/utils/`
3. Update `main.py` to use your new operations

## License

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
