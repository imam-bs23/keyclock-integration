#!/bin/bash

# Use Python 3.10 (or any available Python version)
echo "Setting up Python environment..."
pyenv local 3.10.12

# Install dependencies
echo "Installing dependencies..."
python -m pip install -r requirements.txt

echo "Setup complete! Run './start.sh' to start the server."
