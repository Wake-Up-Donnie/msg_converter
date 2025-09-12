#!/bin/bash

echo "🚀 Starting EML to PDF Converter Backend Server..."
echo "📍 Server will run on: http://localhost:5002"
echo "📝 Press Ctrl+C to stop the server"
echo ""

cd "$(dirname "$0")"

# Load local environment (e.g., APP_PASSWORD) if present
if [[ -f .env.local ]]; then
	# shellcheck disable=SC1091
	set -a; source .env.local; set +a
elif [[ -f .env ]]; then
	# shellcheck disable=SC1091
	set -a; source .env; set +a
fi

if [[ -n "${APP_PASSWORD:-}" ]]; then
	echo "🔒 Password protection ENABLED (APP_PASSWORD is set)"
else
	echo "🔓 Password protection DISABLED (APP_PASSWORD not set)"
fi

# Activate virtual environment
source .venv/bin/activate

# Start the Flask server
python backend/app.py