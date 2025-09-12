#!/bin/bash
# Startup script for the EML to PDF Converter

echo "🚀 Starting EML to PDF Converter..."
echo "📍 Backend will run on: http://localhost:5002"
echo "📍 Frontend will run on: http://localhost:8000"
echo ""

# Load local environment (e.g., APP_PASSWORD) if present
cd "$(dirname "$0")"
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

# Kill any existing processes
pkill -f "python.*app.py" 2>/dev/null || true
pkill -f "http.server.*8000" 2>/dev/null || true

# Start backend in background
echo "Starting backend server..."
source .venv/bin/activate
nohup python backend/app.py > backend.log 2>&1 &
BACKEND_PID=$!

# Start frontend in background
echo "Starting frontend server..."
cd simple-frontend
nohup python3 -m http.server 8000 > ../frontend.log 2>&1 &
FRONTEND_PID=$!

# Wait a moment for servers to start
sleep 3

echo "✅ Backend running on http://localhost:5002 (PID: $BACKEND_PID)"
echo "✅ Frontend running on http://localhost:8000 (PID: $FRONTEND_PID)"
echo ""
echo "🌐 Open your browser to: http://localhost:8000/"
echo ""
echo "📝 Logs:"
echo "  Backend: tail -f backend.log"
echo "  Frontend: tail -f frontend.log"
echo ""
echo "🛑 To stop servers:"
echo "  pkill -f 'python.*app.py'"
echo "  pkill -f 'http.server.*8000'"