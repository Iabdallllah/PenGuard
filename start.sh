#!/bin/bash
set -e

PORT_API=${PORT:-8000}
TARGET_PORT=${TARGET_PORT:-8001}

# If Render provides only $PORT, run API on $PORT and target on $TARGET_PORT internally
# For single-port platforms, both can run and frontend proxies via relative /api

echo "Starting target on 0.0.0.0:$TARGET_PORT ..."
uvicorn target_app:app --host 0.0.0.0 --port $TARGET_PORT &
TARGET_PID=$!

echo "Starting API on 0.0.0.0:$PORT_API ..."
uvicorn api_server:app --host 0.0.0.0 --port $PORT_API &
API_PID=$!

# Wait on any process to exit, keep container alive
wait -n
