#!/bin/bash
# Simple startup script for the vulnerable test application

echo "🚀 Starting Vulnerable Test Application..."

# Start SSH service (insecure for demo)
service ssh start

# Create a simple web server
python3 -m http.server 8080 &

# Start Node.js application if it exists
if [ -f "app.js" ]; then
    node app.js &
fi

echo "✅ Application started on multiple ports"
echo "🔓 SSH: port 22 (root:vulnerable123)"
echo "🌐 HTTP: port 8080"
echo "⚠️  This is a deliberately insecure test container!"

# Keep container running
tail -f /dev/null 