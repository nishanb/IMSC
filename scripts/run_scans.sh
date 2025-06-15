#!/bin/bash

# Create reports directory if it doesn't exist
mkdir -p reports

# Get the image name and tag from environment variables
IMAGE_NAME=${IMAGE_NAME:-"vulnerable-test-app"}
IMAGE_TAG=${IMAGE_TAG:-"latest"}
FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"

echo "🔍 Running vulnerability scans on ${FULL_IMAGE_NAME}..."

# Run Trivy scan
echo "📊 Running Trivy scan..."
trivy image --format json --output reports/trivy-report.json ${FULL_IMAGE_NAME}

# Run Grype scan
echo "📊 Running Grype scan..."
grype ${FULL_IMAGE_NAME} -o json > reports/grype-report.json

echo "✅ Scan results saved to reports directory" 