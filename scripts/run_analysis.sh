#!/bin/bash

# Check for NVIDIA API key
if [ -z "$NVIDIA_API_KEY" ]; then
    echo "❌ NVIDIA_API_KEY environment variable is not set"
    echo "Please set it with: export NVIDIA_API_KEY=your_api_key_here"
    exit 1
fi

# Make scripts executable
chmod +x scripts/run_scans.sh
chmod +x scripts/analyze_with_nvidia_ai.py
chmod +x scripts/auto_fix.py

# Step 1: Run vulnerability scans
echo "🔍 Step 1: Running vulnerability scans..."
./scripts/run_scans.sh

# Step 2: Run NVIDIA AI analysis
echo "🤖 Step 2: Running NVIDIA AI analysis..."
python scripts/analyze_with_nvidia_ai.py

# Step 3: Generate auto-fix recommendations
echo "🛠️ Step 3: Generating auto-fix recommendations..."
python scripts/auto_fix.py

echo "✅ Analysis workflow completed!"
echo "📊 Results can be found in:"
echo "   - reports/trivy-report.json"
echo "   - reports/grype-report.json"
echo "   - ai-analysis-report.json"
echo "   - security-recommendations.md" 