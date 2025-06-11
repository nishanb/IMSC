#!/bin/bash

echo "🔐 AI-Powered Container Vulnerability Analysis - Setup Test"
echo "=========================================================="

# Check prerequisites
echo "📋 Checking prerequisites..."

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi
echo "✅ Docker found"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed."
    exit 1
fi
echo "✅ Python 3 found"

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi
echo "✅ Docker is running"

# Make scripts executable
echo "🔧 Setting up permissions..."
chmod +x scripts/*.py
chmod +x start.sh
echo "✅ Scripts are executable"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install requests pandas numpy python-dotenv > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Python dependencies installed"
else
    echo "⚠️  Some Python dependencies may not be installed. This is okay for the demo."
fi

# Build the test container
echo "🐳 Building vulnerable test container..."
docker build -t vulnerable-test-app:latest . > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Test container built successfully"
else
    echo "❌ Failed to build test container"
    exit 1
fi

# Check container size
IMAGE_SIZE=$(docker images vulnerable-test-app:latest --format "table {{.Size}}" | tail -n +2)
echo "📏 Test container size: $IMAGE_SIZE"

# Create mock scan reports for testing (since scanners may not be available locally)
echo "📊 Creating mock scan reports for testing..."
mkdir -p reports

# Create mock Trivy report
cat > reports/trivy-report.json << 'EOF'
{
  "SchemaVersion": 2,
  "ArtifactName": "vulnerable-test-app:latest",
  "ArtifactType": "container_image",
  "Metadata": {
    "ImageID": "sha256:test123",
    "DiffIDs": ["sha256:test456"],
    "RepoTags": ["vulnerable-test-app:latest"]
  },
  "Results": [
    {
      "Target": "ubuntu:20.04",
      "Class": "os-pkgs",
      "Type": "ubuntu",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-44228",
          "PkgName": "log4j-core",
          "Severity": "CRITICAL",
          "Title": "Apache Log4j2 Remote Code Execution Vulnerability",
          "Description": "Apache Log4j2 vulnerable to RCE via LDAP JNDI lookups"
        },
        {
          "VulnerabilityID": "CVE-2022-12345",
          "PkgName": "openssl",
          "Severity": "HIGH", 
          "Title": "OpenSSL vulnerability",
          "Description": "Base image OpenSSL vulnerability"
        },
        {
          "VulnerabilityID": "CVE-2023-67890",
          "PkgName": "libc6",
          "Severity": "MEDIUM",
          "Title": "Glibc vulnerability",
          "Description": "Base image glibc vulnerability"
        }
      ]
    }
  ]
}
EOF

# Create mock Grype report
cat > reports/grype-report.json << 'EOF'
{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2021-44228",
        "severity": "Critical"
      },
      "artifact": {
        "name": "log4j-core",
        "version": "2.14.1"
      }
    },
    {
      "vulnerability": {
        "id": "CVE-2022-11111",
        "severity": "High"
      },
      "artifact": {
        "name": "python3",
        "version": "3.8.10"
      }
    }
  ]
}
EOF

echo "✅ Mock scan reports created"

# Set environment variables for testing
export IMAGE_NAME=vulnerable-test-app
export IMAGE_TAG=latest

# Run the AI analysis pipeline
echo "🧠 Running AI vulnerability analysis..."
python3 scripts/analyze_with_nvidia_ai.py
if [ $? -eq 0 ]; then
    echo "✅ AI analysis completed"
else
    echo "❌ AI analysis failed"
    exit 1
fi

echo "🛠️  Running auto-fix generation..."
python3 scripts/auto_fix.py
if [ $? -eq 0 ]; then
    echo "✅ Auto-fix generation completed"
else
    echo "❌ Auto-fix generation failed"
fi

echo "📊 Running image analysis..."
python3 scripts/image_analysis.py
if [ $? -eq 0 ]; then
    echo "✅ Image analysis completed"
else
    echo "❌ Image analysis failed"
fi

echo "📋 Generating comprehensive report..."
python3 scripts/generate_report.py
if [ $? -eq 0 ]; then
    echo "✅ Report generation completed"
else
    echo "❌ Report generation failed"
fi

# Display results
echo ""
echo "🎉 AI-Powered Vulnerability Analysis Complete!"
echo "=============================================="

if [ -f "ai-analysis-report.json" ]; then
    TOTAL_VULNS=$(python3 -c "import json; data=json.load(open('ai-analysis-report.json')); print(data.get('total_vulnerabilities', 0))")
    REDUCTION=$(python3 -c "import json; data=json.load(open('ai-analysis-report.json')); print(f\"{data.get('reduction_percentage', 0):.1f}%\")")
    echo "📊 Total vulnerabilities found: $TOTAL_VULNS"
    echo "📈 AI noise reduction: $REDUCTION"
fi

if [ -f "fix-recommendations.json" ]; then
    CRITICAL_FIXES=$(python3 -c "import json; data=json.load(open('fix-recommendations.json')); print(data.get('critical_fixes', 0))")
    HIGH_FIXES=$(python3 -c "import json; data=json.load(open('fix-recommendations.json')); print(data.get('high_priority_fixes', 0))")
    echo "🚨 Critical fixes needed: $CRITICAL_FIXES"
    echo "⚠️  High priority fixes: $HIGH_FIXES"
fi

echo ""
echo "📁 Generated Files:"
echo "==================="
for file in *.json *.md *.patch reports/*.json reports/*.txt; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    fi
done

echo ""
echo "🚀 Next Steps:"
echo "=============="
echo "1. Review the security-summary.md report"
echo "2. Check the generated patch files"
echo "3. Set up GitHub Actions by pushing to your repository"
echo "4. Configure GitHub secrets for production use"
echo ""
echo "⚠️  Remember: This test container contains deliberate vulnerabilities!"
echo "   Never use in production environments."
echo ""
echo "🎯 Ready to deploy? Push this code to GitHub and watch the magic happen!" 