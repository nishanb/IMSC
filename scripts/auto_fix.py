#!/usr/bin/env python3
"""
Auto-Fix Recommendations Generator
Generates automated fix suggestions based on AI vulnerability analysis
"""

import json
import os
from typing import Dict, List, Any
from datetime import datetime

def load_ai_analysis() -> Dict[str, Any]:
    """Load AI analysis results"""
    if os.path.exists('ai-analysis-report.json'):
        with open('ai-analysis-report.json', 'r') as f:
            return json.load(f)
    return {}

def generate_dockerfile_fixes(vulnerabilities: List[Dict]) -> List[str]:
    """Generate Dockerfile fix recommendations"""
    fixes = []
    
    # Base image recommendations
    base_image_vulns = [v for v in vulnerabilities if 'base' in v.get('ai_analysis', {}).get('reasoning', '').lower()]
    
    if base_image_vulns:
        fixes.append("# Update base image to latest secure version")
        fixes.append("# Consider using distroless or alpine images for smaller attack surface")
        fixes.append("FROM node:18-alpine  # Instead of ubuntu:20.04")
        fixes.append("")
    
    # Package update recommendations
    fixes.append("# Update all packages to latest versions")
    fixes.append("RUN apt-get update && apt-get upgrade -y \\")
    fixes.append("    && apt-get clean \\")
    fixes.append("    && rm -rf /var/lib/apt/lists/*")
    fixes.append("")
    
    # Security hardening
    fixes.append("# Security hardening")
    fixes.append("RUN useradd -m -u 1000 appuser")
    fixes.append("USER appuser")
    fixes.append("")
    
    return fixes

def generate_dependency_fixes(vulnerabilities: List[Dict]) -> Dict[str, List[str]]:
    """Generate dependency fix recommendations"""
    fixes = {
        'package.json': [],
        'requirements.txt': [],
        'pom.xml': [],
        'general': []
    }
    
    for vuln in vulnerabilities:
        pkg_name = vuln.get('PkgName', vuln.get('artifact', {}).get('name', ''))
        ai_analysis = vuln.get('ai_analysis', {})
        
        if ai_analysis.get('priority') in ['CRITICAL', 'HIGH']:
            if 'node' in pkg_name.lower() or 'npm' in pkg_name.lower():
                fixes['package.json'].append(f"# Update {pkg_name} to latest secure version")
                fixes['package.json'].append(f"# Run: npm audit fix --force")
                
            elif 'python' in pkg_name.lower() or 'pip' in pkg_name.lower():
                fixes['requirements.txt'].append(f"# Update {pkg_name} to latest secure version")
                fixes['requirements.txt'].append(f"# Run: pip install --upgrade {pkg_name}")
                
            elif 'java' in pkg_name.lower() or 'maven' in pkg_name.lower():
                fixes['pom.xml'].append(f"<!-- Update {pkg_name} to latest secure version -->")
                fixes['pom.xml'].append(f"<!-- Check Maven security updates -->")
    
    return fixes

def generate_security_patches() -> List[str]:
    """Generate general security patch recommendations"""
    patches = [
        "# Security Configuration Recommendations",
        "",
        "## 1. Environment Hardening",
        "- Remove unnecessary packages and services",
        "- Use minimal base images (alpine, distroless)",
        "- Implement proper user permissions",
        "",
        "## 2. Runtime Security",
        "- Enable read-only root filesystem",
        "- Drop unnecessary capabilities",
        "- Use security contexts in Kubernetes",
        "",
        "## 3. Network Security", 
        "- Limit network access to required ports only",
        "- Use service mesh for internal communication",
        "- Implement proper firewall rules",
        "",
        "## 4. Monitoring & Logging",
        "- Enable comprehensive logging",
        "- Set up security monitoring alerts",
        "- Implement intrusion detection",
    ]
    
    return patches

def create_patch_files(ai_analysis: Dict[str, Any]) -> None:
    """Create patch files for different vulnerability categories"""
    
    if not ai_analysis:
        print("⚠️  No AI analysis data found")
        return
    
    detailed_analysis = ai_analysis.get('detailed_analysis', {})
    
    # Get high priority vulnerabilities
    exploitable = detailed_analysis.get('exploitable_code', [])
    potentially_exploitable = detailed_analysis.get('potentially_exploitable', [])
    
    high_priority_vulns = [
        v for v in exploitable + potentially_exploitable 
        if v.get('ai_analysis', {}).get('priority') in ['CRITICAL', 'HIGH']
    ]
    
    if not high_priority_vulns:
        print("✅ No high priority vulnerabilities found")
        return
    
    # Generate Dockerfile fixes
    dockerfile_fixes = generate_dockerfile_fixes(high_priority_vulns)
    with open('Dockerfile.patch', 'w') as f:
        f.write('\n'.join(dockerfile_fixes))
    
    # Generate dependency fixes
    dependency_fixes = generate_dependency_fixes(high_priority_vulns)
    
    # Create dependency fix files
    for file_type, fixes in dependency_fixes.items():
        if fixes and file_type != 'general':
            with open(f'{file_type}.patch', 'w') as f:
                f.write('\n'.join(fixes))
    
    # Generate security patches
    security_patches = generate_security_patches()
    with open('security-recommendations.md', 'w') as f:
        f.write('\n'.join(security_patches))

def generate_fix_summary(ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a summary of all recommended fixes"""
    
    if not ai_analysis:
        return {}
    
    detailed_analysis = ai_analysis.get('detailed_analysis', {})
    
    summary = {
        'timestamp': datetime.now().isoformat(),
        'total_fixes_recommended': 0,
        'critical_fixes': 0,
        'high_priority_fixes': 0,
        'automated_fixes': [],
        'manual_review_required': [],
        'fix_categories': {
            'dockerfile': 0,
            'dependencies': 0,
            'configuration': 0,
            'base_image': 0
        }
    }
    
    # Analyze each vulnerability category
    for category, vulns in detailed_analysis.items():
        for vuln in vulns:
            ai_analysis_data = vuln.get('ai_analysis', {})
            priority = ai_analysis_data.get('priority', 'LOW')
            action = ai_analysis_data.get('recommended_action', '')
            
            if priority == 'CRITICAL':
                summary['critical_fixes'] += 1
                summary['manual_review_required'].append({
                    'vuln_id': vuln.get('VulnerabilityID', 'UNKNOWN'),
                    'package': vuln.get('PkgName', 'UNKNOWN'),
                    'action': action
                })
            elif priority == 'HIGH':
                summary['high_priority_fixes'] += 1
                summary['automated_fixes'].append({
                    'vuln_id': vuln.get('VulnerabilityID', 'UNKNOWN'),
                    'package': vuln.get('PkgName', 'UNKNOWN'),
                    'action': action
                })
            
            # Categorize fix types
            pkg_name = vuln.get('PkgName', '').lower()
            if any(base_pkg in pkg_name for base_pkg in ['libc', 'glibc', 'apt', 'dpkg']):
                summary['fix_categories']['base_image'] += 1
            elif any(app_pkg in pkg_name for app_pkg in ['node', 'python', 'npm', 'pip']):
                summary['fix_categories']['dependencies'] += 1
            else:
                summary['fix_categories']['configuration'] += 1
    
    summary['total_fixes_recommended'] = summary['critical_fixes'] + summary['high_priority_fixes']
    
    return summary

def main():
    """Main execution function"""
    print("🛠️  Starting Auto-Fix Generation...")
    
    # Load AI analysis results
    ai_analysis = load_ai_analysis()
    
    if not ai_analysis:
        print("❌ No AI analysis results found. Run analyze_with_nvidia_ai.py first.")
        return
    
    # Create patch files
    create_patch_files(ai_analysis)
    
    # Generate fix summary
    fix_summary = generate_fix_summary(ai_analysis)
    
    # Save fix summary
    with open('fix-recommendations.json', 'w') as f:
        json.dump(fix_summary, f, indent=2)
    
    # Display summary
    print(f"✅ Auto-Fix Generation Complete!")
    print(f"🚨 Critical Fixes: {fix_summary.get('critical_fixes', 0)}")
    print(f"⚠️  High Priority Fixes: {fix_summary.get('high_priority_fixes', 0)}")
    print(f"🤖 Automated Fixes: {len(fix_summary.get('automated_fixes', []))}")
    print(f"👁️  Manual Review Required: {len(fix_summary.get('manual_review_required', []))}")
    
    # List generated files
    generated_files = []
    for filename in ['Dockerfile.patch', 'package.json.patch', 'requirements.txt.patch', 
                     'pom.xml.patch', 'security-recommendations.md', 'fix-recommendations.json']:
        if os.path.exists(filename):
            generated_files.append(filename)
    
    if generated_files:
        print(f"📁 Generated fix files: {', '.join(generated_files)}")

if __name__ == "__main__":
    main() 