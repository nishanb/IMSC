#!/usr/bin/env python3
"""
AI-Powered CVE Analysis using NVIDIA Morpheus (Simulated)
Differentiates between exploitable code vulnerabilities and base image false positives
"""

import json
import os
import requests
from typing import Dict, List, Any
import time
from datetime import datetime

def load_scan_results() -> Dict[str, Any]:
    """Load vulnerability scan results from Trivy and Grype"""
    results = {
        'trivy': {},
        'grype': {}
    }
    
    # Load Trivy results
    trivy_path = 'reports/trivy-report.json'
    if os.path.exists(trivy_path):
        with open(trivy_path, 'r') as f:
            results['trivy'] = json.load(f)
    
    # Load Grype results  
    grype_path = 'reports/grype-report.json'
    if os.path.exists(grype_path):
        with open(grype_path, 'r') as f:
            results['grype'] = json.load(f)
    
    return results

def simulate_nvidia_ai_analysis(vulnerabilities: List[Dict]) -> Dict[str, Any]:
    """
    Simulate NVIDIA Morpheus AI analysis for CVE contextualization
    In a real implementation, this would call NVIDIA's CVE analysis API
    """
    print("🧠 Simulating NVIDIA AI CVE Analysis...")
    
    # Simulate AI processing time
    time.sleep(2)
    
    categorized_vulns = {
        'exploitable_code': [],
        'base_image_noise': [],
        'potentially_exploitable': [],
        'false_positives': []
    }
    
    # AI simulation logic based on common patterns
    for vuln in vulnerabilities:
        cve_id = vuln.get('VulnerabilityID', vuln.get('vulnerability', {}).get('id', 'UNKNOWN'))
        severity = vuln.get('Severity', vuln.get('vulnerability', {}).get('severity', 'UNKNOWN'))
        pkg_name = vuln.get('PkgName', vuln.get('artifact', {}).get('name', 'UNKNOWN'))
        
        # AI decision logic (simplified simulation)
        ai_decision = analyze_vulnerability_with_ai(cve_id, severity, pkg_name, vuln)
        
        category = ai_decision['category']
        vuln['ai_analysis'] = ai_decision
        
        categorized_vulns[category].append(vuln)
    
    return categorized_vulns

def analyze_vulnerability_with_ai(cve_id: str, severity: str, pkg_name: str, vuln_data: Dict) -> Dict[str, Any]:
    """
    Simulate AI-based vulnerability analysis
    """
    # Simulate AI confidence scoring
    confidence_score = 0.85
    
    # Base image packages (common false positives)
    base_image_packages = [
        'libc6', 'libssl', 'openssl', 'apt', 'dpkg', 'bash', 'coreutils',
        'util-linux', 'glibc', 'zlib', 'libsystemd', 'systemd'
    ]
    
    # Application packages (more likely to be exploitable)
    app_packages = [
        'nodejs', 'python', 'pip', 'npm', 'flask', 'django', 'express',
        'react', 'vue', 'angular', 'spring', 'hibernate'
    ]
    
    # Critical CVEs that are known to be actively exploited
    known_exploited = [
        'CVE-2021-44228',  # Log4j
        'CVE-2021-45046',  # Log4j
        'CVE-2022-22965',  # Spring4Shell
        'CVE-2021-34527',  # PrintNightmare
    ]
    
    # AI decision logic
    if cve_id in known_exploited:
        return {
            'category': 'exploitable_code',
            'confidence': 0.95,
            'reasoning': f'Known actively exploited CVE: {cve_id}',
            'priority': 'CRITICAL',
            'recommended_action': 'Immediate patching required'
        }
    
    if any(pkg in pkg_name.lower() for pkg in app_packages):
        if severity in ['CRITICAL', 'HIGH']:
            return {
                'category': 'potentially_exploitable',
                'confidence': 0.80,
                'reasoning': f'Application dependency {pkg_name} with {severity} severity',
                'priority': 'HIGH',
                'recommended_action': 'Review and patch within 48 hours'
            }
        else:
            return {
                'category': 'exploitable_code',
                'confidence': 0.70,
                'reasoning': f'Application dependency vulnerability in {pkg_name}',
                'priority': 'MEDIUM',
                'recommended_action': 'Schedule patching in next release cycle'
            }
    
    if any(pkg in pkg_name.lower() for pkg in base_image_packages):
        return {
            'category': 'base_image_noise',
            'confidence': 0.75,
            'reasoning': f'Base image package {pkg_name} - likely false positive',
            'priority': 'LOW',
            'recommended_action': 'Update base image when convenient'
        }
    
    # Default case
    return {
        'category': 'false_positives',
        'confidence': 0.60,
        'reasoning': f'Insufficient context for {pkg_name}',
        'priority': 'LOW',
        'recommended_action': 'Monitor for exploit development'
    }

def call_nvidia_api(vulns: List[Dict]) -> Dict[str, Any]:
    """
    Placeholder for actual NVIDIA API call
    """
    api_key = os.getenv('NVIDIA_API_KEY')
    
    if not api_key:
        print("⚠️  NVIDIA_API_KEY not found, using simulation mode")
        return simulate_nvidia_ai_analysis(vulns)
    
    # In a real implementation, this would make actual API calls to NVIDIA
    print("🌐 NVIDIA API key found, but using simulation for demo")
    return simulate_nvidia_ai_analysis(vulns)

def extract_vulnerabilities(scan_results: Dict[str, Any]) -> List[Dict]:
    """Extract vulnerabilities from scan results"""
    all_vulns = []
    
    # Extract from Trivy results
    if 'trivy' in scan_results and scan_results['trivy']:
        trivy_data = scan_results['trivy']
        if 'Results' in trivy_data:
            for result in trivy_data['Results']:
                if 'Vulnerabilities' in result:
                    for vuln in result['Vulnerabilities']:
                        vuln['scanner'] = 'trivy'
                        all_vulns.append(vuln)
    
    # Extract from Grype results
    if 'grype' in scan_results and scan_results['grype']:
        grype_data = scan_results['grype']
        if 'matches' in grype_data:
            for match in grype_data['matches']:
                vuln = {
                    'scanner': 'grype',
                    'VulnerabilityID': match.get('vulnerability', {}).get('id'),
                    'Severity': match.get('vulnerability', {}).get('severity'),
                    'PkgName': match.get('artifact', {}).get('name'),
                    'vulnerability': match.get('vulnerability', {}),
                    'artifact': match.get('artifact', {})
                }
                all_vulns.append(vuln)
    
    return all_vulns

def main():
    """Main execution function"""
    print("🚀 Starting AI-Powered CVE Analysis...")
    
    # Load scan results
    scan_results = load_scan_results()
    
    # Extract all vulnerabilities
    vulnerabilities = extract_vulnerabilities(scan_results)
    
    print(f"📊 Found {len(vulnerabilities)} total vulnerabilities")
    
    if not vulnerabilities:
        print("ℹ️  No vulnerabilities found to analyze")
        return
    
    # Perform AI analysis
    ai_results = call_nvidia_api(vulnerabilities)
    
    # Generate analysis report
    analysis_report = {
        'timestamp': datetime.now().isoformat(),
        'total_vulnerabilities': len(vulnerabilities),
        'ai_categorization': {
            'exploitable_code': len(ai_results['exploitable_code']),
            'potentially_exploitable': len(ai_results['potentially_exploitable']),
            'base_image_noise': len(ai_results['base_image_noise']),
            'false_positives': len(ai_results['false_positives'])
        },
        'detailed_analysis': ai_results,
        'reduction_percentage': round((len(ai_results['base_image_noise']) + len(ai_results['false_positives'])) / len(vulnerabilities) * 100, 2)
    }
    
    # Save results
    with open('ai-analysis-report.json', 'w') as f:
        json.dump(analysis_report, f, indent=2)
    
    # Save critical vulnerabilities for pipeline decision
    critical_vulns = {
        'critical_count': len([v for v in ai_results['exploitable_code'] if v.get('ai_analysis', {}).get('priority') == 'CRITICAL']),
        'high_priority_count': len([v for v in ai_results['exploitable_code'] + ai_results['potentially_exploitable'] if v.get('ai_analysis', {}).get('priority') in ['CRITICAL', 'HIGH']])
    }
    
    os.makedirs('reports', exist_ok=True)
    with open('reports/critical-vulns.json', 'w') as f:
        json.dump(critical_vulns, f, indent=2)
    
    print("✅ AI Analysis Complete!")
    print(f"📈 Noise Reduction: {analysis_report['reduction_percentage']}%")
    print(f"🚨 Critical Issues: {critical_vulns['critical_count']}")
    print(f"⚠️  High Priority Issues: {critical_vulns['high_priority_count']}")

if __name__ == "__main__":
    main() 