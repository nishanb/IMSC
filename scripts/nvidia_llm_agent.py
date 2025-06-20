#!/usr/bin/env python3
"""
NVIDIA LLM Agent for CVE Vulnerability Analysis
Based on the official NVIDIA AI Blueprint approach using LLM agents and RAG
"""

import json
import os
import requests
import numpy as np
from typing import Dict, List, Any, Optional
from datetime import datetime
import hashlib
import time

class NVIDIAVulnerabilityAgent:
    """
    LLM-based vulnerability analysis agent using NVIDIA's approach
    """
    
    def __init__(self):
        self.nvidia_api_key = os.getenv('NVIDIA_API_KEY')
        self.openai_base_url = os.getenv('OPENAI_BASE_URL', 'https://integrate.api.nvidia.com/v1')
        self.model_name = os.getenv('MODEL_NAME', 'meta/llama-3.1-8b-instruct')
        self.max_tokens = int(os.getenv('MAX_TOKENS', '2000'))
        self.cache_dir = "cache"
        self.embedding_cache = {}
        
        # Create cache directory
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # VEX (Vulnerability Exploitability eXchange) status categories
        self.vex_statuses = [
            "not_affected",
            "affected", 
            "fixed",
            "under_investigation",
            "will_not_fix",
            "fix_planned",
            "affected_vulnerable",
            "affected_not_vulnerable",
            "disputed",
            "rejected"
        ]

    def _make_cached_request(self, endpoint: str, payload: Dict) -> Optional[Dict]:
        """Make cached API request to avoid repeated calls"""
        # Create cache key from payload
        cache_key = hashlib.md5(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        cache_file = os.path.join(self.cache_dir, f"{endpoint.replace('/', '_')}_{cache_key}.json")
        
        # Try to load from cache
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Make API request
        if not self.nvidia_api_key:
            print(f"⚠️  No NVIDIA API key found. Skipping {endpoint} request.")
            return None
            
        headers = {
            "Authorization": f"Bearer {self.nvidia_api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                f"{self.openai_base_url}/{endpoint}",
                headers=headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                # Cache the result
                with open(cache_file, 'w') as f:
                    json.dump(result, f, indent=2)
                return result
            else:
                print(f"❌ API request failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error making API request: {e}")
            return None

    def _get_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Get embeddings for text using NVIDIA embedding model"""
        embeddings = []
        
        for text in texts:
            # Check cache first
            text_hash = hashlib.md5(text.encode()).hexdigest()
            if text_hash in self.embedding_cache:
                embeddings.append(self.embedding_cache[text_hash])
                continue
            
            payload = {
                "input": text,
                "model": "nvidia/nv-embedqa-e5-v5",
                "input_type": "query"
            }
            
            result = self._make_cached_request("embeddings", payload)
            if result and 'data' in result and len(result['data']) > 0:
                embedding = result['data'][0]['embedding']
                self.embedding_cache[text_hash] = embedding
                embeddings.append(embedding)
            else:
                # Fallback to random embedding for demo
                embedding = np.random.normal(0, 1, 1024).tolist()
                embeddings.append(embedding)
        
        return embeddings

    def _create_vulnerability_context(self, cve_data: Dict) -> str:
        """Create rich context for vulnerability analysis"""
        cve_id = cve_data.get('VulnerabilityID', 'Unknown')
        pkg_name = cve_data.get('PkgName', 'Unknown')
        severity = cve_data.get('Severity', 'Unknown')
        title = cve_data.get('Title', '')
        description = cve_data.get('Description', '')
        
        context = f"""
CVE ID: {cve_id}
Package: {pkg_name}
Severity: {severity}
Title: {title}
Description: {description}

Additional Context:
- This vulnerability was found in a container image scan
- The package is part of {"base image" if self._is_base_package(pkg_name) else "application dependencies"}
- Scanner: {cve_data.get('scanner', 'Unknown')}
"""
        
        return context.strip()

    def _is_base_package(self, pkg_name: str) -> bool:
        """Determine if package is part of base image"""
        base_packages = [
            'libc6', 'libssl', 'openssl', 'apt', 'dpkg', 'bash', 'coreutils',
            'util-linux', 'glibc', 'zlib', 'libsystemd', 'systemd', 'gcc',
            'binutils', 'perl', 'tzdata', 'ca-certificates'
        ]
        return any(base_pkg in pkg_name.lower() for base_pkg in base_packages)

    def _get_exploitability_prompt(self, cve_context: str) -> str:
        """Create prompt for exploitability analysis"""
        return f"""
You are a cybersecurity expert analyzing container vulnerabilities. Your task is to determine if a CVE represents a real exploitable risk in the context of a containerized application.

CVE Information:
{cve_context}

Analysis Guidelines:
1. Consider the container context - not all CVEs affect containerized applications the same way
2. Base image vulnerabilities are often not exploitable in application context
3. Application-level dependencies pose higher risk
4. Consider attack vectors and accessibility in containers
5. Known exploited CVEs should be flagged as high priority

Please analyze this vulnerability and provide:
1. Exploitability assessment (HIGH/MEDIUM/LOW/NONE)
2. VEX status from: {', '.join(self.vex_statuses)}
3. Reasoning for your assessment
4. Recommended action
5. Confidence level (0.0-1.0)

Respond in JSON format:
{{
    "exploitability": "HIGH|MEDIUM|LOW|NONE",
    "vex_status": "one of the VEX statuses",
    "reasoning": "detailed explanation",
    "recommended_action": "specific action to take",
    "confidence": 0.0-1.0,
    "priority": "CRITICAL|HIGH|MEDIUM|LOW",
    "category": "exploitable_code|potentially_exploitable|base_image_noise|false_positive"
}}
"""

    def analyze_vulnerability(self, cve_data: Dict) -> Dict[str, Any]:
        """Analyze a single vulnerability using LLM agent"""
        
        # Create context for the vulnerability
        context = self._create_vulnerability_context(cve_data)
        
        # Get exploitability analysis prompt
        prompt = self._get_exploitability_prompt(context)
        
        # Make LLM request for analysis
        payload = {
            "model": self.model_name,
            "messages": [
                {
                    "role": "system", 
                    "content": "You are an expert cybersecurity analyst specializing in container vulnerability assessment."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,  # Low temperature for consistent analysis
            "max_tokens": self.max_tokens
        }
        
        result = self._make_cached_request("chat/completions", payload)
        
        if result and 'choices' in result and len(result['choices']) > 0:
            try:
                # Extract JSON response from LLM
                content = result['choices'][0]['message']['content']
                
                # Find JSON in the response
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    json_str = content[json_start:json_end]
                    analysis = json.loads(json_str)
                    
                    # Add metadata
                    analysis['timestamp'] = datetime.now().isoformat()
                    analysis['model_used'] = self.model_name
                    analysis['cve_id'] = cve_data.get('VulnerabilityID', 'Unknown')
                    analysis['package'] = cve_data.get('PkgName', 'Unknown')
                    
                    return analysis
                    
            except json.JSONDecodeError as e:
                print(f"⚠️  Failed to parse LLM response as JSON: {e}")
                print(f"Raw response: {content}")
        
        # Fallback analysis if LLM fails
        return self._fallback_analysis(cve_data)

    def _fallback_analysis(self, cve_data: Dict) -> Dict[str, Any]:
        """Fallback analysis when LLM is unavailable"""
        cve_id = cve_data.get('VulnerabilityID', 'Unknown')
        pkg_name = cve_data.get('PkgName', 'Unknown')
        severity = cve_data.get('Severity', 'Unknown')
        
        # Simple rule-based fallback
        if self._is_base_package(pkg_name):
            category = "base_image_noise"
            priority = "LOW"
            vex_status = "affected_not_vulnerable"
        elif severity in ['CRITICAL', 'HIGH']:
            category = "potentially_exploitable"
            priority = severity
            vex_status = "under_investigation"
        else:
            category = "false_positive"
            priority = "LOW"
            vex_status = "not_affected"
        
        return {
            "exploitability": "LOW",
            "vex_status": vex_status,
            "reasoning": f"Fallback analysis for {pkg_name} - LLM unavailable",
            "recommended_action": "Review manually or re-run with LLM",
            "confidence": 0.5,
            "priority": priority,
            "category": category,
            "timestamp": datetime.now().isoformat(),
            "model_used": "fallback",
            "cve_id": cve_id,
            "package": pkg_name
        }

    def analyze_vulnerabilities_batch(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Analyze multiple vulnerabilities using LLM agents"""
        
        print(f"🧠 Starting NVIDIA LLM Agent Analysis for {len(vulnerabilities)} vulnerabilities...")
        
        categorized_results = {
            'exploitable_code': [],
            'potentially_exploitable': [],
            'base_image_noise': [],
            'false_positive': []
        }
        
        analysis_details = []
        
        # Process vulnerabilities with rate limiting
        for i, vuln in enumerate(vulnerabilities):
            print(f"Analyzing {i+1}/{len(vulnerabilities)}: {vuln.get('VulnerabilityID', 'Unknown')}")
            
            # Analyze individual vulnerability
            analysis = self.analyze_vulnerability(vuln)
            
            # Add analysis to vulnerability data
            vuln['llm_analysis'] = analysis
            
            # Categorize based on LLM analysis
            category = analysis.get('category', 'false_positive')
            categorized_results[category].append(vuln)
            
            analysis_details.append(analysis)
            
            # Rate limiting - small delay between requests
            time.sleep(0.1)
        
        # Generate summary statistics
        total_analyzed = len(vulnerabilities)
        noise_count = len(categorized_results['base_image_noise']) + len(categorized_results['false_positive'])
        noise_reduction_percentage = (noise_count / total_analyzed * 100) if total_analyzed > 0 else 0
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': total_analyzed,
            'llm_categorization': {
                'exploitable_code': len(categorized_results['exploitable_code']),
                'potentially_exploitable': len(categorized_results['potentially_exploitable']),
                'base_image_noise': len(categorized_results['base_image_noise']),
                'false_positive': len(categorized_results['false_positive'])
            },
            'noise_reduction_percentage': round(noise_reduction_percentage, 2),
            'detailed_analysis': categorized_results,
            'analysis_details': analysis_details,
            'model_used': self.model_name,
            'api_endpoint': self.openai_base_url
        }
        
        print(f"✅ LLM Analysis Complete!")
        print(f"📈 Noise Reduction: {noise_reduction_percentage:.1f}%")
        print(f"🚨 Exploitable: {len(categorized_results['exploitable_code'])}")
        print(f"⚠️  Potentially Exploitable: {len(categorized_results['potentially_exploitable'])}")
        print(f"📦 Base Image Noise: {len(categorized_results['base_image_noise'])}")
        print(f"❌ False Positives: {len(categorized_results['false_positive'])}")
        
        return summary

def main():
    """Main execution function"""
    print("🚀 Starting NVIDIA LLM Agent CVE Analysis...")
    
    # Initialize the LLM agent
    agent = NVIDIAVulnerabilityAgent()
    
    # Load scan results (same as before)
    scan_results = {}
    
    # Load Trivy results
    trivy_path = 'reports/trivy-report.json'
    if os.path.exists(trivy_path):
        with open(trivy_path, 'r') as f:
            scan_results['trivy'] = json.load(f)
    
    # Load Grype results
    grype_path = 'reports/grype-report.json'
    if os.path.exists(grype_path):
        with open(grype_path, 'r') as f:
            scan_results['grype'] = json.load(f)
    
    # Extract vulnerabilities
    vulnerabilities = []
    
    # Extract from Trivy
    if 'trivy' in scan_results:
        trivy_data = scan_results['trivy']
        if 'Results' in trivy_data:
            for result in trivy_data['Results']:
                if 'Vulnerabilities' in result:
                    for vuln in result['Vulnerabilities']:
                        vuln['scanner'] = 'trivy'
                        vulnerabilities.append(vuln)
    
    # Extract from Grype
    if 'grype' in scan_results:
        grype_data = scan_results['grype']
        if 'matches' in grype_data:
            for match in grype_data['matches']:
                vuln = {
                    'scanner': 'grype',
                    'VulnerabilityID': match.get('vulnerability', {}).get('id'),
                    'Severity': match.get('vulnerability', {}).get('severity'),
                    'PkgName': match.get('artifact', {}).get('name'),
                    'Title': match.get('vulnerability', {}).get('description', ''),
                    'Description': match.get('vulnerability', {}).get('description', ''),
                    'vulnerability': match.get('vulnerability', {}),
                    'artifact': match.get('artifact', {})
                }
                vulnerabilities.append(vuln)
    
    if not vulnerabilities:
        print("ℹ️  No vulnerabilities found to analyze")
        return
    
    # Analyze vulnerabilities using LLM agents
    analysis_results = agent.analyze_vulnerabilities_batch(vulnerabilities)
    
    # Save results
    with open('nvidia-llm-analysis-report.json', 'w') as f:
        json.dump(analysis_results, f, indent=2)
    
    # Save critical vulnerabilities for pipeline decision
    critical_vulns = {
        'critical_count': len([
            v for v in analysis_results['detailed_analysis']['exploitable_code'] 
            if v.get('llm_analysis', {}).get('priority') == 'CRITICAL'
        ]),
        'high_priority_count': len([
            v for v in analysis_results['detailed_analysis']['exploitable_code'] + 
                      analysis_results['detailed_analysis']['potentially_exploitable']
            if v.get('llm_analysis', {}).get('priority') in ['CRITICAL', 'HIGH']
        ])
    }
    
    os.makedirs('reports', exist_ok=True)
    with open('reports/critical-vulns.json', 'w') as f:
        json.dump(critical_vulns, f, indent=2)
    
    print(f"🚨 Critical Issues: {critical_vulns['critical_count']}")
    print(f"⚠️  High Priority Issues: {critical_vulns['high_priority_count']}")

if __name__ == "__main__":
    main() 