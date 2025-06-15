#!/usr/bin/env python3
"""
NVIDIA LLM Agent for CVE Vulnerability Analysis
Based on the official NVIDIA AI Blueprint using LLM agents and RAG
Reference: https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis
"""

import json
import os
import requests
import numpy as np
from typing import Dict, List, Any, Optional
import time
import hashlib
from datetime import datetime
import faiss
import pandas as pd
from dotenv import load_dotenv
import glob
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

class VulnerabilityAnalyzer:
    def __init__(self):
        """Initialize the vulnerability analyzer with NVIDIA AI integration."""
        load_dotenv()
        
        # Initialize NVIDIA API configuration
        self.nvidia_api_key = os.getenv('NVIDIA_API_KEY')
        if not self.nvidia_api_key:
            raise ValueError("NVIDIA_API_KEY environment variable is not set")
            
        # Initialize vector database
        self.vector_dimension = 1024  # Dimension for NVIDIA's embedding model
        self.index = faiss.IndexFlatL2(self.vector_dimension)
        self.code_files = []
        
        # Initialize code context
        self._initialize_code_context()

    def _get_embedding(self, text: str) -> np.ndarray:
        """Get embedding from NVIDIA's NIM service."""
        url = "https://api.nvcf.nvidia.com/v2/nvcf/pexec/functions/8f4118ba-60a8-4e6b-8574-e38a4067a4a3"
        headers = {
            "Authorization": f"Bearer {self.nvidia_api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "nvidia/nv-embedqa-e5-v5",
            "input": text,
            "truncate": "END",
            "max_batch_size": 128
        }
        
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            return np.array(response.json()["embedding"])
        else:
            raise Exception(f"Failed to get embedding: {response.text}")

    def _initialize_code_context(self):
        """Initialize code context by processing relevant code files."""
        code_extensions = ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php']
        
        for ext in code_extensions:
            for file_path in glob.glob(f"**/*{ext}", recursive=True):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    # Create document with metadata
                    doc = {
                        'content': content,
                        'file_path': file_path,
                        'type': 'code'
                    }
                    
                    # Get embedding
                    embedding = self._get_embedding(content)
                    
                    # Add to vector store
                    self.index.add(np.array([embedding]))
                    self.code_files.append(doc)
                    
                except Exception as e:
                    logger.warning(f"Error processing {file_path}: {e}")
        
        logger.info(f"Processed {len(self.code_files)} files for code context")

    def _get_relevant_code_context(self, query: str, k: int = 3) -> List[Dict]:
        """Get relevant code context based on semantic similarity."""
        query_embedding = self._get_embedding(query)
        distances, indices = self.index.search(np.array([query_embedding]), k)
        
        relevant_docs = []
        for idx in indices[0]:
            if idx < len(self.code_files):
                relevant_docs.append(self.code_files[idx])
        
        return relevant_docs

    def _create_vulnerability_context(self, cve_data: Dict) -> str:
        """Create rich context for vulnerability analysis"""
        cve_id = cve_data.get('VulnerabilityID', cve_data.get('vulnerability', {}).get('id', 'Unknown'))
        pkg_name = cve_data.get('PkgName', cve_data.get('artifact', {}).get('name', 'Unknown'))
        severity = cve_data.get('Severity', cve_data.get('vulnerability', {}).get('severity', 'Unknown'))
        title = cve_data.get('Title', '')
        description = cve_data.get('Description', '')
        
        # Get relevant code context
        query = f"{title} {description} {pkg_name}"
        relevant_code = self._get_relevant_code_context(query)
        
        # Create checklist items based on NVIDIA's approach
        checklist = [
            "Is this vulnerability present in the running code?",
            "Is the vulnerable package directly used by the application?",
            "Are there any mitigating factors or workarounds?",
            "What is the potential impact on the container?",
            "Is this a false positive in the container context?"
        ]
        
        # Format code context
        code_context = ""
        if relevant_code:
            code_context = "\nRelevant Code Context:\n"
            for doc in relevant_code:
                code_context += f"\nFile: {doc['file_path']}\n"
                # Extract relevant lines (first 10 lines for brevity)
                lines = doc['content'].split('\n')[:10]
                code_context += '\n'.join(lines) + "\n"
        
        context = f"""
CVE Analysis Checklist for {cve_id}:

Vulnerability Details:
- Package: {pkg_name}
- Severity: {severity}
- Title: {title}
- Description: {description}

{code_context}

Analysis Checklist:
{chr(10).join(f"- {item}" for item in checklist)}

Additional Context:
- This vulnerability was found in a container image scan
- The package is part of {"base image" if self._is_base_package(pkg_name) else "application dependencies"}
- Scanner: {cve_data.get('scanner', 'Unknown')}
"""
        return context.strip()

    def _get_exploitability_prompt(self, cve_context: str) -> str:
        """Create prompt for exploitability analysis based on NVIDIA blueprint"""
        return f"""
You are a cybersecurity expert analyzing container vulnerabilities. Your task is to evaluate each item in the checklist and provide a detailed analysis.

{cve_context}

For each checklist item, provide:
1. A clear yes/no answer
2. Detailed reasoning for your answer
3. Supporting evidence or context
4. Confidence level (High/Medium/Low)

Format your response as a JSON object with the following structure:
{{
    "checklist_analysis": [
        {{
            "question": "question text",
            "answer": "yes/no",
            "reasoning": "detailed explanation",
            "evidence": "supporting evidence",
            "confidence": "High/Medium/Low"
        }}
    ],
    "overall_assessment": {{
        "exploitability": "High/Medium/Low",
        "risk_level": "Critical/High/Medium/Low",
        "recommendation": "detailed recommendation",
        "mitigation_steps": ["step1", "step2", ...]
    }}
}}
"""

    def _make_cached_request(self, endpoint: str, payload: Dict) -> Optional[Dict]:
        """Make cached API request to avoid repeated calls"""
        cache_key = hashlib.md5(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        cache_file = os.path.join("cache", f"{endpoint.replace('/', '_')}_{cache_key}.json")
        
        # Try to load from cache
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Make API request
        if not self.nvidia_api_key:
            print(f"⚠️  No NVIDIA API key found. Using fallback analysis.")
            return None
            
        headers = {
            "Authorization": f"Bearer {self.nvidia_api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            url = 'https://api.nvcf.nvidia.com/v2/nvcf/pexec/functions/8f4118ba-60a8-4e6b-8574-e38a4067a4a3'
            print(f"🌐 Making request to: {url}")
            print(f"📦 Request payload: {json.dumps(payload, indent=2)}")
            
            response = requests.post(
                url,
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
                print(f"❌ API request failed: {response.status_code}")
                print(f"📄 Response headers: {dict(response.headers)}")
                try:
                    print(f"📄 Response body: {response.text}")
                except:
                    print("📄 Could not read response body")
                return None
                
        except Exception as e:
            print(f"❌ Error making API request: {e}")
            return None

    def analyze_vulnerability(self, cve_data: Dict) -> Dict[str, Any]:
        """Analyze a single vulnerability using the NVIDIA approach"""
        # Create rich context
        context = self._create_vulnerability_context(cve_data)
        
        # Get analysis prompt
        prompt = self._get_exploitability_prompt(context)
        
        # Make LLM request
        payload = {
            "model": "nvidia/llama-2-70b-chat",
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
            "temperature": 0.1,
            "max_tokens": 2000
        }
        
        result = self._make_cached_request("chat/completions", payload)
        
        if result and 'choices' in result and len(result['choices']) > 0:
            try:
                content = result['choices'][0]['message']['content']
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    json_str = content[json_start:json_end]
                    analysis = json.loads(json_str)
                    
                    # Add metadata
                    analysis['timestamp'] = datetime.now().isoformat()
                    analysis['model_used'] = "nvidia/llama-2-70b-chat"
                    analysis['cve_id'] = cve_data.get('VulnerabilityID', 'Unknown')
                    analysis['package'] = cve_data.get('PkgName', 'Unknown')
                    
                    return analysis
                    
            except json.JSONDecodeError as e:
                print(f"⚠️  Failed to parse LLM response as JSON: {e}")
        
        return self._fallback_analysis(cve_data)

    def _fallback_analysis(self, cve_data: Dict) -> Dict[str, Any]:
        """Fallback analysis when LLM is unavailable"""
        pkg_name = cve_data.get('PkgName', 'Unknown')
        severity = cve_data.get('Severity', 'Unknown')
        
        return {
            "checklist_analysis": [
                {
                    "question": "Is this vulnerability present in the running code?",
                    "answer": "unknown",
                    "reasoning": "LLM analysis unavailable",
                    "evidence": "Fallback analysis",
                    "confidence": "Low"
                }
            ],
            "overall_assessment": {
                "exploitability": "Unknown",
                "risk_level": severity,
                "recommendation": "Manual review required",
                "mitigation_steps": ["Review vulnerability details", "Assess package usage"]
            },
            "timestamp": datetime.now().isoformat(),
            "model_used": "fallback",
            "cve_id": cve_data.get('VulnerabilityID', 'Unknown'),
            "package": pkg_name
        }

    def _is_base_package(self, pkg_name: str) -> bool:
        """Determine if package is part of base image"""
        base_packages = [
            'libc6', 'libssl', 'openssl', 'apt', 'dpkg', 'bash', 'coreutils',
            'util-linux', 'glibc', 'zlib', 'libsystemd', 'systemd', 'gcc',
            'binutils', 'perl', 'tzdata', 'ca-certificates'
        ]
        return any(base_pkg in pkg_name.lower() for base_pkg in base_packages)

def main():
    """Main function to run vulnerability analysis"""
    # Load scan results
    scan_results = load_scan_results()
    
    # Initialize analyzer
    analyzer = VulnerabilityAnalyzer()
    
    # Extract vulnerabilities
    vulnerabilities = []
    for scanner, results in scan_results.items():
        if scanner == 'trivy':
            for result in results.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    vuln['scanner'] = 'trivy'
                    vulnerabilities.append(vuln)
        elif scanner == 'grype':
            for match in results.get('matches', []):
                vuln = match.get('vulnerability', {})
                vuln['scanner'] = 'grype'
                vulnerabilities.append(vuln)
    
    print(f"🔍 Found {len(vulnerabilities)} vulnerabilities to analyze")
    
    # Analyze vulnerabilities
    analysis_results = []
    for i, vuln in enumerate(vulnerabilities):
        print(f"Analyzing {i+1}/{len(vulnerabilities)}: {vuln.get('VulnerabilityID', 'Unknown')}")
        analysis = analyzer.analyze_vulnerability(vuln)
        analysis_results.append(analysis)
    
    # Save results
    output = {
        'timestamp': datetime.now().isoformat(),
        'total_vulnerabilities': len(vulnerabilities),
        'analysis_results': analysis_results
    }
    
    with open('nvidia-llm-analysis-report.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print("✅ Analysis complete! Results saved to nvidia-llm-analysis-report.json")

if __name__ == "__main__":
    main() 