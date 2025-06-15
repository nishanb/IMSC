#!/usr/bin/env python3
"""
Docker Image Analysis and Slimming Simulation
Analyzes image layers and simulates size optimization
"""

import json
import subprocess
import os
from typing import Dict, List, Any
from datetime import datetime

def get_image_info(image_name: str) -> Dict[str, Any]:
    """Get detailed information about the Docker image"""
    try:
        # Get image size
        size_result = subprocess.run(
            ['docker', 'images', '--format', 'table {{.Size}}', image_name],
            capture_output=True, text=True, check=True
        )
        size = size_result.stdout.strip().split('\n')[1] if len(size_result.stdout.strip().split('\n')) > 1 else "Unknown"
        
        # Get image history (layers)
        history_result = subprocess.run(
            ['docker', 'history', '--format', 'json', image_name],
            capture_output=True, text=True, check=True
        )
        
        layers = []
        for line in history_result.stdout.strip().split('\n'):
            if line:
                layer = json.loads(line)
                layers.append(layer)
        
        # Get image inspection details
        inspect_result = subprocess.run(
            ['docker', 'inspect', image_name],
            capture_output=True, text=True, check=True
        )
        inspect_data = json.loads(inspect_result.stdout)[0]
        
        return {
            'name': image_name,
            'size': size,
            'layers': layers,
            'config': inspect_data.get('Config', {}),
            'architecture': inspect_data.get('Architecture', 'unknown'),
            'os': inspect_data.get('Os', 'unknown'),
            'created': inspect_data.get('Created', ''),
            'total_layers': len(layers)
        }
        
    except subprocess.CalledProcessError as e:
        print(f"Error analyzing image {image_name}: {e}")
        return {}
    except Exception as e:
        print(f"Unexpected error: {e}")
        return {}

def analyze_layers(layers: List[Dict]) -> Dict[str, Any]:
    """Analyze image layers for optimization opportunities"""
    analysis = {
        'total_layers': len(layers),
        'large_layers': [],
        'redundant_commands': [],
        'optimization_opportunities': []
    }
    
    for i, layer in enumerate(layers):
        size_str = layer.get('Size', '0')
        created_by = layer.get('CreatedBy', '')
        
        # Convert size to bytes for comparison
        size_bytes = parse_size_to_bytes(size_str)
        
        # Flag large layers (> 50MB)
        if size_bytes > 50 * 1024 * 1024:
            analysis['large_layers'].append({
                'layer_index': i,
                'size': size_str,
                'command': created_by[:100] + "..." if len(created_by) > 100 else created_by
            })
        
        # Look for optimization opportunities
        if 'apt-get update' in created_by and 'apt-get clean' not in created_by:
            analysis['optimization_opportunities'].append({
                'type': 'package_cache',
                'layer_index': i,
                'suggestion': 'Combine apt-get update, install, and clean in single RUN command'
            })
        
        if 'RUN pip install' in created_by and '--no-cache-dir' not in created_by:
            analysis['optimization_opportunities'].append({
                'type': 'pip_cache',
                'layer_index': i,
                'suggestion': 'Use --no-cache-dir flag with pip install'
            })
    
    return analysis

def parse_size_to_bytes(size_str: str) -> int:
    """Convert size string to bytes"""
    if not size_str or size_str == '0':
        return 0
    
    try:
        # Remove any whitespace and convert to uppercase
        size_str = size_str.strip().upper()
        
        # Handle different size formats
        if size_str.endswith('B'):
            return int(float(size_str[:-1]))
        elif size_str.endswith('K'):
            return int(float(size_str[:-1]) * 1024)
        elif size_str.endswith('KB'):
            return int(float(size_str[:-2]) * 1024)
        elif size_str.endswith('M'):
            return int(float(size_str[:-1]) * 1024 * 1024)
        elif size_str.endswith('MB'):
            return int(float(size_str[:-2]) * 1024 * 1024)
        elif size_str.endswith('G'):
            return int(float(size_str[:-1]) * 1024 * 1024 * 1024)
        elif size_str.endswith('GB'):
            return int(float(size_str[:-2]) * 1024 * 1024 * 1024)
        else:
            # Try to parse as a plain number
            return int(float(size_str))
    except (ValueError, TypeError):
        print(f"Warning: Could not parse size string: {size_str}")
        return 0

def simulate_slimming(image_info: Dict[str, Any]) -> Dict[str, Any]:
    """Simulate image slimming benefits"""
    original_size_bytes = parse_size_to_bytes(image_info.get('size', '0'))
    
    # Estimate potential size reduction
    size_reduction_factors = {
        'base_image_optimization': 0.30,  # 30% reduction from using alpine/distroless
        'layer_squashing': 0.15,          # 15% reduction from layer optimization
        'package_cleanup': 0.20,          # 20% reduction from removing unnecessary packages
        'cache_removal': 0.10             # 10% reduction from removing build caches
    }
    
    # Calculate potential savings
    estimated_savings = {}
    total_reduction = 0
    
    for factor_name, reduction_percentage in size_reduction_factors.items():
        saving_bytes = int(original_size_bytes * reduction_percentage)
        estimated_savings[factor_name] = {
            'bytes': saving_bytes,
            'human_readable': bytes_to_human_readable(saving_bytes),
            'percentage': reduction_percentage * 100
        }
        total_reduction += reduction_percentage
    
    # Cap total reduction at 60% (realistic maximum)
    total_reduction = min(total_reduction, 0.60)
    final_size_bytes = int(original_size_bytes * (1 - total_reduction))
    
    return {
        'original_size': {
            'bytes': original_size_bytes,
            'human_readable': image_info.get('size', 'Unknown')
        },
        'estimated_final_size': {
            'bytes': final_size_bytes,
            'human_readable': bytes_to_human_readable(final_size_bytes)
        },
        'total_savings': {
            'bytes': original_size_bytes - final_size_bytes,
            'human_readable': bytes_to_human_readable(original_size_bytes - final_size_bytes),
            'percentage': total_reduction * 100
        },
        'breakdown': estimated_savings
    }

def bytes_to_human_readable(bytes_size: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f}{unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f}TB"

def generate_slimming_recommendations(image_info: Dict[str, Any], layer_analysis: Dict[str, Any]) -> List[str]:
    """Generate specific recommendations for image slimming"""
    recommendations = []
    
    # Base image recommendations
    config = image_info.get('config', {})
    if config:
        recommendations.append("## Base Image Optimization")
        recommendations.append("- Consider using alpine or distroless base images")
        recommendations.append("- Remove unnecessary packages and dependencies")
        recommendations.append("")
    
    # Layer optimization
    if layer_analysis.get('large_layers'):
        recommendations.append("## Layer Optimization")
        recommendations.append("- Combine related RUN commands to reduce layers")
        recommendations.append("- Use multi-stage builds to exclude build dependencies")
        for large_layer in layer_analysis['large_layers']:
            recommendations.append(f"- Review large layer {large_layer['layer_index']}: {large_layer['size']}")
        recommendations.append("")
    
    # Package management
    if layer_analysis.get('optimization_opportunities'):
        recommendations.append("## Package Management")
        for opp in layer_analysis['optimization_opportunities']:
            recommendations.append(f"- {opp['suggestion']}")
        recommendations.append("")
    
    # Security hardening
    recommendations.append("## Security Hardening")
    recommendations.append("- Run as non-root user")
    recommendations.append("- Remove shell access if not needed")
    recommendations.append("- Use read-only root filesystem")
    recommendations.append("- Drop unnecessary Linux capabilities")
    
    return recommendations

def main():
    """Main execution function"""
    print("📊 Starting Image Analysis & Slimming Simulation...")
    
    image_name = os.getenv('IMAGE_NAME', 'vulnerable-test-app:latest')
    
    # Get image information
    image_info = get_image_info(image_name)
    
    if not image_info:
        print(f"❌ Could not analyze image {image_name}")
        return
    
    print(f"🔍 Analyzing image: {image_name}")
    print(f"📏 Current size: {image_info.get('size', 'Unknown')}")
    
    # Analyze layers
    layers = image_info.get('layers', [])
    layer_analysis = analyze_layers(layers)
    
    # Simulate slimming
    slimming_simulation = simulate_slimming(image_info)
    
    # Generate recommendations
    recommendations = generate_slimming_recommendations(image_info, layer_analysis)
    
    # Create comprehensive analysis report
    analysis_report = {
        'timestamp': datetime.now().isoformat(),
        'image_info': image_info,
        'layer_analysis': layer_analysis,
        'slimming_simulation': slimming_simulation,
        'recommendations': recommendations
    }
    
    # Save analysis report
    with open('image-analysis-report.json', 'w') as f:
        json.dump(analysis_report, f, indent=2)
    
    # Save recommendations as markdown
    with open('slimming-recommendations.md', 'w') as f:
        f.write("# Docker Image Slimming Recommendations\n\n")
        f.write('\n'.join(recommendations))
    
    # Display results
    print("✅ Image Analysis Complete!")
    print(f"📊 Total layers: {layer_analysis['total_layers']}")
    print(f"🚨 Large layers: {len(layer_analysis['large_layers'])}")
    print(f"💡 Optimization opportunities: {len(layer_analysis['optimization_opportunities'])}")
    
    savings = slimming_simulation['total_savings']
    print(f"💾 Estimated size reduction: {savings['human_readable']} ({savings['percentage']:.1f}%)")
    
    final_size = slimming_simulation['estimated_final_size']
    print(f"🎯 Estimated final size: {final_size['human_readable']}")

if __name__ == "__main__":
    main() 