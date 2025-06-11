#!/usr/bin/env python3
"""
Comprehensive Security Report Generator
Combines all analysis results into a final security report
"""

import json
import os
from typing import Dict, List, Any
from datetime import datetime

def load_report_data() -> Dict[str, Any]:
    """Load all generated report data"""
    data = {}
    
    # Load AI analysis report
    if os.path.exists('ai-analysis-report.json'):
        with open('ai-analysis-report.json', 'r') as f:
            data['ai_analysis'] = json.load(f)
    
    # Load fix recommendations
    if os.path.exists('fix-recommendations.json'):
        with open('fix-recommendations.json', 'r') as f:
            data['fix_recommendations'] = json.load(f)
    
    # Load image analysis
    if os.path.exists('image-analysis-report.json'):
        with open('image-analysis-report.json', 'r') as f:
            data['image_analysis'] = json.load(f)
    
    # Load raw scan reports
    if os.path.exists('reports/trivy-report.json'):
        with open('reports/trivy-report.json', 'r') as f:
            data['trivy_scan'] = json.load(f)
    
    if os.path.exists('reports/grype-report.json'):
        with open('reports/grype-report.json', 'r') as f:
            data['grype_scan'] = json.load(f)
    
    return data

def generate_executive_summary(data: Dict[str, Any]) -> List[str]:
    """Generate executive summary"""
    summary = [
        "# 🔐 AI-Powered Container Security Analysis Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## 📊 Executive Summary",
        ""
    ]
    
    ai_analysis = data.get('ai_analysis', {})
    fix_recommendations = data.get('fix_recommendations', {})
    image_analysis = data.get('image_analysis', {})
    
    # Vulnerability statistics
    if ai_analysis:
        total_vulns = ai_analysis.get('total_vulnerabilities', 0)
        categorization = ai_analysis.get('ai_categorization', {})
        reduction_percentage = ai_analysis.get('reduction_percentage', 0)
        
        summary.extend([
            f"- **Total Vulnerabilities Found:** {total_vulns}",
            f"- **AI Noise Reduction:** {reduction_percentage}%",
            f"- **Exploitable Code Issues:** {categorization.get('exploitable_code', 0)}",
            f"- **Potentially Exploitable:** {categorization.get('potentially_exploitable', 0)}",
            f"- **Base Image Noise:** {categorization.get('base_image_noise', 0)}",
            f"- **False Positives:** {categorization.get('false_positives', 0)}",
            ""
        ])
    
    # Fix recommendations
    if fix_recommendations:
        critical_fixes = fix_recommendations.get('critical_fixes', 0)
        high_priority_fixes = fix_recommendations.get('high_priority_fixes', 0)
        
        summary.extend([
            f"- **Critical Fixes Required:** {critical_fixes}",
            f"- **High Priority Fixes:** {high_priority_fixes}",
            ""
        ])
    
    # Image optimization
    if image_analysis:
        slimming_sim = image_analysis.get('slimming_simulation', {})
        if slimming_sim:
            original_size = slimming_sim.get('original_size', {}).get('human_readable', 'Unknown')
            estimated_size = slimming_sim.get('estimated_final_size', {}).get('human_readable', 'Unknown')
            savings_percentage = slimming_sim.get('total_savings', {}).get('percentage', 0)
            
            summary.extend([
                f"- **Current Image Size:** {original_size}",
                f"- **Estimated Optimized Size:** {estimated_size}",
                f"- **Potential Size Reduction:** {savings_percentage:.1f}%",
                ""
            ])
    
    return summary

def generate_detailed_vulnerability_analysis(data: Dict[str, Any]) -> List[str]:
    """Generate detailed vulnerability analysis section"""
    section = [
        "## 🧠 AI-Powered Vulnerability Analysis",
        ""
    ]
    
    ai_analysis = data.get('ai_analysis', {})
    if not ai_analysis:
        section.append("⚠️ No AI analysis data available")
        return section
    
    detailed_analysis = ai_analysis.get('detailed_analysis', {})
    
    # Exploitable code vulnerabilities
    exploitable = detailed_analysis.get('exploitable_code', [])
    if exploitable:
        section.extend([
            "### 🚨 Exploitable Code Vulnerabilities",
            ""
        ])
        
        for vuln in exploitable[:10]:  # Show top 10
            cve_id = vuln.get('VulnerabilityID', 'Unknown')
            severity = vuln.get('Severity', 'Unknown')
            pkg_name = vuln.get('PkgName', 'Unknown')
            ai_data = vuln.get('ai_analysis', {})
            
            section.extend([
                f"- **{cve_id}** ({severity})",
                f"  - Package: `{pkg_name}`",
                f"  - Priority: {ai_data.get('priority', 'Unknown')}",
                f"  - Confidence: {ai_data.get('confidence', 0):.2f}",
                f"  - Action: {ai_data.get('recommended_action', 'Unknown')}",
                ""
            ])
    
    # Potentially exploitable
    potentially_exploitable = detailed_analysis.get('potentially_exploitable', [])
    if potentially_exploitable:
        section.extend([
            "### ⚠️ Potentially Exploitable Vulnerabilities",
            ""
        ])
        
        for vuln in potentially_exploitable[:5]:  # Show top 5
            cve_id = vuln.get('VulnerabilityID', 'Unknown')
            severity = vuln.get('Severity', 'Unknown')
            pkg_name = vuln.get('PkgName', 'Unknown')
            ai_data = vuln.get('ai_analysis', {})
            
            section.extend([
                f"- **{cve_id}** ({severity})",
                f"  - Package: `{pkg_name}`",
                f"  - Reasoning: {ai_data.get('reasoning', 'Unknown')}",
                ""
            ])
    
    return section

def generate_fix_recommendations_section(data: Dict[str, Any]) -> List[str]:
    """Generate fix recommendations section"""
    section = [
        "## 🛠️ Fix Recommendations",
        ""
    ]
    
    fix_recommendations = data.get('fix_recommendations', {})
    if not fix_recommendations:
        section.append("⚠️ No fix recommendations available")
        return section
    
    # Critical fixes
    manual_review = fix_recommendations.get('manual_review_required', [])
    if manual_review:
        section.extend([
            "### 🚨 Critical Issues Requiring Manual Review",
            ""
        ])
        
        for fix in manual_review:
            section.extend([
                f"- **{fix.get('vuln_id', 'Unknown')}**",
                f"  - Package: `{fix.get('package', 'Unknown')}`",
                f"  - Action: {fix.get('action', 'Unknown')}",
                ""
            ])
    
    # Automated fixes
    automated_fixes = fix_recommendations.get('automated_fixes', [])
    if automated_fixes:
        section.extend([
            "### 🤖 Automated Fix Candidates",
            ""
        ])
        
        for fix in automated_fixes:
            section.extend([
                f"- **{fix.get('vuln_id', 'Unknown')}**",
                f"  - Package: `{fix.get('package', 'Unknown')}`",
                f"  - Action: {fix.get('action', 'Unknown')}",
                ""
            ])
    
    # Fix categories breakdown
    fix_categories = fix_recommendations.get('fix_categories', {})
    if fix_categories:
        section.extend([
            "### 📊 Fix Categories Breakdown",
            ""
        ])
        
        for category, count in fix_categories.items():
            if count > 0:
                section.append(f"- **{category.replace('_', ' ').title()}:** {count} issues")
        section.append("")
    
    return section

def generate_image_optimization_section(data: Dict[str, Any]) -> List[str]:
    """Generate image optimization section"""
    section = [
        "## 📦 Container Image Optimization",
        ""
    ]
    
    image_analysis = data.get('image_analysis', {})
    if not image_analysis:
        section.append("⚠️ No image analysis data available")
        return section
    
    # Image info
    image_info = image_analysis.get('image_info', {})
    if image_info:
        section.extend([
            "### 📊 Current Image Analysis",
            "",
            f"- **Image:** {image_info.get('name', 'Unknown')}",
            f"- **Current Size:** {image_info.get('size', 'Unknown')}",
            f"- **Total Layers:** {image_info.get('total_layers', 'Unknown')}",
            f"- **Architecture:** {image_info.get('architecture', 'Unknown')}",
            ""
        ])
    
    # Slimming simulation
    slimming_sim = image_analysis.get('slimming_simulation', {})
    if slimming_sim:
        section.extend([
            "### 🎯 Optimization Potential",
            ""
        ])
        
        breakdown = slimming_sim.get('breakdown', {})
        for optimization, details in breakdown.items():
            section.append(f"- **{optimization.replace('_', ' ').title()}:** {details.get('human_readable', 'Unknown')} ({details.get('percentage', 0):.1f}%)")
        
        total_savings = slimming_sim.get('total_savings', {})
        section.extend([
            "",
            f"**Total Potential Savings:** {total_savings.get('human_readable', 'Unknown')} ({total_savings.get('percentage', 0):.1f}%)",
            ""
        ])
    
    # Layer analysis
    layer_analysis = image_analysis.get('layer_analysis', {})
    if layer_analysis:
        large_layers = layer_analysis.get('large_layers', [])
        optimization_opportunities = layer_analysis.get('optimization_opportunities', [])
        
        if large_layers:
            section.extend([
                "### 🔍 Large Layers Identified",
                ""
            ])
            for layer in large_layers:
                section.append(f"- Layer {layer.get('layer_index', 'Unknown')}: {layer.get('size', 'Unknown')}")
            section.append("")
        
        if optimization_opportunities:
            section.extend([
                "### 💡 Optimization Opportunities",
                ""
            ])
            for opp in optimization_opportunities:
                section.append(f"- {opp.get('suggestion', 'Unknown')}")
            section.append("")
    
    return section

def generate_recommendations_section() -> List[str]:
    """Generate next steps and recommendations"""
    return [
        "## 🎯 Next Steps",
        "",
        "### Immediate Actions (0-24 hours)",
        "1. Address all CRITICAL vulnerabilities requiring manual review",
        "2. Apply automated fixes for high-priority vulnerabilities",
        "3. Update base image to latest secure version",
        "",
        "### Short-term Actions (1-7 days)", 
        "1. Implement image slimming recommendations",
        "2. Set up automated vulnerability monitoring",
        "3. Configure security scanning in CI/CD pipeline",
        "",
        "### Long-term Actions (1-4 weeks)",
        "1. Migrate to distroless or Alpine base images",
        "2. Implement security hardening best practices",
        "3. Set up continuous security monitoring",
        "",
        "## 📋 Generated Files",
        "",
        "This analysis has generated the following files:",
        "- `ai-analysis-report.json` - Detailed AI vulnerability analysis",
        "- `fix-recommendations.json` - Automated fix suggestions", 
        "- `image-analysis-report.json` - Container image optimization analysis",
        "- `security-summary.md` - This comprehensive report",
        "- `Dockerfile.patch` - Dockerfile improvements (if applicable)",
        "- `security-recommendations.md` - Security hardening guide",
        ""
    ]

def main():
    """Main execution function"""
    print("📋 Generating Comprehensive Security Report...")
    
    # Load all report data
    data = load_report_data()
    
    if not data:
        print("⚠️ No report data found to generate summary")
        return
    
    # Generate report sections
    report_sections = []
    
    # Executive summary
    report_sections.extend(generate_executive_summary(data))
    
    # Detailed vulnerability analysis
    report_sections.extend(generate_detailed_vulnerability_analysis(data))
    
    # Fix recommendations
    report_sections.extend(generate_fix_recommendations_section(data))
    
    # Image optimization
    report_sections.extend(generate_image_optimization_section(data))
    
    # Next steps
    report_sections.extend(generate_recommendations_section())
    
    # Write comprehensive report
    with open('security-summary.md', 'w') as f:
        f.write('\n'.join(report_sections))
    
    # Generate JSON summary for pipeline
    pipeline_summary = {
        'timestamp': datetime.now().isoformat(),
        'scan_completed': True,
        'ai_analysis_completed': 'ai_analysis' in data,
        'fix_recommendations_generated': 'fix_recommendations' in data,
        'image_analysis_completed': 'image_analysis' in data,
        'total_vulnerabilities': data.get('ai_analysis', {}).get('total_vulnerabilities', 0),
        'critical_fixes_required': data.get('fix_recommendations', {}).get('critical_fixes', 0),
        'noise_reduction_percentage': data.get('ai_analysis', {}).get('reduction_percentage', 0),
        'estimated_size_reduction': data.get('image_analysis', {}).get('slimming_simulation', {}).get('total_savings', {}).get('percentage', 0)
    }
    
    with open('pipeline-summary.json', 'w') as f:
        json.dump(pipeline_summary, f, indent=2)
    
    print("✅ Security Report Generation Complete!")
    print("📄 Generated: security-summary.md")
    print("📊 Generated: pipeline-summary.json")
    
    # Display key metrics
    if 'ai_analysis' in data:
        ai_data = data['ai_analysis']
        print(f"🎯 Total vulnerabilities: {ai_data.get('total_vulnerabilities', 0)}")
        print(f"📈 Noise reduction: {ai_data.get('reduction_percentage', 0)}%")
    
    if 'fix_recommendations' in data:
        fix_data = data['fix_recommendations']
        print(f"🚨 Critical fixes: {fix_data.get('critical_fixes', 0)}")
        print(f"⚠️  High priority fixes: {fix_data.get('high_priority_fixes', 0)}")

if __name__ == "__main__":
    main() 