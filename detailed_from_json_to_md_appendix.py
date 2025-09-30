#!/usr/bin/env python3
"""
Detailed Technical Analysis Report Generator
Creates comprehensive technical documentation from Java and C++ analyzer JSON outputs.
"""

import json
import argparse
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import statistics

class DetailedTechnicalReportGenerator:
    def __init__(self, java_report_path: Optional[str] = None, cpp_report_path: Optional[str] = None):
        self.java_data = self._load_json_report(java_report_path) if java_report_path else None
        self.cpp_data = self._load_json_report(cpp_report_path) if cpp_report_path else None
        
        if not self.java_data and not self.cpp_data:
            raise ValueError("At least one report file (Java or C++) must be provided")

    def _load_json_report(self, file_path: str) -> Optional[Dict]:
        """Load and parse JSON report file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: Report file {file_path} not found")
            return None
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {file_path}: {e}")
            return None

    def generate_detailed_report(self, output_path: str = "detailed_technical_analysis.md"):
        """Generate comprehensive technical markdown report"""
        
        report_content = self._build_detailed_report_content()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
            
        print(f"Detailed technical analysis report generated: {output_path}")
        return report_content

    def _build_detailed_report_content(self) -> str:
        """Build the complete detailed technical report content"""
        
        sections = [
            self._generate_detailed_header(),
            self._generate_analysis_overview(),
            self._generate_statistical_analysis(),
            self._generate_java_complete_analysis() if self.java_data else "",
            self._generate_cpp_complete_analysis() if self.cpp_data else "",
            self._generate_comprehensive_security_analysis(),
            self._generate_code_quality_deep_dive(),
            self._generate_oop_analysis_detailed(),
            self._generate_file_by_file_breakdown(),
            self._generate_metrics_glossary(),
            self._generate_technical_appendix()
        ]
        
        return '\n\n'.join(filter(None, sections))

    def _generate_detailed_header(self) -> str:
        """Generate detailed report header"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        languages = []
        if self.java_data:
            languages.append("Java")
        if self.cpp_data:
            languages.append("C++")
            
        return f"""# Comprehensive Technical Code Analysis Report

**Document Type:** Detailed Technical Analysis  
**Languages Analyzed:** {" & ".join(languages)}  
**Analysis Date:** {timestamp}  
**Report Classification:** Technical Deep Dive  

## Document Purpose

This report provides a comprehensive technical analysis of the provided source code, including detailed breakdowns of:
- Individual file metrics and assessments
- Complete security vulnerability analysis
- Object-oriented design principle evaluation
- Code complexity and maintainability metrics
- Line-by-line issue identification
- Statistical analysis of code quality trends

This document serves as a technical appendix and detailed reference for development teams and security analysts.

---"""

    def _generate_analysis_overview(self) -> str:
        """Generate detailed analysis overview"""
        
        # Collect comprehensive statistics
        total_stats = self._collect_comprehensive_statistics()
        
        return f"""## Analysis Overview

### Scope of Analysis

{self._generate_analysis_scope()}

### Statistical Summary

| Metric | Value |
|--------|-------|
| Total Source Files | {total_stats['total_files']} |
| Total Lines of Code | {total_stats['total_loc']:,} |
| Total Executable Lines | {total_stats['total_executable']:,} |
| Total Comment Lines | {total_stats['total_comments']:,} |
| Total Security Issues | {total_stats['total_security_issues']} |
| Total OOP Violations | {total_stats['total_oop_violations']} |
| Files with Security Issues | {total_stats['files_with_security_issues']} |
| Files with OOP Violations | {total_stats['files_with_oop_violations']} |
| Average File Size (LOC) | {total_stats['avg_file_size']:.1f} |
| Median Complexity | {total_stats['median_complexity']:.1f} |
| Files Requiring Immediate Attention | {total_stats['critical_files']} |

### Quality Distribution

{self._generate_quality_distribution()}"""

    def _collect_comprehensive_statistics(self) -> Dict[str, Any]:
        """Collect comprehensive statistics from both reports"""
        stats = {
            'total_files': 0,
            'total_loc': 0,
            'total_executable': 0,
            'total_comments': 0,
            'total_security_issues': 0,
            'total_oop_violations': 0,
            'files_with_security_issues': 0,
            'files_with_oop_violations': 0,
            'complexities': [],
            'maintainabilities': [],
            'comment_ratios': [],
            'critical_files': 0
        }
        
        for data in [self.java_data, self.cpp_data]:
            if not data:
                continue
                
            summary = data.get('analysis_summary', {})
            stats['total_files'] += summary.get('total_files_analyzed', 0)
            stats['total_loc'] += summary.get('total_lines_of_code', 0)
            stats['total_security_issues'] += summary.get('total_security_issues', 0)
            stats['total_oop_violations'] += summary.get('total_oop_violations', 0)
            
            for file_detail in data.get('file_details', []):
                stats['total_executable'] += file_detail.get('executable_lines', 0)
                stats['total_comments'] += file_detail.get('comment_lines', 0)
                stats['complexities'].append(file_detail.get('cyclomatic_complexity', 0))
                stats['maintainabilities'].append(file_detail.get('maintainability_index', 0))
                stats['comment_ratios'].append(file_detail.get('comment_ratio', 0))
                
                if file_detail.get('security_issues'):
                    stats['files_with_security_issues'] += 1
                if file_detail.get('oop_violations'):
                    stats['files_with_oop_violations'] += 1
                if file_detail.get('file_quality_grade', 'F') in ['D', 'F']:
                    stats['critical_files'] += 1
        
        # Calculate derived statistics
        stats['avg_file_size'] = stats['total_loc'] / stats['total_files'] if stats['total_files'] > 0 else 0
        stats['median_complexity'] = statistics.median(stats['complexities']) if stats['complexities'] else 0
        
        return stats

    def _generate_analysis_scope(self) -> str:
        """Generate analysis scope description"""
        scope_details = []
        
        if self.java_data:
            java_summary = self.java_data.get('analysis_summary', {})
            scope_details.append(f"**Java Analysis:** {java_summary.get('total_files_analyzed', 0)} files, "
                               f"{java_summary.get('total_lines_of_code', 0):,} lines of code")
        
        if self.cpp_data:
            cpp_summary = self.cpp_data.get('analysis_summary', {})
            scope_details.append(f"**C++ Analysis:** {cpp_summary.get('total_files_analyzed', 0)} files, "
                               f"{cpp_summary.get('total_lines_of_code', 0):,} lines of code")
        
        return '\n'.join(scope_details)

    def _generate_quality_distribution(self) -> str:
        """Generate quality grade distribution"""
        grade_counts = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0}
        
        for data in [self.java_data, self.cpp_data]:
            if not data:
                continue
            for file_detail in data.get('file_details', []):
                grade = file_detail.get('file_quality_grade', 'F')
                if grade in grade_counts:
                    grade_counts[grade] += 1
        
        distribution = []
        distribution.append("| Grade | Count | Description |")
        distribution.append("|-------|-------|-------------|")
        distribution.append(f"| A | {grade_counts['A']} | Excellent - Production ready |")
        distribution.append(f"| B | {grade_counts['B']} | Good - Minor improvements needed |")
        distribution.append(f"| C | {grade_counts['C']} | Acceptable - Moderate improvements needed |")
        distribution.append(f"| D | {grade_counts['D']} | Poor - Significant improvements required |")
        distribution.append(f"| F | {grade_counts['F']} | Critical - Major refactoring required |")
        
        return '\n'.join(distribution)

    def _generate_statistical_analysis(self) -> str:
        """Generate detailed statistical analysis"""
        stats = self._collect_comprehensive_statistics()
        
        return f"""## Statistical Analysis

### Code Complexity Statistics

| Statistic | Value |
|-----------|-------|
| Mean Cyclomatic Complexity | {statistics.mean(stats['complexities']):.2f} |
| Median Cyclomatic Complexity | {statistics.median(stats['complexities']):.2f} |
| Standard Deviation | {statistics.stdev(stats['complexities']):.2f} if len(stats['complexities']) > 1 else 'N/A' |
| Minimum Complexity | {min(stats['complexities'])} |
| Maximum Complexity | {max(stats['complexities'])} |
| Files Above Complexity 15 | {len([c for c in stats['complexities'] if c > 15])} |
| Files Above Complexity 20 | {len([c for c in stats['complexities'] if c > 20])} |

### Maintainability Statistics

| Statistic | Value |
|-----------|-------|
| Mean Maintainability Index | {statistics.mean(stats['maintainabilities']):.2f} |
| Median Maintainability Index | {statistics.median(stats['maintainabilities']):.2f} |
| Standard Deviation | {statistics.stdev(stats['maintainabilities']):.2f} if len(stats['maintainabilities']) > 1 else 'N/A' |
| Files Below MI 50 | {len([m for m in stats['maintainabilities'] if m < 50])} |
| Files Below MI 30 | {len([m for m in stats['maintainabilities'] if m < 30])} |

### Documentation Statistics

| Statistic | Value |
|-----------|-------|
| Mean Comment Ratio | {statistics.mean(stats['comment_ratios']):.2f}% |
| Median Comment Ratio | {statistics.median(stats['comment_ratios']):.2f}% |
| Files with <10% Comments | {len([c for c in stats['comment_ratios'] if c < 10])} |
| Files with <5% Comments | {len([c for c in stats['comment_ratios'] if c < 5])} |
| Files with >20% Comments | {len([c for c in stats['comment_ratios'] if c > 20])} |"""

    def _generate_java_complete_analysis(self) -> str:
        """Generate complete Java analysis section"""
        if not self.java_data:
            return ""
        
        content = ["## Java Analysis - Complete Breakdown"]
        
        # Project overview
        summary = self.java_data.get('analysis_summary', {})
        assessment = self.java_data.get('quality_assessment', {})
        
        content.append("### Project Overview")
        content.append(f"- **Total Files:** {summary.get('total_files_analyzed', 0)}")
        content.append(f"- **Total Lines of Code:** {summary.get('total_lines_of_code', 0):,}")
        content.append(f"- **Total Executable Lines:** Sum of executable lines across all files")
        content.append(f"- **Average Cyclomatic Complexity:** {summary.get('average_cyclomatic_complexity', 0):.2f}")
        content.append(f"- **Average Maintainability Index:** {summary.get('average_maintainability_index', 0):.2f}")
        content.append(f"- **Average Comment Ratio:** {summary.get('average_comment_ratio', 0):.2f}%")
        content.append(f"- **Overall Quality Score:** {summary.get('overall_quality_score', 0)}/100")
        content.append(f"- **Security Risk Level:** {summary.get('security_risk_level', 'Unknown')}")
        content.append("")
        
        # Maturity assessment
        content.append("### Code Maturity Assessment")
        content.append(f"**Assessment:** {assessment.get('code_maturity_level', 'Unknown')}")
        content.append("")
        
        # Detailed file analysis
        content.append("### Detailed File Analysis")
        content.append("")
        
        file_details = self.java_data.get('file_details', [])
        for file_detail in sorted(file_details, key=lambda x: x.get('file_quality_grade', 'F')):
            content.extend(self._generate_file_detailed_analysis(file_detail, "Java"))
        
        # Recommendations
        recommendations = assessment.get('recommendations', [])
        if recommendations:
            content.append("### Java-Specific Recommendations")
            for i, rec in enumerate(recommendations, 1):
                content.append(f"{i}. {rec}")
            content.append("")
        
        return '\n'.join(content)

    def _generate_cpp_complete_analysis(self) -> str:
        """Generate complete C++ analysis section"""
        if not self.cpp_data:
            return ""
        
        content = ["## C++ Analysis - Complete Breakdown"]
        
        # Project overview
        summary = self.cpp_data.get('analysis_summary', {})
        assessment = self.cpp_data.get('quality_assessment', {})
        
        content.append("### Project Overview")
        content.append(f"- **Total Files:** {summary.get('total_files_analyzed', 0)}")
        content.append(f"- **Total Lines of Code:** {summary.get('total_lines_of_code', 0):,}")
        content.append(f"- **Average Cyclomatic Complexity:** {summary.get('average_cyclomatic_complexity', 0):.2f}")
        content.append(f"- **Average Maintainability Index:** {summary.get('average_maintainability_index', 0):.2f}")
        content.append(f"- **Average Comment Ratio:** {summary.get('average_comment_ratio', 0):.2f}%")
        content.append(f"- **Overall Quality Score:** {summary.get('overall_quality_score', 0)}/100")
        content.append(f"- **Security Risk Level:** {summary.get('security_risk_level', 'Unknown')}")
        content.append("")
        
        # Maturity assessment
        content.append("### Code Maturity Assessment")
        content.append(f"**Assessment:** {assessment.get('code_maturity_level', 'Unknown')}")
        content.append("")
        
        # Detailed file analysis
        content.append("### Detailed File Analysis")
        content.append("")
        
        file_details = self.cpp_data.get('file_details', [])
        for file_detail in sorted(file_details, key=lambda x: x.get('file_quality_grade', 'F')):
            content.extend(self._generate_file_detailed_analysis(file_detail, "C++"))
        
        # Recommendations
        recommendations = assessment.get('recommendations', [])
        if recommendations:
            content.append("### C++-Specific Recommendations")
            for i, rec in enumerate(recommendations, 1):
                content.append(f"{i}. {rec}")
            content.append("")
        
        return '\n'.join(content)

    def _generate_file_detailed_analysis(self, file_detail: Dict, language: str) -> List[str]:
        """Generate detailed analysis for a single file"""
        content = []
        
        file_name = os.path.basename(file_detail['file_path'])
        content.append(f"#### {file_name} ({language})")
        content.append("")
        content.append(f"**File Path:** `{file_detail['file_path']}`")
        content.append(f"**Quality Grade:** {file_detail.get('file_quality_grade', 'F')}")
        content.append("")
        
        # Metrics table
        content.append("**Detailed Metrics:**")
        content.append("")
        content.append("| Metric | Value |")
        content.append("|--------|-------|")
        content.append(f"| Lines of Code | {file_detail.get('lines_of_code', 0)} |")
        content.append(f"| Executable Lines | {file_detail.get('executable_lines', 0)} |")
        content.append(f"| Comment Lines | {file_detail.get('comment_lines', 0)} |")
        content.append(f"| Comment Ratio | {file_detail.get('comment_ratio', 0):.1f}% |")
        content.append(f"| Cyclomatic Complexity | {file_detail.get('cyclomatic_complexity', 0)} |")
        content.append(f"| Halstead Volume | {file_detail.get('halstead_volume', 0):.2f} |")
        content.append(f"| Maintainability Index | {file_detail.get('maintainability_index', 0):.2f} |")
        
        # Language-specific metrics
        if language == "Java":
            content.append(f"| Methods Count | {file_detail.get('methods_count', 0)} |")
        else:  # C++
            content.append(f"| Functions Count | {file_detail.get('functions_count', 0)} |")
        
        content.append(f"| Classes Count | {file_detail.get('classes_count', 0)} |")
        content.append(f"| Max Nesting Depth | {file_detail.get('max_nesting_depth', 0)} |")
        content.append(f"| Duplicated Lines | {file_detail.get('duplicated_lines', 0)} |")
        content.append("")
        
        # Security issues
        security_issues = file_detail.get('security_issues', [])
        if security_issues:
            content.append("**Security Issues Identified:**")
            for i, issue in enumerate(security_issues, 1):
                content.append(f"{i}. {issue}")
            content.append("")
        else:
            content.append("**Security Issues:** None detected")
            content.append("")
        
        # OOP violations
        oop_violations = file_detail.get('oop_violations', [])
        if oop_violations:
            content.append("**OOP Principle Violations:**")
            for i, violation in enumerate(oop_violations, 1):
                content.append(f"{i}. {violation}")
            content.append("")
        else:
            content.append("**OOP Violations:** None detected")
            content.append("")
        
        # Assessment
        content.append("**Assessment:**")
        grade = file_detail.get('file_quality_grade', 'F')
        complexity = file_detail.get('cyclomatic_complexity', 0)
        maintainability = file_detail.get('maintainability_index', 0)
        
        assessment = self._generate_file_assessment(grade, complexity, maintainability, len(security_issues), len(oop_violations))
        content.append(assessment)
        content.append("")
        content.append("---")
        content.append("")
        
        return content

    def _generate_file_assessment(self, grade: str, complexity: int, maintainability: float, security_count: int, oop_count: int) -> str:
        """Generate detailed assessment for a file"""
        assessments = []
        
        if grade in ['A', 'B']:
            assessments.append("This file demonstrates good software engineering practices.")
        elif grade == 'C':
            assessments.append("This file is acceptable but has areas for improvement.")
        elif grade == 'D':
            assessments.append("This file has significant quality issues that should be addressed.")
        else:  # F
            assessments.append("This file has critical quality issues requiring immediate attention.")
        
        if complexity > 20:
            assessments.append(f"The cyclomatic complexity of {complexity} is very high and should be reduced through refactoring.")
        elif complexity > 15:
            assessments.append(f"The cyclomatic complexity of {complexity} is high and could benefit from refactoring.")
        elif complexity > 10:
            assessments.append(f"The cyclomatic complexity of {complexity} is moderate.")
        else:
            assessments.append(f"The cyclomatic complexity of {complexity} is good.")
        
        if maintainability < 30:
            assessments.append(f"The maintainability index of {maintainability:.1f} indicates poor maintainability.")
        elif maintainability < 50:
            assessments.append(f"The maintainability index of {maintainability:.1f} indicates moderate maintainability.")
        elif maintainability < 70:
            assessments.append(f"The maintainability index of {maintainability:.1f} indicates good maintainability.")
        else:
            assessments.append(f"The maintainability index of {maintainability:.1f} indicates excellent maintainability.")
        
        if security_count > 0:
            assessments.append(f"Security review required: {security_count} potential vulnerability(ies) identified.")
        
        if oop_count > 0:
            assessments.append(f"Design review recommended: {oop_count} OOP principle violation(s) identified.")
        
        return ' '.join(assessments)

    def _generate_comprehensive_security_analysis(self) -> str:
        """Generate comprehensive security analysis"""
        content = ["## Comprehensive Security Analysis"]
        
        # Collect all security issues
        all_security_issues = []
        
        for data, language in [(self.java_data, "Java"), (self.cpp_data, "C++")]:
            if not data:
                continue
            
            for file_detail in data.get('file_details', []):
                file_path = file_detail['file_path']
                for issue in file_detail.get('security_issues', []):
                    all_security_issues.append({
                        'file': file_path,
                        'language': language,
                        'issue': issue,
                        'category': self._categorize_security_issue(issue)
                    })
        
        if not all_security_issues:
            content.append("### No Security Issues Detected")
            content.append("Static analysis did not identify any security vulnerabilities in the provided source code.")
            return '\n'.join(content)
        
        # Group by category
        issues_by_category = {}
        for issue_data in all_security_issues:
            category = issue_data['category']
            if category not in issues_by_category:
                issues_by_category[category] = []
            issues_by_category[category].append(issue_data)
        
        content.append(f"### Security Issue Summary")
        content.append(f"**Total Issues Identified:** {len(all_security_issues)}")
        content.append("")
        
        # Detailed breakdown by category
        for category, issues in sorted(issues_by_category.items()):
            content.append(f"### {category.replace('_', ' ').title()} Vulnerabilities")
            content.append(f"**Count:** {len(issues)}")
            content.append(f"**Severity:** {self._get_issue_severity(category)}")
            content.append("")
            
            for i, issue_data in enumerate(issues, 1):
                file_name = os.path.basename(issue_data['file'])
                content.append(f"{i}. **File:** `{file_name}` ({issue_data['language']})")
                content.append(f"   **Issue:** {issue_data['issue']}")
                content.append("")
        
        return '\n'.join(content)

    def _categorize_security_issue(self, issue_description: str) -> str:
        """Categorize security issue based on description"""
        issue_lower = issue_description.lower()
        
        if 'sql injection' in issue_lower:
            return 'sql_injection'
        elif 'path traversal' in issue_lower:
            return 'path_traversal'
        elif 'command injection' in issue_lower:
            return 'command_injection'
        elif 'buffer overflow' in issue_lower:
            return 'buffer_overflow'
        elif 'format string' in issue_lower:
            return 'format_string'
        elif 'memory' in issue_lower:
            return 'memory_management'
        elif 'credentials' in issue_lower:
            return 'hardcoded_credentials'
        else:
            return 'other'

    def _get_issue_severity(self, issue_type: str) -> str:
        """Get severity level for issue type"""
        high_severity = ['sql_injection', 'path_traversal', 'command_injection', 'buffer_overflow', 'format_string']
        medium_severity = ['memory_management', 'hardcoded_credentials', 'integer_overflow']
        
        if issue_type in high_severity:
            return 'HIGH'
        elif issue_type in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_code_quality_deep_dive(self) -> str:
        """Generate deep dive into code quality metrics"""
        content = ["## Code Quality Deep Dive"]
        
        # Collect all metrics
        all_files = []
        
        for data, language in [(self.java_data, "Java"), (self.cpp_data, "C++")]:
            if not data:
                continue
            
            for file_detail in data.get('file_details', []):
                file_info = {
                    'file': os.path.basename(file_detail['file_path']),
                    'language': language,
                    'grade': file_detail.get('file_quality_grade', 'F'),
                    'complexity': file_detail.get('cyclomatic_complexity', 0),
                    'maintainability': file_detail.get('maintainability_index', 0),
                    'comment_ratio': file_detail.get('comment_ratio', 0),
                    'loc': file_detail.get('lines_of_code', 0),
                    'halstead': file_detail.get('halstead_volume', 0)
                }
                all_files.append(file_info)
        
        # Sort files by quality grade
        all_files.sort(key=lambda x: ['A', 'B', 'C', 'D', 'F'].index(x['grade']))
        
        content.append("### File Quality Rankings")
        content.append("")
        content.append("| File | Language | Grade | Complexity | Maintainability | Comments | LOC |")
        content.append("|------|----------|-------|------------|----------------|----------|-----|")
        
        for file_info in all_files:
            content.append(f"| {file_info['file']} | {file_info['language']} | {file_info['grade']} | "
                         f"{file_info['complexity']} | {file_info['maintainability']:.1f} | "
                         f"{file_info['comment_ratio']:.1f}% | {file_info['loc']} |")
        
        content.append("")
        
        # Identify problematic files
        problem_files = [f for f in all_files if f['grade'] in ['D', 'F'] or f['complexity'] > 15]
        
        if problem_files:
            content.append("### Files Requiring Immediate Attention")
            content.append("")
            
            for file_info in problem_files:
                content.append(f"#### {file_info['file']} ({file_info['language']})")
                content.append(f"- **Grade:** {file_info['grade']}")
                content.append(f"- **Primary Issues:**")
                
                if file_info['complexity'] > 20:
                    content.append(f"  - Extremely high complexity ({file_info['complexity']})")
                elif file_info['complexity'] > 15:
                    content.append(f"  - High complexity ({file_info['complexity']})")
                
                if file_info['maintainability'] < 30:
                    content.append(f"  - Very low maintainability ({file_info['maintainability']:.1f})")
                elif file_info['maintainability'] < 50:
                    content.append(f"  - Low maintainability ({file_info['maintainability']:.1f})")
                
                if file_info['comment_ratio'] < 5:
                    content.append(f"  - Insufficient documentation ({file_info['comment_ratio']:.1f}%)")
                
                content.append("")
        
        return '\n'.join(content)

    def _generate_oop_analysis_detailed(self) -> str:
        """Generate detailed OOP analysis"""
        content = ["## Object-Oriented Programming Analysis"]
        
        # Collect all OOP violations
        all_oop_violations = []
        
        for data, language in [(self.java_data, "Java"), (self.cpp_data, "C++")]:
            if not data:
                continue
            
            for file_detail in data.get('file_details', []):
                file_path = file_detail['file_path']
                for violation in file_detail.get('oop_violations', []):
                    all_oop_violations.append({
                        'file': file_path,
                        'language': language,
                        'violation': violation
                    })
        
        if not all_oop_violations:
            content.append("### No OOP Violations Detected")
            content.append("All analyzed files appear to follow object-oriented programming principles correctly.")
            return '\n'.join(content)
        
        content.append(f"### OOP Violations Summary")
        content.append(f"**Total Violations:** {len(all_oop_violations)}")
        content.append("")
        
        # Group by violation type
        violations_by_type = {}
        for violation_data in all_oop_violations:
            violation_type = violation_data['violation'].split(':')[0]
            if violation_type not in violations_by_type:
                violations_by_type[violation_type] = []
            violations_by_type[violation_type].append(violation_data)
        
        for violation_type, violations in sorted(violations_by_type.items()):
            content.append(f"### {violation_type.replace('_', ' ').title()}")
            content.append(f"**Occurrences:** {len(violations)}")
            content.append("")
            
            for violation_data in violations:
                file_name = os.path.basename(violation_data['file'])
                content.append(f"- **File:** `{file_name}` ({violation_data['language']})")
                content.append(f"  **Details:** {violation_data['violation']}")
            
            content.append("")
        
        return '\n'.join(content)

    def _generate_file_by_file_breakdown(self) -> str:
        """Generate complete file-by-file breakdown"""
        content = ["## Complete File-by-File Breakdown"]
        
        content.append("This section provides a comprehensive analysis of every file in the codebase, "
                      "including detailed metrics, identified issues, and specific recommendations.")
        content.append("")
        
        # Process all files from both analyses
        all_files = []
        
        for data, language in [(self.java_data, "Java"), (self.cpp_data, "C++")]:
            if not data:
                continue
            
            for file_detail in data.get('file_details', []):
                all_files.append((file_detail, language))
        
        # Sort by grade then by file name
        all_files.sort(key=lambda x: (
            ['A', 'B', 'C', 'D', 'F'].index(x[0].get('file_quality_grade', 'F')),
            os.path.basename(x[0]['file_path'])
        ))
        
        for file_detail, language in all_files:
            content.extend(self._generate_complete_file_analysis(file_detail, language))
        
        return '\n'.join(content)

    def _generate_complete_file_analysis(self, file_detail: Dict, language: str) -> List[str]:
        """Generate complete analysis for a single file including recommendations"""
        content = []
        
        file_name = os.path.basename(file_detail['file_path'])
        file_path = file_detail['file_path']
        
        content.append(f"### {file_name} - Complete Analysis")
        content.append("")
        content.append(f"**Language:** {language}")
        content.append(f"**File Path:** `{file_path}`")
        content.append(f"**Overall Grade:** {file_detail.get('file_quality_grade', 'F')}")
        content.append("")
        
        # Complete metrics breakdown
        content.append("#### Comprehensive Metrics")
        content.append("")
        content.append("| Category | Metric | Value | Assessment |")
        content.append("|----------|--------|-------|------------|")
        
        # Size metrics
        loc = file_detail.get('lines_of_code', 0)
        exec_lines = file_detail.get('executable_lines', 0)
        comment_lines = file_detail.get('comment_lines', 0)
        comment_ratio = file_detail.get('comment_ratio', 0)
        
        content.append(f"| Size | Lines of Code | {loc} | {self._assess_loc(loc)} |")
        content.append(f"| Size | Executable Lines | {exec_lines} | {exec_lines/loc*100:.1f}% of total |")
        content.append(f"| Size | Comment Lines | {comment_lines} | {comment_ratio:.1f}% ratio |")
        
        # Complexity metrics
        complexity = file_detail.get('cyclomatic_complexity', 0)
        halstead = file_detail.get('halstead_volume', 0)
        maintainability = file_detail.get('maintainability_index', 0)
        nesting = file_detail.get('max_nesting_depth', 0)
        
        content.append(f"| Complexity | Cyclomatic Complexity | {complexity} | {self._assess_complexity(complexity)} |")
        content.append(f"| Complexity | Halstead Volume | {halstead:.2f} | {self._assess_halstead(halstead)} |")
        content.append(f"| Complexity | Max Nesting Depth | {nesting} | {self._assess_nesting(nesting)} |")
        content.append(f"| Quality | Maintainability Index | {maintainability:.2f} | {self._assess_maintainability(maintainability)} |")
        
        # Structure metrics
        if language == "Java":
            methods = file_detail.get('methods_count', 0)
            content.append(f"| Structure | Methods Count | {methods} | {self._assess_methods(methods)} |")
        else:
            functions = file_detail.get('functions_count', 0)
            content.append(f"| Structure | Functions Count | {functions} | {self._assess_functions(functions)} |")
        
        classes = file_detail.get('classes_count', 0)
        duplicated = file_detail.get('duplicated_lines', 0)
        
        content.append(f"| Structure | Classes/Structs | {classes} | {self._assess_classes(classes)} |")
        content.append(f"| Quality | Duplicated Lines | {duplicated} | {self._assess_duplication(duplicated, loc)} |")
        content.append("")
        
        # Issues analysis
        security_issues = file_detail.get('security_issues', [])
        oop_violations = file_detail.get('oop_violations', [])
        
        if security_issues or oop_violations:
            content.append("#### Issues Identified")
            content.append("")
            
            if security_issues:
                content.append("**Security Vulnerabilities:**")
                for i, issue in enumerate(security_issues, 1):
                    content.append(f"{i}. {issue}")
                    content.append(f"   - **Action Required:** Immediate remediation recommended")
                content.append("")
            
            if oop_violations:
                content.append("**Design Pattern Violations:**")
                for i, violation in enumerate(oop_violations, 1):
                    content.append(f"{i}. {violation}")
                    content.append(f"   - **Action Required:** Design review and refactoring")
                content.append("")
        else:
            content.append("#### Issues Identified")
            content.append("No security vulnerabilities or design pattern violations detected.")
            content.append("")
        
        # Specific recommendations
        content.append("#### Specific Recommendations")
        content.append("")
        recommendations = self._generate_file_specific_recommendations(file_detail, language)
        for i, rec in enumerate(recommendations, 1):
            content.append(f"{i}. {rec}")
        
        content.append("")
        content.append("---")
        content.append("")
        
        return content

    def _assess_loc(self, loc: int) -> str:
        """Assess lines of code"""
        if loc > 1000:
            return "Very large file - consider splitting"
        elif loc > 500:
            return "Large file - monitor complexity"
        elif loc > 200:
            return "Moderate size"
        else:
            return "Appropriate size"

    def _assess_complexity(self, complexity: int) -> str:
        """Assess cyclomatic complexity"""
        if complexity > 20:
            return "Very High - Refactor immediately"
        elif complexity > 15:
            return "High - Refactoring recommended"
        elif complexity > 10:
            return "Moderate - Monitor"
        else:
            return "Good"

    def _assess_halstead(self, halstead: float) -> str:
        """Assess Halstead volume"""
        if halstead > 1000:
            return "High complexity"
        elif halstead > 500:
            return "Moderate complexity"
        else:
            return "Low complexity"

    def _assess_nesting(self, nesting: int) -> str:
        """Assess nesting depth"""
        if nesting > 6:
            return "Too deep - refactor"
        elif nesting > 4:
            return "Deep - consider refactoring"
        else:
            return "Acceptable"

    def _assess_maintainability(self, maintainability: float) -> str:
        """Assess maintainability index"""
        if maintainability >= 85:
            return "Excellent"
        elif maintainability >= 65:
            return "Good"
        elif maintainability >= 50:
            return "Moderate"
        else:
            return "Poor"

    def _assess_methods(self, methods: int) -> str:
        """Assess method count"""
        if methods > 20:
            return "High - consider splitting class"
        elif methods > 10:
            return "Moderate"
        else:
            return "Appropriate"

    def _assess_functions(self, functions: int) -> str:
        """Assess function count"""
        if functions > 15:
            return "High - consider modularization"
        elif functions > 8:
            return "Moderate"
        else:
            return "Appropriate"

    def _assess_classes(self, classes: int) -> str:
        """Assess class count"""
        if classes > 5:
            return "Multiple classes - ensure cohesion"
        elif classes > 1:
            return "Multiple classes"
        else:
            return "Single class"

    def _assess_duplication(self, duplicated: int, total_loc: int) -> str:
        """Assess code duplication"""
        if total_loc == 0:
            return "N/A"
        
        percentage = (duplicated / total_loc) * 100
        if percentage > 10:
            return f"High ({percentage:.1f}%) - refactor"
        elif percentage > 5:
            return f"Moderate ({percentage:.1f}%)"
        else:
            return f"Low ({percentage:.1f}%)"

    def _generate_file_specific_recommendations(self, file_detail: Dict, language: str) -> List[str]:
        """Generate specific recommendations for a file"""
        recommendations = []
        
        complexity = file_detail.get('cyclomatic_complexity', 0)
        maintainability = file_detail.get('maintainability_index', 0)
        comment_ratio = file_detail.get('comment_ratio', 0)
        security_issues = file_detail.get('security_issues', [])
        oop_violations = file_detail.get('oop_violations', [])
        nesting = file_detail.get('max_nesting_depth', 0)
        duplicated = file_detail.get('duplicated_lines', 0)
        
        # Security recommendations
        if security_issues:
            recommendations.append(f"CRITICAL: Address {len(security_issues)} security vulnerability(ies) immediately")
        
        # Complexity recommendations
        if complexity > 20:
            recommendations.append("Break down complex methods into smaller, focused functions")
        elif complexity > 15:
            recommendations.append("Consider refactoring to reduce cyclomatic complexity")
        
        # Maintainability recommendations
        if maintainability < 30:
            recommendations.append("Major refactoring required to improve maintainability")
        elif maintainability < 50:
            recommendations.append("Refactoring recommended to improve maintainability")
        
        # Documentation recommendations
        if comment_ratio < 5:
            recommendations.append("Add comprehensive documentation and comments")
        elif comment_ratio < 10:
            recommendations.append("Improve code documentation")
        
        # Design recommendations
        if oop_violations:
            recommendations.append(f"Address {len(oop_violations)} object-oriented design issue(s)")
        
        if nesting > 6:
            recommendations.append("Reduce nesting depth through early returns or guard clauses")
        
        if duplicated > 0:
            recommendations.append("Eliminate code duplication through refactoring")
        
        # Language-specific recommendations
        if language == "C++":
            recommendations.append("Consider using modern C++ features (smart pointers, RAII)")
            recommendations.append("Ensure proper exception safety")
        elif language == "Java":
            recommendations.append("Follow Java coding conventions and best practices")
            recommendations.append("Consider using appropriate design patterns")
        
        # Default recommendation if none identified
        if not recommendations:
            recommendations.append("Code quality is acceptable - continue following current practices")
        
        return recommendations

    def _generate_metrics_glossary(self) -> str:
        """Generate comprehensive metrics glossary"""
        return """## Metrics Glossary

This section provides detailed explanations of all metrics used in the analysis.

### Code Size Metrics

**Lines of Code (LOC)**
- Definition: Total number of lines in the source file, including blank lines and comments
- Good Range: Varies by file type, generally <500 lines per file
- Purpose: Indicates file size and potential complexity

**Executable Lines**
- Definition: Lines containing actual executable code (excluding comments and blank lines)
- Purpose: Measures the amount of logic in the file

**Comment Lines**
- Definition: Lines containing comments or documentation
- Purpose: Indicates level of code documentation

**Comment Ratio**
- Definition: Percentage of comment lines relative to total lines
- Good Range: 15-25% for production code
- Purpose: Measures documentation quality

### Complexity Metrics

**Cyclomatic Complexity**
- Definition: Measures the number of linearly independent paths through code
- Calculation: Based on decision points (if, while, for, case statements)
- Ranges:
  - 1-10: Simple, low risk
  - 11-15: Moderate complexity, manageable
  - 16-20: High complexity, needs attention
  - 21+: Very high complexity, immediate refactoring needed
- Purpose: Predicts testing difficulty and maintenance effort

**Halstead Volume**
- Definition: Measures program complexity based on operators and operands
- Calculation: N × log₂(n), where N is program length and n is vocabulary
- Purpose: Estimates mental effort required to understand code

**Maximum Nesting Depth**
- Definition: Deepest level of nested control structures
- Good Range: ≤4 levels
- Purpose: Indicates code readability and maintainability

### Quality Metrics

**Maintainability Index (MI)**
- Definition: Composite metric combining complexity, size, and documentation
- Calculation: 171 - 5.2×ln(HV) - 0.23×CC - 16.2×ln(LOC)
- Ranges:
  - 85-100: Excellent maintainability
  - 65-84: Good maintainability
  - 50-64: Moderate maintainability
  - <50: Poor maintainability
- Purpose: Predicts long-term maintenance effort

**Duplicated Lines**
- Definition: Lines of code that appear multiple times in the file
- Good Range: <5% of total lines
- Purpose: Identifies opportunities for refactoring

### Structure Metrics

**Methods/Functions Count**
- Definition: Number of methods (Java) or functions (C++) in the file
- Good Range: <20 methods per class
- Purpose: Indicates class/file responsibility and cohesion

**Classes Count**
- Definition: Number of classes, interfaces, or structs defined
- Purpose: Indicates file organization and single responsibility principle adherence

### Quality Grades

**Grade A (90-100 points)**
- Excellent code quality
- Low complexity, high maintainability
- Well documented
- No security issues
- Ready for production

**Grade B (80-89 points)**
- Good code quality
- Moderate complexity
- Adequate documentation
- Minor issues that don't impact functionality

**Grade C (70-79 points)**
- Acceptable code quality
- Some areas need improvement
- May have moderate complexity or documentation gaps

**Grade D (60-69 points)**
- Poor code quality
- High complexity or low maintainability
- Significant improvements needed

**Grade F (<60 points)**
- Critical code quality issues
- Very high complexity or security vulnerabilities
- Immediate attention required"""

    def _generate_technical_appendix(self) -> str:
        """Generate technical appendix with methodology and limitations"""
        return """## Technical Appendix

### Analysis Methodology

This analysis was performed using custom static analysis tools designed specifically for Java and C++ source code evaluation. The methodology includes:

#### Static Code Analysis Process
1. **Lexical Analysis**: Source code is tokenized and parsed
2. **Syntax Tree Generation**: Abstract syntax trees are built for each file
3. **Pattern Matching**: Security vulnerability patterns are matched against code
4. **Metric Calculation**: Quantitative metrics are computed using established algorithms
5. **Quality Assessment**: Overall quality scores are derived from multiple metrics

#### Security Vulnerability Detection
- **Pattern-based Detection**: Uses regular expressions to identify common vulnerability patterns
- **CWE Mapping**: Issues are mapped to Common Weakness Enumeration identifiers
- **OWASP Alignment**: Vulnerabilities are categorized according to OWASP Top 10
- **Severity Classification**: Issues are classified as HIGH, MEDIUM, or LOW severity

#### Code Quality Metrics
- **Cyclomatic Complexity**: Calculated using McCabe's method
- **Halstead Metrics**: Based on Halstead's software science
- **Maintainability Index**: Microsoft's maintainability index formula
- **Documentation Metrics**: Comment-to-code ratio analysis

### Tool Limitations

#### Static Analysis Limitations
- **Runtime Behavior**: Cannot detect issues that only manifest during execution
- **Context Sensitivity**: Limited understanding of business logic context
- **False Positives**: Pattern matching may identify non-issues as problems
- **False Negatives**: Complex vulnerabilities may not be detected

#### Language-Specific Limitations

**Java Analysis**
- **Framework-Specific Issues**: Limited knowledge of framework-specific security patterns
- **Dynamic Features**: Reflection and dynamic class loading not fully analyzed
- **Third-Party Libraries**: External dependencies not evaluated

**C++ Analysis**
- **Template Complexity**: Complex template instantiations may not be fully analyzed
- **Preprocessor Directives**: Macro expansions and conditional compilation limitations
- **Platform Dependencies**: Platform-specific code patterns may not be recognized

#### Metric Limitations
- **Threshold Sensitivity**: Quality thresholds are based on industry standards but may not fit all contexts
- **Composite Metrics**: Combined metrics may obscure specific issues
- **Size Dependency**: Some metrics are influenced by file size rather than complexity

### Recommendations for Use

#### Best Practices
1. **Combine with Dynamic Analysis**: Use alongside runtime testing and profiling
2. **Manual Review**: Critical findings should be manually verified
3. **Context Consideration**: Consider business requirements and constraints
4. **Iterative Improvement**: Use results to guide incremental improvements

#### Integration Suggestions
1. **CI/CD Integration**: Incorporate into continuous integration pipelines
2. **Code Review Process**: Use findings to guide manual code reviews
3. **Development Training**: Share results with development teams for learning
4. **Quality Gates**: Establish quality thresholds for release decisions

### Data Sources and References

#### Industry Standards
- **OWASP Top 10**: Web application security risks
- **CWE/SANS Top 25**: Most dangerous software errors
- **ISO/IEC 25010**: Software quality model

#### Academic References
- **McCabe, T.J.**: "A Complexity Measure" (1976)
- **Halstead, M.H.**: "Elements of Software Science" (1977)
- **Oman, P. & Hagemeister, J.**: "Metrics for Assessing a Software System's Maintainability" (1992)

### Report Versioning

- **Report Version**: 1.0
- **Analysis Engine**: Custom Static Analysis Tools v1.0
- **Pattern Database**: Updated {datetime.now().strftime("%Y-%m-%d")}
- **Methodology**: Based on industry best practices and academic research

---

*This report was generated automatically by the Multi-Language Code Quality Analysis System. For questions about methodology or findings, please consult the development team.*"""

def main():
    """Main function to generate detailed technical report"""
    parser = argparse.ArgumentParser(
        description="Detailed Technical Analysis Report Generator",
        epilog="Example: python detailed_report_generator.py --java java_report.json --cpp cpp_report.json"
    )
    
    parser.add_argument(
        '--java', '-j',
        help='Path to Java analyzer JSON report file'
    )
    
    parser.add_argument(
        '--cpp', '-c', 
        help='Path to C++ analyzer JSON report file'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='detailed_technical_analysis.md',
        help='Output markdown file path (default: detailed_technical_analysis.md)'
    )
    
    args = parser.parse_args()
    
    if not args.java and not args.cpp:
        print("Error: At least one report file (--java or --cpp) must be specified.")
        sys.exit(1)
    
    try:
        # Generate detailed technical report
        generator = DetailedTechnicalReportGenerator(args.java, args.cpp)
        generator.generate_detailed_report(args.output)
        
        print(f"\nDetailed technical analysis report generated successfully!")
        print(f"Output file: {args.output}")
        
        # Print file size information
        if os.path.exists(args.output):
            file_size = os.path.getsize(args.output)
            print(f"Report size: {file_size:,} bytes")
        
        if args.java and os.path.exists(args.java):
            print(f"Java report source: {args.java}")
        if args.cpp and os.path.exists(args.cpp):
            print(f"C++ report source: {args.cpp}")
            
    except Exception as e:
        print(f"Error generating detailed report: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
