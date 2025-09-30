#!/usr/bin/env python3
"""
Multi-Language Code Quality Report Generator (Professional Version)
Combines Java and C++ analyzer results into a comprehensive markdown report for defense/aerospace settings.
"""

import json
import argparse
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

class MultiLanguageReportGenerator:
    def __init__(self, java_report_path: Optional[str] = None, cpp_report_path: Optional[str] = None):
        self.java_data = self._load_json_report(java_report_path) if java_report_path else None
        self.cpp_data = self._load_json_report(cpp_report_path) if cpp_report_path else None

        if not self.java_data and not self.cpp_data:
            raise ValueError("At least one report file (Java or C++) must be provided")

    def _load_json_report(self, file_path: str) -> Optional[Dict]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error: Could not load JSON from {file_path}: {e}")
            return None

    def generate_markdown_report(self, output_path: str = "combined_code_analysis_report.md"):
        report_content = self._build_report_content()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        print(f"Combined analysis report generated: {output_path}")
        return report_content

    def _build_report_content(self) -> str:
        sections = [
            self._generate_header(),
            self._generate_executive_summary(),
            self._generate_high_level_analysis(),
            self._generate_security_assessment(),
            self._generate_quality_metrics_comparison(),
            self._generate_java_detailed_analysis() if self.java_data else "",
            self._generate_cpp_detailed_analysis() if self.cpp_data else "",
            self._generate_combined_recommendations(),
            self._generate_action_plan(),
            self._generate_appendix()
        ]
        return '\n\n'.join(filter(None, sections))

    def _generate_header(self) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        languages = []
        if self.java_data:
            languages.append("Java")
        if self.cpp_data:
            languages.append("C++")
        return (
            "# Multi-Language Code Quality Analysis Report\n\n"
            f"**Languages Analyzed:** {', '.join(languages)}  \n"
            f"**Date Generated:** {timestamp}  \n"
            "Analysis performed using static code analysis tools.\n\n"
            "---"
        )

    def _generate_executive_summary(self) -> str:
        total_files = 0
        total_loc = 0
        total_security_issues = 0
        total_oop_violations = 0
        overall_scores = []

        if self.java_data:
            js = self.java_data.get('analysis_summary', {})
            total_files += js.get('total_files_analyzed', 0)
            total_loc += js.get('total_lines_of_code', 0)
            total_security_issues += js.get('total_security_issues', 0)
            total_oop_violations += js.get('total_oop_violations', 0)
            overall_scores.append(js.get('overall_quality_score', 0))
        if self.cpp_data:
            cs = self.cpp_data.get('analysis_summary', {})
            total_files += cs.get('total_files_analyzed', 0)
            total_loc += cs.get('total_lines_of_code', 0)
            total_security_issues += cs.get('total_security_issues', 0)
            total_oop_violations += cs.get('total_oop_violations', 0)
            overall_scores.append(cs.get('overall_quality_score', 0))
        avg_quality_score = sum(overall_scores) / len(overall_scores) if overall_scores else 0

        if total_security_issues > total_files * 0.2:
            risk_level = "HIGH"
            risk_description = (
                "Critical security vulnerabilities require immediate remediation throughout the codebase."
            )
        elif total_security_issues > 0:
            risk_level = "MEDIUM"
            risk_description = (
                "Some security issues are present. Remediation is recommended before further deployment."
            )
        else:
            risk_level = "LOW"
            risk_description = (
                "No major security vulnerabilities detected by static analysis in the provided source."
            )

        return (
            "## Executive Summary\n\n"
            "### Key Metrics\n"
            f"- Total Files Analyzed: {total_files:,}\n"
            f"- Total Lines of Code: {total_loc:,}\n"
            f"- Mean Quality Score: {avg_quality_score:.1f} / 100\n"
            f"- Security Risk Level: {risk_level}\n"
            f"- Security Issues Identified: {total_security_issues}\n"
            f"- OOP Violations Identified: {total_oop_violations}\n\n"
            f"### Risk Assessment\n"
            f"{risk_description}\n\n"
            f"### Quality Assessment\n"
            f"{self._assess_overall_quality(avg_quality_score)}\n"
        )

    def _assess_overall_quality(self, score: float) -> str:
        if score >= 80:
            return "Mature and maintainable codebase with strong engineering standards."
        elif score >= 65:
            return "Code adheres to most professional standards but presents some areas for improvement."
        elif score >= 50:
            return "Code is functional but requires significant remediation for security and maintainability."
        elif score >= 35:
            return "Major quality and security concerns are present. Immediate action is required."
        else:
            return "Critical deficiencies. This codebase should not be deployed in a production environment."

    def _generate_high_level_analysis(self) -> str:
        issues = []
        js = self.java_data.get('analysis_summary', {}) if self.java_data else {}
        cs = self.cpp_data.get('analysis_summary', {}) if self.cpp_data else {}

        # Security
        js_sec = js.get('total_security_issues', 0)
        cs_sec = cs.get('total_security_issues', 0)
        if js_sec > 0 or cs_sec > 0:
            issues.append("Security vulnerabilities are present in one or more primary language modules.")

        # Complexity
        js_cplx = js.get('average_cyclomatic_complexity', 0)
        cs_cplx = cs.get('average_cyclomatic_complexity', 0)
        if js_cplx > 15 or cs_cplx > 15:
            issues.append("High code complexity detected, which may impact maintainability and testability.")

        # Documentation
        js_docs = js.get('average_comment_ratio', 0)
        cs_docs = cs.get('average_comment_ratio', 0)
        if js_docs < 10 or cs_docs < 10:
            issues.append("Some portions of the codebase lack sufficient documentation.")

        # OOP Violations
        js_oop = js.get('total_oop_violations', 0)
        cs_oop = cs.get('total_oop_violations', 0)
        if js_oop > 0 or cs_oop > 0:
            issues.append("Object-Oriented Design violations identified in class or function organization.")

        overarching = "\n".join(f"- {issue}" for issue in issues) if issues else "- No critical issues identified by static analysis."

        return (
            "## High-Level Analysis\n\n"
            "### Overarching Technical Issues\n"
            f"{overarching}\n\n"
            "### Cross-Language Metrics Table\n"
            f"{self._generate_language_comparison()}"
        )

    def _generate_language_comparison(self) -> str:
        table = []
        if self.java_data and self.cpp_data:
            js = self.java_data.get('analysis_summary', {})
            cs = self.cpp_data.get('analysis_summary', {})
            table.append("| Metric | Java | C++ |")
            table.append("|--------|------|-----|")
            table.append(f"| Files Analyzed | {js.get('total_files_analyzed', 0)} | {cs.get('total_files_analyzed', 0)} |")
            table.append(f"| Lines of Code | {js.get('total_lines_of_code', 0):,} | {cs.get('total_lines_of_code', 0):,} |")
            table.append(f"| Quality Score | {js.get('overall_quality_score', 0)} | {cs.get('overall_quality_score', 0)} |")
            table.append(f"| Security Issues | {js.get('total_security_issues', 0)} | {cs.get('total_security_issues', 0)} |")
            table.append(f"| Avg. Complexity | {js.get('average_cyclomatic_complexity', 0):.1f} | {cs.get('average_cyclomatic_complexity', 0):.1f} |")
            table.append(f"| Comment Ratio | {js.get('average_comment_ratio', 0):.1f}% | {cs.get('average_comment_ratio', 0):.1f}% |")
        elif self.java_data:
            table.append("> Only Java analysis is available for this report (no C++ data submitted).")
        elif self.cpp_data:
            table.append("> Only C++ analysis is available for this report (no Java data submitted).")
        return '\n'.join(table)

    def _generate_security_assessment(self) -> str:
        security_content = ["## Security Assessment"]
        java_issues = self._extract_security_issues(self.java_data) if self.java_data else {}
        cpp_issues = self._extract_security_issues(self.cpp_data) if self.cpp_data else {}
        all_issue_types = set(java_issues.keys()) | set(cpp_issues.keys())
        if all_issue_types:
            security_content.append("### Security Vulnerabilities by Category")
            security_content.append("")
            security_content.append("| Issue Type | Java | C++ | Total | Severity |")
            security_content.append("|-----------|------|-----|-------|----------|")
            for issue_type in sorted(all_issue_types):
                jc = len(java_issues.get(issue_type, []))
                cc = len(cpp_issues.get(issue_type, []))
                total = jc + cc
                severity = self._get_issue_severity(issue_type)
                security_content.append(f"| {issue_type.replace('_', ' ').title()} | {jc} | {cc} | {total} | {severity} |")
        else:
            security_content.append("### No Security Issues Detected")
        return '\n'.join(security_content)

    def _extract_security_issues(self, data: Dict) -> Dict[str, List]:
        issues_by_type = {}
        if not data or 'file_details' not in data:
            return issues_by_type
        for file_detail in data['file_details']:
            for issue in file_detail.get('security_issues', []):
                issue_type = self._categorize_security_issue(issue)
                if issue_type not in issues_by_type:
                    issues_by_type[issue_type] = []
                issues_by_type[issue_type].append({
                    'file': file_detail['file_path'],
                    'description': issue
                })
        return issues_by_type

    def _categorize_security_issue(self, issue_description: str) -> str:
        desc = issue_description.lower()
        if 'sql injection' in desc:
            return 'sql_injection'
        elif 'path traversal' in desc:
            return 'path_traversal'
        elif 'command injection' in desc:
            return 'command_injection'
        elif 'buffer overflow' in desc:
            return 'buffer_overflow'
        elif 'format string' in desc:
            return 'format_string'
        elif 'memory' in desc:
            return 'memory_management'
        elif 'credentials' in desc:
            return 'hardcoded_credentials'
        else:
            return 'other'

    def _get_issue_severity(self, issue_type: str) -> str:
        high = ['sql_injection', 'path_traversal', 'command_injection', 'buffer_overflow', 'format_string']
        medium = ['memory_management', 'hardcoded_credentials', 'integer_overflow']
        if issue_type in high:
            return 'HIGH'
        elif issue_type in medium:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_quality_metrics_comparison(self) -> str:
        lines = ["## Quality and Maintainability Metrics"]
        if self.java_data:
            java = self.java_data.get('analysis_summary', {})
            lines.append(f"- Java Average Cyclomatic Complexity: {java.get('average_cyclomatic_complexity', 0):.1f}")
            lines.append(f"- Java Maintainability Index: {java.get('average_maintainability_index', 0):.1f}")
            lines.append(f"- Java Comment Ratio: {java.get('average_comment_ratio', 0):.1f}%")
        if self.cpp_data:
            cpp = self.cpp_data.get('analysis_summary', {})
            lines.append(f"- C++ Average Cyclomatic Complexity: {cpp.get('average_cyclomatic_complexity', 0):.1f}")
            lines.append(f"- C++ Maintainability Index: {cpp.get('average_maintainability_index', 0):.1f}")
            lines.append(f"- C++ Comment Ratio: {cpp.get('average_comment_ratio', 0):.1f}%")
        return '\n'.join(lines)

    def _generate_java_detailed_analysis(self) -> str:
        if not self.java_data:
            return ""
        content = ["## Java Analysis Details"]
        summary = self.java_data.get('analysis_summary', {})
        content.append("### Project Summary")
        content.append(f"- Files Analyzed: {summary.get('total_files_analyzed', 0)}")
        content.append(f"- Total Lines of Code: {summary.get('total_lines_of_code', 0):,}")
        content.append(f"- Overall Quality Score: {summary.get('overall_quality_score', 0)} / 100")
        assessment = self.java_data.get('quality_assessment', {})
        content.append(f"- Maturity Assessment: {assessment.get('code_maturity_level', '')}")
        file_details = self.java_data.get('file_details', [])
        content.append("\n### File Details")
        content.append("| File | Grade | Complexity | Security Issues | OOP Violations |")
        content.append("|------|-------|------------|----------------|----------------|")
        for fd in sorted(file_details, key=lambda x: x.get('file_quality_grade', 'F')):
            content.append(f"| {os.path.basename(fd['file_path'])} | {fd.get('file_quality_grade','F')} | "
                           f"{fd.get('cyclomatic_complexity',0)} | {len(fd.get('security_issues',[]))} | "
                           f"{len(fd.get('oop_violations', []))} |")
        if assessment.get('recommendations'):
            content.append("\n### Recommendations")
            for rec in assessment['recommendations']:
                content.append(f"- {rec}")
        return '\n'.join(content)

    def _generate_cpp_detailed_analysis(self) -> str:
        if not self.cpp_data:
            return ""
        content = ["## C++ Analysis Details"]
        summary = self.cpp_data.get('analysis_summary', {})
        content.append("### Project Summary")
        content.append(f"- Files Analyzed: {summary.get('total_files_analyzed', 0)}")
        content.append(f"- Total Lines of Code: {summary.get('total_lines_of_code', 0):,}")
        content.append(f"- Overall Quality Score: {summary.get('overall_quality_score', 0)} / 100")
        assessment = self.cpp_data.get('quality_assessment', {})
        content.append(f"- Maturity Assessment: {assessment.get('code_maturity_level', '')}")
        file_details = self.cpp_data.get('file_details', [])
        content.append("\n### File Details")
        content.append("| File | Grade | Complexity | Security Issues | OOP Violations |")
        content.append("|------|-------|------------|----------------|----------------|")
        for fd in sorted(file_details, key=lambda x: x.get('file_quality_grade', 'F')):
            content.append(f"| {os.path.basename(fd['file_path'])} | {fd.get('file_quality_grade','F')} | "
                           f"{fd.get('cyclomatic_complexity',0)} | {len(fd.get('security_issues',[]))} | "
                           f"{len(fd.get('oop_violations', []))} |")
        if assessment.get('recommendations'):
            content.append("\n### Recommendations")
            for rec in assessment['recommendations']:
                content.append(f"- {rec}")
        return '\n'.join(content)

    def _generate_combined_recommendations(self) -> str:
        content = ["## Combined Recommendations"]
        relevant = []
        js = self.java_data.get('analysis_summary', {}) if self.java_data else {}
        cs = self.cpp_data.get('analysis_summary', {}) if self.cpp_data else {}
        if js.get('total_security_issues', 0) > 0 or cs.get('total_security_issues', 0) > 0:
            relevant.append("Address all identified security vulnerabilities as a top priority.")
        if js.get('average_cyclomatic_complexity', 0) > 15 or cs.get('average_cyclomatic_complexity', 0) > 15:
            relevant.append("Refactor complex methods/functions to reduce cyclomatic complexity below 15 where feasible.")
        if js.get('average_comment_ratio', 0) < 15 or cs.get('average_comment_ratio', 0) < 15:
            relevant.append("Increase code documentation and comments for greater maintainability.")
        if not relevant:
            relevant.append("No critical issues require immediate attention based on static analysis.")
        for rec in relevant:
            content.append(f"- {rec}")
        return '\n'.join(content)

    def _generate_action_plan(self) -> str:
        return (
            "## Action Plan\n\n"
            "The following steps are recommended to remediate outstanding issues:\n\n"
            "Immediate (0-2 weeks):\n"
            "1. Address all HIGH severity security vulnerabilities.\n"
            "2. Refactor code to address extreme complexity and OOP violations.\n"
            "3. Increase test coverage and documentation in low-coverage files.\n\n"
            "Short Term (1-2 months):\n"
            "1. Roll out improved code review and CI/CD security scanning.\n"
            "2. Conduct design reviews on problematic modules.\n\n"
            "Ongoing:\n"
            "1. Schedule periodic reviews and continuous integration of code quality tools.\n"
        )

    def _generate_appendix(self) -> str:
        return (
            "## Appendix\n\n"
            "This assessment was performed using static analysis tools developed in Python and applied to provided Java and C++ source code. "
            "Metrics reported include code quality, maintainability, complexity, documentation coverage, security vulnerabilities, and design patterns. "
            "Analyses do not account for runtime behavior, business logic vulnerabilities, or external dependencies."
        )

def main():
    parser = argparse.ArgumentParser(
        description="Multi-Language Code Quality Report Generator (Professional/DoD Version)",
        epilog="Example: python report_generator.py --java java_report.json --cpp cpp_report.json"
    )
    parser.add_argument('--java', '-j', help='Path to Java analyzer JSON report file')
    parser.add_argument('--cpp', '-c', help='Path to C++ analyzer JSON report file')
    parser.add_argument('--output', '-o', default='combined_analysis_report.md', help='Output markdown file path')
    args = parser.parse_args()
    if not args.java and not args.cpp:
        print("Error: At least one report file (--java or --cpp) must be specified.")
        sys.exit(1)
    try:
        generator = MultiLanguageReportGenerator(args.java, args.cpp)
        generator.generate_markdown_report(args.output)
        print(f"\nReport generated successfully: {args.output}")
    except Exception as e:
        print(f"Error during report generation: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
