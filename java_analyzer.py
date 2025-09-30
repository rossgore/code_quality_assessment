#!/usr/bin/env python3
"""
Java Code Quality and Security Analyzer
A comprehensive tool for analyzing Java source code quality and security.
"""

import os
import re
import math
import json
import csv
import argparse
import sys
from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class CodeMetrics:
    """Data class to store code quality metrics"""
    file_path: str
    lines_of_code: int
    executable_lines: int
    comment_lines: int
    comment_ratio: float
    cyclomatic_complexity: int
    halstead_volume: float
    maintainability_index: float
    methods_count: int
    classes_count: int
    max_nesting_depth: int
    duplicated_lines: int
    security_issues: List[str]
    oop_violations: List[str]

@dataclass
class SecurityIssue:
    """Data class to store security vulnerability information"""
    file_path: str
    line_number: int
    issue_type: str
    severity: str
    description: str
    cwe_id: str = ""
    owasp_category: str = ""

class JavaCodeAnalyzer:
    """Main class for analyzing Java code quality and security"""

    def __init__(self):
        self.security_patterns = self._load_security_patterns()
        self.oop_patterns = self._load_oop_patterns()
        self.dangerous_methods = self._load_dangerous_methods()

    def _load_security_patterns(self):
        """Load common Java security vulnerability patterns"""
        sql_injection_patterns = [
            'Statement.*createStatement',
            'executeQuery.*\+',
            'prepareStatement.*\+.*\'',
        ]

        path_traversal_patterns = [
            'new File.*\+',
            'FileInputStream.*\+',
            '\.\.',
        ]

        command_injection_patterns = [
            'Runtime\.getRuntime\(\)\.exec',
            'ProcessBuilder.*\+',
        ]

        credential_patterns = [
            'password\s*=\s*[\'\"][^\'\"]{6,}[\'\"]',
            'secret\s*=\s*[\'\"][^\'\"]{10,}[\'\"]',
            'api.*key\s*=\s*[\'\"][^\'\"]{10,}[\'\"]',
        ]

        return {
            'sql_injection': {
                'patterns': sql_injection_patterns,
                'cwe': 'CWE-89',
                'severity': 'HIGH',
                'description': 'Potential SQL Injection vulnerability'
            },
            'path_traversal': {
                'patterns': path_traversal_patterns,
                'cwe': 'CWE-22', 
                'severity': 'HIGH',
                'description': 'Potential Path Traversal vulnerability'
            },
            'command_injection': {
                'patterns': command_injection_patterns,
                'cwe': 'CWE-77',
                'severity': 'HIGH', 
                'description': 'Potential Command Injection vulnerability'
            },
            'hardcoded_credentials': {
                'patterns': credential_patterns,
                'cwe': 'CWE-798',
                'severity': 'MEDIUM',
                'description': 'Potential hardcoded credentials'
            }
        }

    def _load_oop_patterns(self):
        """Load patterns to check OOP principles violations"""
        return {
            'encapsulation_violations': [
                'public\s+\w+\s+\w+\s*;',  # Public fields
            ],
            'inheritance_issues': [
                'extends\s+\w+\s+extends',  # Multiple inheritance
            ]
        }

    def _load_dangerous_methods(self):
        """Load list of potentially dangerous Java methods"""
        return [
            'Runtime.exec',
            'ProcessBuilder', 
            'System.exit',
            'Thread.stop',
            'Class.forName',
        ]

    def analyze_file(self, file_path: str) -> CodeMetrics:
        """Analyze a single Java file for quality and security metrics"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return self._empty_metrics(file_path)

        # Calculate basic metrics
        basic_metrics = self._calculate_basic_metrics(lines, content)

        # Calculate complexity metrics  
        complexity_metrics = self._calculate_complexity_metrics(content, lines)

        # Analyze security issues
        security_issues = self._analyze_security_issues(content, file_path)

        # Check OOP violations
        oop_violations = self._check_oop_violations(content)

        # Calculate Halstead metrics
        halstead_volume = self._calculate_halstead_volume(content)

        # Calculate maintainability index
        maintainability_index = self._calculate_maintainability_index(
            halstead_volume,
            complexity_metrics['cyclomatic_complexity'],
            basic_metrics['lines_of_code']
        )

        return CodeMetrics(
            file_path=file_path,
            lines_of_code=basic_metrics['lines_of_code'],
            executable_lines=basic_metrics['executable_lines'],
            comment_lines=basic_metrics['comment_lines'],
            comment_ratio=basic_metrics['comment_ratio'],
            cyclomatic_complexity=complexity_metrics['cyclomatic_complexity'],
            halstead_volume=halstead_volume,
            maintainability_index=maintainability_index,
            methods_count=complexity_metrics['methods_count'],
            classes_count=complexity_metrics['classes_count'],
            max_nesting_depth=complexity_metrics['max_nesting_depth'],
            duplicated_lines=basic_metrics['duplicated_lines'],
            security_issues=[issue.description for issue in security_issues],
            oop_violations=oop_violations
        )

    def _empty_metrics(self, file_path: str) -> CodeMetrics:
        """Return empty metrics for files that can't be read"""
        return CodeMetrics(
            file_path=file_path,
            lines_of_code=0,
            executable_lines=0,
            comment_lines=0,
            comment_ratio=0,
            cyclomatic_complexity=0,
            halstead_volume=0,
            maintainability_index=0,
            methods_count=0,
            classes_count=0,
            max_nesting_depth=0,
            duplicated_lines=0,
            security_issues=[],
            oop_violations=[]
        )

    def _calculate_basic_metrics(self, lines: List[str], content: str) -> Dict[str, Any]:
        """Calculate basic code metrics like LOC, comments, etc."""
        total_lines = len(lines)
        comment_lines = 0
        executable_lines = 0

        in_multiline_comment = False

        for line in lines:
            stripped = line.strip()

            if not stripped:
                continue

            # Handle multi-line comments
            if '/*' in stripped:
                in_multiline_comment = True
            if '*/' in stripped:
                in_multiline_comment = False
                comment_lines += 1
                continue

            if in_multiline_comment:
                comment_lines += 1
                continue

            # Single line comments
            if stripped.startswith('//'):
                comment_lines += 1
                continue

            # Regular executable lines
            executable_lines += 1

        # Calculate duplicated lines
        duplicated_lines = self._count_duplicated_lines(lines)

        comment_ratio = (comment_lines / total_lines * 100) if total_lines > 0 else 0

        return {
            'lines_of_code': total_lines,
            'executable_lines': executable_lines,
            'comment_lines': comment_lines,
            'comment_ratio': round(comment_ratio, 2),
            'duplicated_lines': duplicated_lines
        }

    def _count_duplicated_lines(self, lines: List[str]) -> int:
        """Count lines that appear more than once"""
        line_counts = {}
        duplicated = 0

        for line in lines:
            stripped = line.strip()
            if len(stripped) > 10 and not stripped.startswith('//'):
                line_counts[stripped] = line_counts.get(stripped, 0) + 1

        for line, count in line_counts.items():
            if count > 1:
                duplicated += count - 1

        return duplicated

    def _calculate_complexity_metrics(self, content: str, lines: List[str]) -> Dict[str, int]:
        """Calculate cyclomatic complexity and other structural metrics"""

        # Count decision points for cyclomatic complexity
        complexity = 1  # Start with 1 for the main path

        # Simple pattern counting
        decision_keywords = ['if', 'while', 'for', 'switch', 'case', 'catch']
        for keyword in decision_keywords:
            pattern = r'\b' + keyword + r'\s*\('
            matches = re.findall(pattern, content, re.IGNORECASE)
            complexity += len(matches)

        # Count logical operators
        complexity += len(re.findall(r'&&', content))
        complexity += len(re.findall(r'\|\|', content))

        # Count methods
        method_matches = re.findall(r'\b\w+\s+\w+\s*\([^)]*\)\s*\{', content)
        methods_count = len(method_matches)

        # Count classes and interfaces
        class_matches = re.findall(r'\b(class|interface|enum)\s+\w+', content)
        classes_count = len(class_matches)

        # Calculate maximum nesting depth
        max_depth = self._calculate_max_nesting_depth(content)

        return {
            'cyclomatic_complexity': complexity,
            'methods_count': methods_count,
            'classes_count': classes_count,
            'max_nesting_depth': max_depth
        }

    def _calculate_max_nesting_depth(self, content: str) -> int:
        """Calculate the maximum nesting depth of control structures"""
        lines = content.split('\n')
        current_depth = 0
        max_depth = 0

        for line in lines:
            stripped = line.strip()

            if not stripped or stripped.startswith('//'):
                continue

            # Count braces
            open_braces = stripped.count('{')
            close_braces = stripped.count('}')

            current_depth += open_braces - close_braces
            max_depth = max(max_depth, current_depth)
            current_depth = max(0, current_depth)

        return max_depth

    def _calculate_halstead_volume(self, content: str) -> float:
        """Calculate Halstead Volume metric"""
        # Simple implementation - count operators and operands
        operators = re.findall(r'[+\-*/=<>!&|^~]+|\b(if|else|while|for|return)\b', content)
        operands = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', content)

        unique_operators = len(set(operators)) if operators else 1
        unique_operands = len(set(operands)) if operands else 1
        total_operators = len(operators)
        total_operands = len(operands)

        vocabulary = unique_operators + unique_operands
        length = total_operators + total_operands

        if vocabulary > 0:
            volume = length * math.log2(vocabulary)
        else:
            volume = 0

        return round(volume, 2)

    def _calculate_maintainability_index(self, halstead_volume: float, 
                                       cyclomatic_complexity: int, 
                                       lines_of_code: int) -> float:
        """Calculate Maintainability Index"""
        if lines_of_code == 0:
            return 0

        if halstead_volume <= 0:
            halstead_volume = 1

        mi = (171 - 
              5.2 * math.log(halstead_volume) - 
              0.23 * cyclomatic_complexity - 
              16.2 * math.log(lines_of_code))

        return max(0, min(100, round(mi, 2)))

    def _analyze_security_issues(self, content: str, file_path: str) -> List[SecurityIssue]:
        """Analyze content for security vulnerabilities"""
        issues = []
        lines = content.split('\n')

        for issue_type, pattern_info in self.security_patterns.items():
            for pattern in pattern_info['patterns']:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append(SecurityIssue(
                            file_path=file_path,
                            line_number=line_num,
                            issue_type=issue_type,
                            severity=pattern_info['severity'],
                            description=pattern_info['description'],
                            cwe_id=pattern_info.get('cwe', ''),
                            owasp_category=pattern_info.get('owasp', '')
                        ))

        return issues

    def _check_oop_violations(self, content: str) -> List[str]:
        """Check for Object-Oriented Programming principle violations"""
        violations = []

        for violation_type, patterns in self.oop_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    violations.append(f"{violation_type}: {len(matches)} occurrences")

        return violations

    def analyze_directory(self, directory_path: str) -> List[CodeMetrics]:
        """Analyze all Java files in a directory recursively"""
        results = []
        java_files = []

        # Find all Java files
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.java'):
                    java_files.append(os.path.join(root, file))

        print(f"Found {len(java_files)} Java files to analyze...")

        # Analyze each file
        for i, file_path in enumerate(java_files, 1):
            print(f"Analyzing {i}/{len(java_files)}: {os.path.basename(file_path)}")
            metrics = self.analyze_file(file_path)
            results.append(metrics)

        return results

    def generate_report(self, metrics_list: List[CodeMetrics], output_path: str = "java_analysis_report.json"):
        """Generate a comprehensive analysis report"""

        # Calculate aggregate statistics
        total_files = len(metrics_list)
        if total_files == 0:
            print("No files to analyze")
            return {}

        total_loc = sum(m.lines_of_code for m in metrics_list)
        total_security_issues = sum(len(m.security_issues) for m in metrics_list)
        total_oop_violations = sum(len(m.oop_violations) for m in metrics_list)

        avg_complexity = sum(m.cyclomatic_complexity for m in metrics_list) / total_files
        avg_maintainability = sum(m.maintainability_index for m in metrics_list) / total_files
        avg_comment_ratio = sum(m.comment_ratio for m in metrics_list) / total_files

        # Create quality score
        quality_score = self._calculate_quality_score(metrics_list)

        # Security risk assessment
        security_risk = "HIGH" if total_security_issues > total_files * 0.1 else "MEDIUM" if total_security_issues > 0 else "LOW"

        report = {
            "analysis_summary": {
                "total_files_analyzed": total_files,
                "total_lines_of_code": total_loc,
                "average_cyclomatic_complexity": round(avg_complexity, 2),
                "average_maintainability_index": round(avg_maintainability, 2),
                "average_comment_ratio": round(avg_comment_ratio, 2),
                "total_security_issues": total_security_issues,
                "total_oop_violations": total_oop_violations,
                "overall_quality_score": quality_score,
                "security_risk_level": security_risk
            },
            "quality_assessment": {
                "code_maturity_level": self._assess_code_maturity(metrics_list),
                "recommendations": self._generate_recommendations(metrics_list)
            },
            "file_details": []
        }

        # Add individual file metrics
        for metrics in metrics_list:
            file_report = {
                "file_path": metrics.file_path,
                "lines_of_code": metrics.lines_of_code,
                "executable_lines": metrics.executable_lines,
                "comment_ratio": metrics.comment_ratio,
                "cyclomatic_complexity": metrics.cyclomatic_complexity,
                "halstead_volume": metrics.halstead_volume,
                "maintainability_index": metrics.maintainability_index,
                "methods_count": metrics.methods_count,
                "classes_count": metrics.classes_count,
                "max_nesting_depth": metrics.max_nesting_depth,
                "duplicated_lines": metrics.duplicated_lines,
                "security_issues": metrics.security_issues,
                "oop_violations": metrics.oop_violations,
                "file_quality_grade": self._calculate_file_grade(metrics)
            }
            report["file_details"].append(file_report)

        # Save report
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"Analysis report saved to: {output_path}")
        return report

    def _calculate_quality_score(self, metrics_list: List[CodeMetrics]) -> int:
        """Calculate overall code quality score (0-100)"""
        if not metrics_list:
            return 0

        total_score = 0

        for metrics in metrics_list:
            file_score = 100

            # Deduct points for high complexity
            if metrics.cyclomatic_complexity > 10:
                file_score -= min(30, (metrics.cyclomatic_complexity - 10) * 3)

            # Deduct points for low maintainability
            if metrics.maintainability_index < 50:
                file_score -= (50 - metrics.maintainability_index) * 0.5

            # Deduct points for poor comment ratio
            if metrics.comment_ratio < 10:
                file_score -= (10 - metrics.comment_ratio) * 2

            # Deduct points for security issues
            file_score -= len(metrics.security_issues) * 10

            # Deduct points for OOP violations
            file_score -= len(metrics.oop_violations) * 5

            total_score += max(0, file_score)

        return int(total_score / len(metrics_list))

    def _assess_code_maturity(self, metrics_list: List[CodeMetrics]) -> str:
        """Assess overall code maturity level"""
        quality_score = self._calculate_quality_score(metrics_list)

        if quality_score >= 80:
            return "MATURE - Well-structured, secure, and maintainable code"
        elif quality_score >= 60:
            return "DEVELOPING - Good practices with room for improvement"
        elif quality_score >= 40:
            return "BASIC - Functional but needs significant improvement"
        else:
            return "IMMATURE - Requires major refactoring and security review"

    def _generate_recommendations(self, metrics_list: List[CodeMetrics]) -> List[str]:
        """Generate specific recommendations based on analysis"""
        recommendations = []

        high_complexity_files = [m for m in metrics_list if m.cyclomatic_complexity > 15]
        low_comment_files = [m for m in metrics_list if m.comment_ratio < 5]
        security_issues = sum(len(m.security_issues) for m in metrics_list)
        oop_violations = sum(len(m.oop_violations) for m in metrics_list)

        if high_complexity_files:
            recommendations.append(f"Refactor {len(high_complexity_files)} files with high complexity")

        if low_comment_files:
            recommendations.append(f"Add documentation to {len(low_comment_files)} files")

        if security_issues > 0:
            recommendations.append(f"Address {security_issues} security vulnerabilities")

        if oop_violations > 0:
            recommendations.append(f"Fix {oop_violations} OOP violations")

        recommendations.extend([
            "Implement automated testing",
            "Set up continuous integration",
            "Establish code review process",
            "Use static analysis tools"
        ])

        return recommendations

    def _calculate_file_grade(self, metrics: CodeMetrics) -> str:
        """Calculate individual file quality grade"""
        score = 100

        if metrics.cyclomatic_complexity > 20:
            score -= 30
        elif metrics.cyclomatic_complexity > 10:
            score -= 15

        if metrics.maintainability_index < 30:
            score -= 25
        elif metrics.maintainability_index < 50:
            score -= 10

        score -= len(metrics.security_issues) * 15
        score -= len(metrics.oop_violations) * 5

        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

def generate_csv_report(metrics_list: List[CodeMetrics], csv_path: str):
    """Generate CSV report with detailed metrics"""
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'file_path', 'lines_of_code', 'executable_lines', 'comment_lines',
            'comment_ratio', 'cyclomatic_complexity', 'halstead_volume',
            'maintainability_index', 'methods_count', 'classes_count',
            'max_nesting_depth', 'duplicated_lines', 'security_issues_count',
            'oop_violations_count', 'quality_grade'
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        analyzer = JavaCodeAnalyzer()

        for metrics in metrics_list:
            writer.writerow({
                'file_path': metrics.file_path,
                'lines_of_code': metrics.lines_of_code,
                'executable_lines': metrics.executable_lines,
                'comment_lines': metrics.comment_lines,
                'comment_ratio': metrics.comment_ratio,
                'cyclomatic_complexity': metrics.cyclomatic_complexity,
                'halstead_volume': metrics.halstead_volume,
                'maintainability_index': metrics.maintainability_index,
                'methods_count': metrics.methods_count,
                'classes_count': metrics.classes_count,
                'max_nesting_depth': metrics.max_nesting_depth,
                'duplicated_lines': metrics.duplicated_lines,
                'security_issues_count': len(metrics.security_issues),
                'oop_violations_count': len(metrics.oop_violations),
                'quality_grade': analyzer._calculate_file_grade(metrics)
            })

def print_summary(report: Dict):
    """Print analysis summary to console"""
    summary = report['analysis_summary']
    assessment = report['quality_assessment']

    print("\n" + "=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Files Analyzed: {summary['total_files_analyzed']}")
    print(f"Total Lines of Code: {summary['total_lines_of_code']:,}")
    print(f"Overall Quality Score: {summary['overall_quality_score']}/100")
    print(f"Security Risk Level: {summary['security_risk_level']}")
    print(f"Code Maturity: {assessment['code_maturity_level']}")
    print()
    print(f"Average Cyclomatic Complexity: {summary['average_cyclomatic_complexity']}")
    print(f"Average Maintainability Index: {summary['average_maintainability_index']}")
    print(f"Average Comment Ratio: {summary['average_comment_ratio']}%")
    print()
    print(f"Security Issues Found: {summary['total_security_issues']}")
    print(f"OOP Violations Found: {summary['total_oop_violations']}")
    print()
    print("TOP RECOMMENDATIONS:")
    for i, rec in enumerate(assessment['recommendations'][:5], 1):
        print(f"  {i}. {rec}")
    print("=" * 60)

def main():
    """Main function to run Java code analysis"""
    parser = argparse.ArgumentParser(
        description="Java Code Quality and Security Analyzer",
        epilog="Example: python java_analyzer.py /path/to/java/project --output report.json"
    )

    parser.add_argument(
        'directory',
        help='Directory path containing Java files to analyze'
    )

    parser.add_argument(
        '--output', '-o',
        default='java_analysis_report.json',
        help='Output file path for the analysis report'
    )

    parser.add_argument(
        '--csv',
        action='store_true',
        help='Also generate CSV report with detailed metrics'
    )

    parser.add_argument(
        '--summary',
        action='store_true',
        help='Print summary to console'
    )

    args = parser.parse_args()

    # Check if directory exists
    if not os.path.exists(args.directory):
        print(f"Error: Directory '{args.directory}' does not exist.")
        sys.exit(1)

    print("=" * 60)
    print("Java Code Quality and Security Analyzer")
    print("=" * 60)
    print(f"Analyzing directory: {args.directory}")
    print(f"Output report: {args.output}")
    print()

    # Initialize analyzer
    analyzer = JavaCodeAnalyzer()

    # Analyze directory
    try:
        metrics_list = analyzer.analyze_directory(args.directory)

        if not metrics_list:
            print("No Java files found in the specified directory.")
            sys.exit(1)

        # Generate report
        report = analyzer.generate_report(metrics_list, args.output)

        # Generate CSV if requested
        if args.csv:
            csv_path = args.output.replace('.json', '.csv')
            generate_csv_report(metrics_list, csv_path)
            print(f"CSV report saved to: {csv_path}")

        # Print summary if requested
        if args.summary:
            print_summary(report)

        print(f"\nAnalysis complete! Check {args.output} for detailed results.")

    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
