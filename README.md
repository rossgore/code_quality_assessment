#Code Quality and Security Analyzer

A  Python tool for analyzing Java and C++ source code to assess code quality, security vulnerabilities, and adherence to Object-Oriented Programming principles.

## Features

### Code Quality Metrics
- **Cyclomatic Complexity**: Measures the complexity of control flow
- **Halstead Volume**: Quantifies program complexity based on operators and operands
- **Maintainability Index**: Combines multiple metrics to assess maintainability
- **Lines of Code (LOC)**: Counts total, executable, and comment lines
- **Comment Ratio**: Percentage of commented vs. total lines
- **Code Duplication**: Identifies repeated code patterns
- **Nesting Depth**: Measures maximum nesting levels

### Security Analysis
- **OWASP Top 10 Vulnerabilities**: Detects common web application security risks
- **CWE (Common Weakness Enumeration)**: Identifies security weaknesses
- **SQL Injection**: Pattern matching for SQL injection vulnerabilities
- **Path Traversal**: Detects directory traversal attacks
- **Command Injection**: Identifies command execution vulnerabilities
- **Hardcoded Credentials**: Finds hardcoded passwords and API keys
- **Cross-Site Scripting (XSS)**: Detects XSS vulnerabilities
- **Unsafe Deserialization**: Identifies deserialization security issues

### OOP Principles Assessment
- **Encapsulation**: Checks for public fields and missing getters/setters
- **Inheritance**: Validates proper inheritance usage
- **Interface Design**: Ensures proper interface implementation

## Installation

No additional dependencies required beyond Python 3.6+. The tool uses only standard library modules.

## Usage

### Command Line Interface

```bash
# Basic analysis
python3 java_analyzer.py sample_java_project/ --output java_analysis_report.json

python3 cpp_code_analyzer.py sample_cpp_project/ --output cpp_analysis_report.json
### Command Line Options

- `directory`: Path to the Java project directory (required)
- `--output`, `-o`: Output file path for JSON report (default: `java_analysis_report.json`)
- `--csv`: Also generate a CSV report with detailed metrics
- `--summary`: Print analysis summary to console

## Output Formats

### JSON Report Structure

```json
{
  "analysis_summary": {
    "total_files_analyzed": 15,
    "total_lines_of_code": 2547,
    "average_cyclomatic_complexity": 8.2,
    "average_maintainability_index": 67.4,
    "average_comment_ratio": 12.8,
    "total_security_issues": 7,
    "total_oop_violations": 3,
    "overall_quality_score": 72,
    "security_risk_level": "MEDIUM"
  },
  "quality_assessment": {
    "code_maturity_level": "DEVELOPING - Good practices with room for improvement",
    "recommendations": [
      "Address 7 potential security vulnerabilities",
      "Refactor 2 files with high cyclomatic complexity (>15)",
      "Add documentation to 3 files with low comment ratios (<5%)"
    ]
  },
  "file_details": [
    {
      "file_path": "src/main/java/com/example/Service.java",
      "lines_of_code": 234,
      "cyclomatic_complexity": 15,
      "maintainability_index": 58.7,
      "security_issues": ["Potential SQL Injection vulnerability"],
      "file_quality_grade": "C"
    }
  ]
}
```

### Markdown Reports

python3 from_json_to_md_report.py --java java_analysis_report.json --cpp cpp_analysis_report.json

python3 detailed_from_json_to_md_appendix.py --java java_analysis_report.json --cpp cpp_analysis_report.json

### Command Line Options

- `--java`: java json file to generate report from
- `--cpp`: cpp json file to generate report from


## Interpreting Results

### Quality Score (0-100)
- **90-100**: Excellent code quality
- **80-89**: Good code quality with minor issues
- **70-79**: Acceptable quality, some improvements needed
- **60-69**: Below average, significant improvements required
- **Below 60**: Poor quality, major refactoring needed

### Cyclomatic Complexity Thresholds
- **1-10**: Low complexity (good)
- **11-15**: Moderate complexity (acceptable)
- **16-20**: High complexity (needs attention)
- **20+**: Very high complexity (refactor recommended)

### Maintainability Index
- **85-100**: Highly maintainable
- **65-84**: Moderately maintainable
- **65 and below**: Difficult to maintain

### Security Risk Levels
- **LOW**: No significant security issues found
- **MEDIUM**: Some potential vulnerabilities identified
- **HIGH**: Critical security issues require immediate attention

## Security Patterns Detected

| Category | CWE ID | OWASP | Severity | Description |
|----------|--------|-------|----------|-------------|
| SQL Injection | CWE-89 | A03:2021 | HIGH | Unsafe SQL query construction |
| Path Traversal | CWE-22 | A01:2021 | HIGH | Directory traversal vulnerabilities |
| Command Injection | CWE-77 | A03:2021 | HIGH | Unsafe command execution |
| Hardcoded Credentials | CWE-798 | A07:2021 | MEDIUM | Embedded secrets in code |
| Cross-Site Scripting | CWE-79 | A03:2021 | HIGH | XSS vulnerabilities |
| Unsafe Deserialization | CWE-502 | A08:2021 | HIGH | Insecure object deserialization |



## References

- [OWASP Top Ten 2021](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [Cyclomatic Complexity - McCabe](https://www.mccabe.com/pdf/mccabe-nist235r.pdf)
- [Halstead Complexity Measures](https://en.wikipedia.org/wiki/Halstead_complexity_measures)
- [Maintainability Index](https://docs.microsoft.com/en-us/visualstudio/code-quality/code-metrics-maintainability-index-range-and-meaning)

---
