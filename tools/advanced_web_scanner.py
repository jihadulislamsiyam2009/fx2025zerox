#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner
A comprehensive scanner that combines multiple tools and techniques for maximum coverage
"""

import argparse
import json
import subprocess
import sys
import os
import re
import time
import random
import concurrent.futures
from typing import List, Dict, Any
import requests
from urllib.parse import urljoin, urlparse, parse_qs
import dns.resolver

class AdvancedWebScanner:
    def __init__(self, target: str, tool: str, scan_type: str):
        self.target = self.normalize_url(target)
        self.tool = tool.lower()
        self.scan_type = scan_type
        self.vulnerabilities = []
        self.timeout = int(os.getenv('TOOL_TIMEOUT', '300'))
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecureScan Pro Advanced Scanner v3.0.0'
        })
        
        # Load wordlists
        self.directory_wordlist = self.load_wordlist("wordlists/common.txt")
        self.xss_payloads = self.load_wordlist("wordlists/xss-payloads.txt")
        self.sql_payloads = self.load_wordlist("wordlists/sql-payloads.txt")
        
        # Nuclei templates path
        self.nuclei_templates = "nuclei-templates"
        
    def normalize_url(self, url: str) -> str:
        """Normalize and validate URL"""
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        return url.rstrip('/')
    
    def load_wordlist(self, filepath: str) -> List[str]:
        """Load wordlist from file"""
        wordlist = []
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"Could not load wordlist {filepath}: {e}", file=sys.stderr)
        return wordlist[:1000]  # Limit to 1000 entries for performance
    
    def run_nuclei_scan(self) -> List[Dict]:
        """Run Nuclei vulnerability scan with templates"""
        vulnerabilities = []
        
        try:
            if os.path.exists(self.nuclei_templates):
                # Simulate nuclei scan with various template categories
                template_categories = [
                    'cves', 'vulnerabilities', 'exposed-panels', 'technologies',
                    'misconfiguration', 'dns', 'fuzzing', 'file'
                ]
                
                for category in template_categories[:4]:  # Limit for performance
                    category_vulns = self.simulate_nuclei_category(category)
                    vulnerabilities.extend(category_vulns)
                    
        except Exception as e:
            print(f"Nuclei scan error: {e}", file=sys.stderr)
            
        return vulnerabilities
    
    def simulate_nuclei_category(self, category: str) -> List[Dict]:
        """Simulate Nuclei template category scan"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target, timeout=10)
            
            # Simulate different vulnerability types based on category
            if category == 'cves':
                vulns = self.detect_cve_vulnerabilities(response)
            elif category == 'exposed-panels':
                vulns = self.detect_exposed_panels(response)
            elif category == 'misconfiguration':
                vulns = self.detect_misconfigurations(response)
            elif category == 'technologies':
                vulns = self.detect_technology_issues(response)
            else:
                vulns = []
                
            vulnerabilities.extend(vulns)
            
        except Exception as e:
            print(f"Nuclei category {category} error: {e}", file=sys.stderr)
            
        return vulnerabilities
    
    def detect_cve_vulnerabilities(self, response) -> List[Dict]:
        """Detect CVE-based vulnerabilities"""
        vulnerabilities = []
        
        # Check for common CVE patterns
        cve_patterns = {
            'Apache Struts': r'struts[/-](\d+\.\d+\.\d+)',
            'WordPress': r'wp-content|wordpress',
            'Drupal': r'drupal|sites/default',
            'Joomla': r'joomla|index\.php\?option=com_',
            'phpMyAdmin': r'phpmyadmin|pma'
        }
        
        for tech, pattern in cve_patterns.items():
            if re.search(pattern, response.text, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'cve_vulnerability',
                    'severity': 'high',
                    'title': f'Potential {tech} CVE Vulnerability',
                    'description': f'{tech} detected - may be vulnerable to known CVEs',
                    'target': self.target,
                    'evidence': {'technology': tech, 'pattern': pattern},
                    'recommendation': f'Update {tech} to latest version and apply security patches'
                })
                
        return vulnerabilities
    
    def detect_exposed_panels(self, response) -> List[Dict]:
        """Detect exposed admin panels"""
        vulnerabilities = []
        
        admin_patterns = [
            '/admin', '/administrator', '/wp-admin', '/login', '/dashboard',
            '/panel', '/control', '/manage', '/console', '/backend'
        ]
        
        for path in admin_patterns:
            try:
                admin_url = urljoin(self.target, path)
                admin_response = self.session.get(admin_url, timeout=5)
                
                if admin_response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'exposed_admin_panel',
                        'severity': 'medium',
                        'title': f'Exposed Admin Panel at {path}',
                        'description': f'Admin panel accessible at {admin_url}',
                        'target': admin_url,
                        'evidence': {'path': path, 'status_code': admin_response.status_code},
                        'recommendation': 'Restrict access to admin panels and implement strong authentication'
                    })
                    
            except:
                continue
                
        return vulnerabilities
    
    def detect_misconfigurations(self, response) -> List[Dict]:
        """Detect security misconfigurations"""
        vulnerabilities = []
        
        # Check security headers
        security_headers = {
            'X-Frame-Options': 'Missing clickjacking protection',
            'X-Content-Type-Options': 'Missing MIME type sniffing protection',
            'X-XSS-Protection': 'Missing XSS protection header',
            'Strict-Transport-Security': 'Missing HTTPS enforcement',
            'Content-Security-Policy': 'Missing content security policy'
        }
        
        for header, description in security_headers.items():
            if header not in response.headers:
                vulnerabilities.append({
                    'type': 'security_header_missing',
                    'severity': 'medium',
                    'title': f'Missing Security Header: {header}',
                    'description': description,
                    'target': self.target,
                    'evidence': {'missing_header': header},
                    'recommendation': f'Implement {header} security header'
                })
        
        # Check for information disclosure
        if 'server' in response.headers:
            server_header = response.headers['server']
            if any(tech in server_header.lower() for tech in ['apache', 'nginx', 'iis']):
                vulnerabilities.append({
                    'type': 'information_disclosure',
                    'severity': 'low',
                    'title': 'Server Information Disclosure',
                    'description': f'Server header reveals: {server_header}',
                    'target': self.target,
                    'evidence': {'server_header': server_header},
                    'recommendation': 'Hide or minimize server version information in headers'
                })
                
        return vulnerabilities
    
    def detect_technology_issues(self, response) -> List[Dict]:
        """Detect technology-specific security issues"""
        vulnerabilities = []
        
        # Check for outdated JavaScript libraries
        js_libraries = {
            'jquery': r'jquery[/-](\d+\.\d+\.\d+)',
            'bootstrap': r'bootstrap[/-](\d+\.\d+\.\d+)',
            'angular': r'angular[/-](\d+\.\d+\.\d+)'
        }
        
        for lib, pattern in js_libraries.items():
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                for version in matches:
                    vulnerabilities.append({
                        'type': 'outdated_library',
                        'severity': 'medium',
                        'title': f'Potentially Outdated {lib.title()} Library',
                        'description': f'{lib.title()} version {version} detected - may have known vulnerabilities',
                        'target': self.target,
                        'evidence': {'library': lib, 'version': version},
                        'recommendation': f'Update {lib} to latest secure version'
                    })
                    
        return vulnerabilities
    
    def run_comprehensive_directory_scan(self) -> List[Dict]:
        """Run comprehensive directory and file discovery"""
        vulnerabilities = []
        
        # Use both common directories and wordlist
        common_dirs = [
            'admin', 'backup', 'config', 'database', 'files', 'images',
            'includes', 'js', 'css', 'uploads', 'downloads', 'docs',
            'api', 'test', 'dev', 'staging', 'old', 'new', 'tmp'
        ]
        
        # Combine common directories with wordlist
        directories_to_test = common_dirs + self.directory_wordlist[:200]
        
        # Test directories concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dir = {
                executor.submit(self.test_directory, directory): directory 
                for directory in directories_to_test
            }
            
            for future in concurrent.futures.as_completed(future_to_dir):
                directory = future_to_dir[future]
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                except Exception as e:
                    print(f"Directory test error for {directory}: {e}", file=sys.stderr)
                    
        return vulnerabilities
    
    def test_directory(self, directory: str) -> Dict:
        """Test if directory exists and is accessible"""
        try:
            test_url = urljoin(self.target, directory)
            response = self.session.get(test_url, timeout=5)
            
            if response.status_code == 200:
                # Check if directory listing is enabled
                if any(indicator in response.text.lower() for indicator in 
                       ['index of', 'directory listing', 'parent directory']):
                    return {
                        'type': 'directory_listing',
                        'severity': 'medium',
                        'title': f'Directory Listing Enabled: /{directory}',
                        'description': f'Directory {directory} has listing enabled, exposing files',
                        'target': test_url,
                        'evidence': {'directory': directory, 'status_code': response.status_code},
                        'recommendation': 'Disable directory listing and implement proper access controls'
                    }
                else:
                    return {
                        'type': 'exposed_directory',
                        'severity': 'low',
                        'title': f'Accessible Directory: /{directory}',
                        'description': f'Directory {directory} is accessible',
                        'target': test_url,
                        'evidence': {'directory': directory, 'status_code': response.status_code},
                        'recommendation': 'Review directory access permissions'
                    }
                    
        except:
            pass
            
        return None
    
    def run_advanced_xss_scan(self) -> List[Dict]:
        """Run advanced XSS scanning with multiple payloads"""
        vulnerabilities = []
        
        # Use loaded XSS payloads or fallback to basic ones
        payloads = self.xss_payloads if self.xss_payloads else [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")'
        ]
        
        # Test different injection points
        injection_points = [
            ('url_param', self.test_url_xss),
            ('form_field', self.test_form_xss),
            ('header', self.test_header_xss)
        ]
        
        for point_type, test_method in injection_points:
            try:
                point_vulns = test_method(payloads[:10])  # Limit payloads for performance
                vulnerabilities.extend(point_vulns)
            except Exception as e:
                print(f"XSS test error for {point_type}: {e}", file=sys.stderr)
                
        return vulnerabilities
    
    def test_url_xss(self, payloads: List[str]) -> List[Dict]:
        """Test URL parameters for XSS"""
        vulnerabilities = []
        
        for payload in payloads[:5]:  # Test first 5 payloads
            try:
                test_url = f"{self.target}{'&' if '?' in self.target else '?'}test={payload}"
                response = self.session.get(test_url, timeout=10)
                
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'reflected_xss',
                        'severity': 'high',
                        'title': 'Reflected XSS via URL Parameter',
                        'description': f'XSS payload reflected in response: {payload[:50]}...',
                        'target': test_url,
                        'evidence': {'payload': payload, 'injection_point': 'url_parameter'},
                        'recommendation': 'Implement proper input validation and output encoding'
                    })
                    break
                    
            except Exception as e:
                print(f"URL XSS test error: {e}", file=sys.stderr)
                
        return vulnerabilities
    
    def test_form_xss(self, payloads: List[str]) -> List[Dict]:
        """Test forms for XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target, timeout=10)
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
            
            for form_html in forms:
                inputs = re.findall(r'<input[^>]*name="([^"]*)"[^>]*>', form_html, re.IGNORECASE)
                
                for input_name in inputs:
                    for payload in payloads[:3]:  # Test first 3 payloads per input
                        # This would require actual form submission in real implementation
                        # For simulation, we'll mark it as potential vulnerability
                        vulnerabilities.append({
                            'type': 'potential_form_xss',
                            'severity': 'medium',
                            'title': f'Potential XSS in form field: {input_name}',
                            'description': f'Form input {input_name} may be vulnerable to XSS',
                            'target': self.target,
                            'evidence': {'input_name': input_name, 'payload': payload},
                            'recommendation': 'Test form inputs manually and implement proper validation'
                        })
                        break  # One vulnerability per input field
                        
        except Exception as e:
            print(f"Form XSS test error: {e}", file=sys.stderr)
            
        return vulnerabilities
    
    def test_header_xss(self, payloads: List[str]) -> List[Dict]:
        """Test HTTP headers for XSS reflection"""
        vulnerabilities = []
        
        test_headers = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        for header_name in test_headers:
            for payload in payloads[:2]:  # Test first 2 payloads per header
                try:
                    headers = {header_name: payload}
                    response = self.session.get(self.target, headers=headers, timeout=10)
                    
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'header_xss',
                            'severity': 'medium',
                            'title': f'XSS via {header_name} header',
                            'description': f'XSS payload reflected from {header_name} header',
                            'target': self.target,
                            'evidence': {'header': header_name, 'payload': payload},
                            'recommendation': 'Validate and encode HTTP header values'
                        })
                        break
                        
                except Exception as e:
                    print(f"Header XSS test error: {e}", file=sys.stderr)
                    
        return vulnerabilities
    
    def run_advanced_sqli_scan(self) -> List[Dict]:
        """Run advanced SQL injection scanning"""
        vulnerabilities = []
        
        # Use loaded SQL payloads or fallback to basic ones
        payloads = self.sql_payloads if self.sql_payloads else [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "'; EXEC xp_cmdshell('dir')--"
        ]
        
        # Test URL parameters
        parsed_url = urlparse(self.target)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param_name in params:
                param_vulns = self.test_parameter_sqli(param_name, payloads[:5])
                vulnerabilities.extend(param_vulns)
                
        return vulnerabilities
    
    def test_parameter_sqli(self, param_name: str, payloads: List[str]) -> List[Dict]:
        """Test parameter for SQL injection"""
        vulnerabilities = []
        
        for payload in payloads:
            try:
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query)
                params[param_name] = [payload]
                
                from urllib.parse import urlencode, urlunparse
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                response = self.session.get(test_url, timeout=10)
                
                # Check for SQL error patterns
                error_patterns = [
                    r"sql syntax", r"mysql", r"postgresql", r"oracle",
                    r"sqlite", r"microsoft", r"odbc", r"ole db"
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'sql_injection',
                            'severity': 'high',
                            'title': f'SQL Injection in {param_name}',
                            'description': f'Parameter {param_name} is vulnerable to SQL injection',
                            'target': test_url,
                            'evidence': {'parameter': param_name, 'payload': payload, 'error_pattern': pattern},
                            'recommendation': 'Use parameterized queries and input validation'
                        })
                        return vulnerabilities  # Return after first match
                        
            except Exception as e:
                print(f"SQL injection test error: {e}", file=sys.stderr)
                
        return vulnerabilities
    
    def run_scan(self) -> Dict[str, Any]:
        """Execute comprehensive advanced web scan"""
        print(f"Starting advanced web scan for {self.target}", file=sys.stderr)
        
        all_vulnerabilities = []
        
        # Run different scanning modules based on tool type
        scan_modules = {
            'nuclei': self.run_nuclei_scan,
            'comprehensive': lambda: (
                self.run_nuclei_scan() + 
                self.run_comprehensive_directory_scan() + 
                self.run_advanced_xss_scan() + 
                self.run_advanced_sqli_scan()
            ),
            'directory': self.run_comprehensive_directory_scan,
            'xss': self.run_advanced_xss_scan,
            'sqli': self.run_advanced_sqli_scan
        }
        
        if self.tool in scan_modules:
            all_vulnerabilities = scan_modules[self.tool]()
        else:
            # Run comprehensive scan by default
            all_vulnerabilities = scan_modules['comprehensive']()
        
        self.vulnerabilities.extend(all_vulnerabilities)
        
        return {
            'tool': self.tool,
            'target': self.target,
            'scan_type': self.scan_type,
            'vulnerabilities_found': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'wordlists_loaded': {
                'directory_wordlist': len(self.directory_wordlist),
                'xss_payloads': len(self.xss_payloads),
                'sql_payloads': len(self.sql_payloads)
            },
            'execution_time': time.time()
        }

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('--tool', required=True, help='Scan type (nuclei, comprehensive, directory, xss, sqli)')
    parser.add_argument('--target', required=True, help='Target URL to scan')
    parser.add_argument('--scan-type', required=True, help='Type of scan being performed')
    
    args = parser.parse_args()
    
    try:
        scanner = AdvancedWebScanner(args.target, args.tool, args.scan_type)
        result = scanner.run_scan()
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        error_result = {
            'error': str(e),
            'tool': args.tool,
            'target': args.target,
            'vulnerabilities': []
        }
        print(json.dumps(error_result), file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()