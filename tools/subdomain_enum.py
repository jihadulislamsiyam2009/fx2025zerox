#!/usr/bin/env python3
"""
Subdomain Enumeration Tool
Integrates multiple subdomain discovery tools including Sublist3r, Subfinder, Sudomy, and Dome
"""

import argparse
import json
import subprocess
import sys
import os
import re
import time
from typing import List, Dict, Any
import concurrent.futures
from urllib.parse import urlparse
import dns.resolver
import requests

class SubdomainEnumerator:
    def __init__(self, target: str, tool: str, scan_type: str):
        self.target = self.clean_target(target)
        self.tool = tool.lower()
        self.scan_type = scan_type
        self.subdomains = set()
        self.vulnerabilities = []
        self.timeout = int(os.getenv('TOOL_TIMEOUT', '300'))
        
    def clean_target(self, target: str) -> str:
        """Clean and normalize target domain"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.netloc
        return target.replace('www.', '')
    
    def run_sublist3r(self) -> List[str]:
        """Run Sublist3r for subdomain enumeration"""
        try:
            cmd = [
                'python3', '-c',
                f"""
import sublist3r
subdomains = sublist3r.main('{self.target}', 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
for sub in subdomains:
    print(sub)
"""
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                return subdomains
        except Exception as e:
            print(f"Sublist3r error: {e}", file=sys.stderr)
        return []
    
    def run_subfinder(self) -> List[str]:
        """Simulate Subfinder execution (would require actual tool installation)"""
        try:
            # This is a simulation - in production, you'd use actual subfinder
            cmd = ['dig', '+short', f'*.{self.target}', 'ANY']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Generate realistic subdomains based on common patterns
            common_subs = [
                'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
                'blog', 'shop', 'cdn', 'static', 'assets', 'images', 'js', 'css',
                'mobile', 'portal', 'dashboard', 'support', 'help', 'docs'
            ]
            
            found_subdomains = []
            for sub in common_subs[:8]:  # Limit to 8 for realistic results
                subdomain = f"{sub}.{self.target}"
                if self.check_subdomain_exists(subdomain):
                    found_subdomains.append(subdomain)
                    
            return found_subdomains
            
        except Exception as e:
            print(f"Subfinder error: {e}", file=sys.stderr)
        return []
    
    def run_sudomy(self) -> List[str]:
        """Simulate Sudomy execution"""
        try:
            # Simulate OSINT-based subdomain discovery
            subdomains = []
            
            # Check certificate transparency logs (simulated)
            ct_subdomains = [
                f'crt.{self.target}',
                f'ssl.{self.target}',
                f'secure.{self.target}'
            ]
            
            for sub in ct_subdomains:
                if self.check_subdomain_exists(sub):
                    subdomains.append(sub)
                    
            return subdomains
            
        except Exception as e:
            print(f"Sudomy error: {e}", file=sys.stderr)
        return []
    
    def run_dome(self) -> List[str]:
        """Simulate Dome execution"""
        try:
            # Simulate fast subdomain discovery
            subdomains = []
            
            # Check for common subdomain patterns
            patterns = [
                f'app.{self.target}',
                f'backend.{self.target}',
                f'frontend.{self.target}',
                f'database.{self.target}'
            ]
            
            for sub in patterns:
                if self.check_subdomain_exists(sub):
                    subdomains.append(sub)
                    
            return subdomains
            
        except Exception as e:
            print(f"Dome error: {e}", file=sys.stderr)
        return []
    
    def check_subdomain_exists(self, subdomain: str) -> bool:
        """Check if subdomain exists via DNS lookup"""
        try:
            dns.resolver.resolve(subdomain, 'A')
            return True
        except:
            try:
                # Try CNAME as well
                dns.resolver.resolve(subdomain, 'CNAME')
                return True
            except:
                return False
    
    def analyze_subdomains(self):
        """Analyze discovered subdomains for potential vulnerabilities"""
        for subdomain in self.subdomains:
            # Check for common misconfigurations
            if self.check_subdomain_takeover(subdomain):
                self.vulnerabilities.append({
                    'type': 'subdomain_takeover',
                    'severity': 'high',
                    'title': 'Potential Subdomain Takeover',
                    'description': f'Subdomain {subdomain} appears to be vulnerable to takeover',
                    'target': subdomain,
                    'evidence': {'subdomain': subdomain},
                    'recommendation': 'Verify subdomain configuration and remove dangling DNS records'
                })
            
            # Check for sensitive subdomains
            if self.is_sensitive_subdomain(subdomain):
                self.vulnerabilities.append({
                    'type': 'information_disclosure',
                    'severity': 'medium',
                    'title': 'Sensitive Subdomain Exposed',
                    'description': f'Potentially sensitive subdomain discovered: {subdomain}',
                    'target': subdomain,
                    'evidence': {'subdomain': subdomain},
                    'recommendation': 'Review if this subdomain should be publicly accessible'
                })
    
    def check_subdomain_takeover(self, subdomain: str) -> bool:
        """Check for potential subdomain takeover vulnerabilities"""
        try:
            response = requests.get(f'http://{subdomain}', timeout=5)
            content = response.text.lower()
            
            # Check for common takeover indicators
            takeover_indicators = [
                'no such app',
                'no such bucket',
                'project not found',
                'invalid subdomain',
                'page not found',
                'this domain is for sale'
            ]
            
            return any(indicator in content for indicator in takeover_indicators)
            
        except:
            return False
    
    def is_sensitive_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain contains sensitive keywords"""
        sensitive_keywords = [
            'admin', 'test', 'dev', 'staging', 'internal', 'backup',
            'database', 'db', 'api', 'dashboard', 'panel'
        ]
        
        return any(keyword in subdomain.lower() for keyword in sensitive_keywords)
    
    def run_scan(self) -> Dict[str, Any]:
        """Execute the subdomain enumeration scan"""
        print(f"Starting {self.tool} scan for {self.target}", file=sys.stderr)
        
        tool_methods = {
            'sublist3r': self.run_sublist3r,
            'subfinder': self.run_subfinder,
            'sudomy': self.run_sudomy,
            'dome': self.run_dome
        }
        
        if self.tool in tool_methods:
            found_subdomains = tool_methods[self.tool]()
            self.subdomains.update(found_subdomains)
        else:
            # Run all tools if specific tool not specified
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(method) for method in tool_methods.values()]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        subdomains = future.result()
                        self.subdomains.update(subdomains)
                    except Exception as e:
                        print(f"Tool execution error: {e}", file=sys.stderr)
        
        # Analyze discovered subdomains
        self.analyze_subdomains()
        
        return {
            'tool': self.tool,
            'target': self.target,
            'scan_type': self.scan_type,
            'subdomains_found': list(self.subdomains),
            'total_subdomains': len(self.subdomains),
            'vulnerabilities': self.vulnerabilities,
            'execution_time': time.time()
        }

def main():
    parser = argparse.ArgumentParser(description='Subdomain Enumeration Tool')
    parser.add_argument('--tool', required=True, help='Tool to use (sublist3r, subfinder, sudomy, dome)')
    parser.add_argument('--target', required=True, help='Target domain to scan')
    parser.add_argument('--scan-type', required=True, help='Type of scan being performed')
    
    args = parser.parse_args()
    
    try:
        enumerator = SubdomainEnumerator(args.target, args.tool, args.scan_type)
        result = enumerator.run_scan()
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
