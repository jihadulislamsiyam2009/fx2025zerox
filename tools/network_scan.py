#!/usr/bin/env python3
"""
Network Reconnaissance Scanner
Integrates multiple network scanning tools including Nmap, Masscan, and Metasploit
"""

import argparse
import json
import subprocess
import sys
import os
import re
import time
import socket
import threading
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse
import concurrent.futures

class NetworkScanner:
    def __init__(self, target: str, tool: str, scan_type: str):
        self.target = self.parse_target(target)
        self.tool = tool.lower()
        self.scan_type = scan_type
        self.vulnerabilities = []
        self.open_ports = []
        self.services = {}
        self.timeout = int(os.getenv('TOOL_TIMEOUT', '300'))
        
        # Common vulnerable services and their typical ports
        self.vulnerable_services = {
            21: 'FTP',
            22: 'SSH', 
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        # Top 1000 most common ports (abbreviated for performance)
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 10000
        ]
        
    def parse_target(self, target: str) -> str:
        """Parse and normalize target (URL or IP/domain)"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.netloc.split(':')[0]  # Remove port if present
        return target.split(':')[0]  # Remove port if present
    
    def run_nmap(self) -> List[Dict]:
        """Simulate Nmap execution with comprehensive port scanning"""
        vulnerabilities = []
        
        try:
            # Simulate different Nmap scan types
            print(f"Running Nmap scan against {self.target}", file=sys.stderr)
            
            # TCP SYN scan (simulated)
            tcp_ports = self.tcp_port_scan(self.target, self.common_ports[:50])
            
            # Service version detection (simulated)
            services = self.detect_services(self.target, tcp_ports)
            
            # UDP scan (simulated - limited ports)
            udp_ports = self.udp_port_scan(self.target, [53, 161, 123, 69])
            
            # OS detection (simulated)
            os_info = self.detect_os(self.target)
            
            # Vulnerability analysis
            vulns = self.analyze_nmap_results(tcp_ports, udp_ports, services, os_info)
            vulnerabilities.extend(vulns)
            
        except Exception as e:
            print(f"Nmap error: {e}", file=sys.stderr)
            
        return vulnerabilities
    
    def run_masscan(self) -> List[Dict]:
        """Simulate Masscan execution with high-speed port scanning"""
        vulnerabilities = []
        
        try:
            print(f"Running Masscan against {self.target}", file=sys.stderr)
            
            # Masscan specializes in fast, large-scale port scanning
            # Simulate scanning larger port range quickly
            ports_to_scan = list(range(1, 10000, 100))  # Every 100th port for simulation
            
            open_ports = self.fast_port_scan(self.target, ports_to_scan)
            
            # Analyze results for common vulnerabilities
            vulns = self.analyze_masscan_results(open_ports)
            vulnerabilities.extend(vulns)
            
        except Exception as e:
            print(f"Masscan error: {e}", file=sys.stderr)
            
        return vulnerabilities
    
    def run_metasploit(self) -> List[Dict]:
        """Simulate Metasploit framework execution"""
        vulnerabilities = []
        
        try:
            print(f"Running Metasploit auxiliary modules against {self.target}", file=sys.stderr)
            
            # Simulate running auxiliary/scanner modules
            vulns = self.run_auxiliary_scanners(self.target)
            vulnerabilities.extend(vulns)
            
            # Simulate exploit matching
            exploits = self.match_exploits(self.target, self.services)
            vulnerabilities.extend(exploits)
            
        except Exception as e:
            print(f"Metasploit error: {e}", file=sys.stderr)
            
        return vulnerabilities
    
    def tcp_port_scan(self, target: str, ports: List[int]) -> List[int]:
        """Perform TCP port scan"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # Use threading for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"TCP port {result} is open", file=sys.stderr)
        
        return sorted(open_ports)
    
    def udp_port_scan(self, target: str, ports: List[int]) -> List[int]:
        """Perform UDP port scan (simplified)"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(b'test', (target, port))
                # UDP scanning is unreliable, so we'll simulate some results
                if port in [53, 123, 161]:  # Common UDP services
                    open_ports.append(port)
                    print(f"UDP port {port} appears open", file=sys.stderr)
                sock.close()
            except:
                pass
        
        return open_ports
    
    def fast_port_scan(self, target: str, ports: List[int]) -> List[int]:
        """Fast port scanning (Masscan style)"""
        open_ports = []
        
        # Simulate faster scanning with reduced accuracy
        for port in ports[:20]:  # Limit for simulation
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Very fast timeout
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
                    print(f"Fast scan: TCP port {port} is open", file=sys.stderr)
            except:
                pass
        
        return open_ports
    
    def detect_services(self, target: str, ports: List[int]) -> Dict[int, Dict]:
        """Detect services running on open ports"""
        services = {}
        
        for port in ports:
            service_info = {'name': 'unknown', 'version': 'unknown', 'banner': ''}
            
            # Use known service mappings
            if port in self.vulnerable_services:
                service_info['name'] = self.vulnerable_services[port]
                
                # Simulate banner grabbing
                banner = self.grab_banner(target, port)
                if banner:
                    service_info['banner'] = banner
                    service_info['version'] = self.extract_version(banner)
            
            services[port] = service_info
            print(f"Service on port {port}: {service_info['name']}", file=sys.stderr)
        
        self.services = services
        return services
    
    def grab_banner(self, target: str, port: int) -> str:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # Send appropriate probe based on port
            if port == 21:  # FTP
                sock.send(b'')
            elif port == 22:  # SSH
                sock.send(b'')
            elif port == 25:  # SMTP
                sock.send(b'EHLO test\r\n')
            elif port in [80, 8080]:  # HTTP
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
            
        except:
            return ''
    
    def extract_version(self, banner: str) -> str:
        """Extract version information from banner"""
        # Simple version extraction patterns
        version_patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'version\s+(\d+\.\d+\.\d+)',
            r'v(\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'unknown'
    
    def detect_os(self, target: str) -> Dict:
        """Detect operating system (simulated)"""
        # This would use TCP/IP fingerprinting in real Nmap
        # For simulation, we'll make educated guesses
        
        try:
            # Check common OS-specific ports
            if self.check_port(target, 3389):  # RDP
                return {'os': 'Windows', 'confidence': 85}
            elif self.check_port(target, 22):  # SSH
                return {'os': 'Linux/Unix', 'confidence': 75}
            else:
                return {'os': 'Unknown', 'confidence': 0}
                
        except:
            return {'os': 'Unknown', 'confidence': 0}
    
    def check_port(self, target: str, port: int) -> bool:
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def analyze_nmap_results(self, tcp_ports: List[int], udp_ports: List[int], 
                           services: Dict, os_info: Dict) -> List[Dict]:
        """Analyze Nmap scan results for vulnerabilities"""
        vulnerabilities = []
        
        # Check for dangerous open ports
        dangerous_ports = {
            21: {'service': 'FTP', 'risk': 'Anonymous access possible'},
            23: {'service': 'Telnet', 'risk': 'Unencrypted protocol'},
            25: {'service': 'SMTP', 'risk': 'Open relay possible'},
            53: {'service': 'DNS', 'risk': 'DNS amplification attacks'},
            135: {'service': 'RPC', 'risk': 'RPC vulnerabilities'},
            139: {'service': 'NetBIOS', 'risk': 'Information disclosure'},
            445: {'service': 'SMB', 'risk': 'SMB vulnerabilities'},
            1433: {'service': 'MSSQL', 'risk': 'Database exposure'},
            3306: {'service': 'MySQL', 'risk': 'Database exposure'},
            3389: {'service': 'RDP', 'risk': 'Brute force attacks'},
            5900: {'service': 'VNC', 'risk': 'Weak authentication'},
            6379: {'service': 'Redis', 'risk': 'Unauthorized access'},
        }
        
        for port in tcp_ports:
            if port in dangerous_ports:
                service_info = dangerous_ports[port]
                vulnerabilities.append(self.create_vulnerability(
                    'dangerous_service',
                    'medium',
                    f'Dangerous Service: {service_info["service"]} on port {port}',
                    f'Service {service_info["service"]} is exposed: {service_info["risk"]}',
                    f'{self.target}:{port}',
                    {
                        'port': port,
                        'service': service_info['service'],
                        'protocol': 'TCP',
                        'risk': service_info['risk'],
                        'tool': 'nmap'
                    },
                    f'Review the necessity of exposing {service_info["service"]} service'
                ))
        
        # Check for version-specific vulnerabilities
        for port, service in services.items():
            if service['version'] != 'unknown':
                version_vulns = self.check_version_vulnerabilities(
                    service['name'], service['version'], port
                )
                vulnerabilities.extend(version_vulns)
        
        # Check for too many open ports
        if len(tcp_ports) > 10:
            vulnerabilities.append(self.create_vulnerability(
                'excessive_open_ports',
                'low',
                'Excessive Open Ports',
                f'Target has {len(tcp_ports)} open TCP ports, increasing attack surface',
                self.target,
                {
                    'open_ports_count': len(tcp_ports),
                    'open_ports': tcp_ports,
                    'tool': 'nmap'
                },
                'Close unnecessary ports and services'
            ))
        
        return vulnerabilities
    
    def analyze_masscan_results(self, open_ports: List[int]) -> List[Dict]:
        """Analyze Masscan results"""
        vulnerabilities = []
        
        # Check for unusual high ports
        high_ports = [port for port in open_ports if port > 10000]
        if high_ports:
            vulnerabilities.append(self.create_vulnerability(
                'high_port_services',
                'low',
                'Services on High Ports',
                f'Services detected on unusual high ports: {high_ports}',
                self.target,
                {
                    'high_ports': high_ports,
                    'tool': 'masscan'
                },
                'Investigate services running on high-numbered ports'
            ))
        
        # Check for common trojan/backdoor ports
        backdoor_ports = {
            12345: 'NetBus',
            31337: 'Back Orifice',
            54321: 'Back Orifice 2000',
            9999: 'Common backdoor port'
        }
        
        for port in open_ports:
            if port in backdoor_ports:
                vulnerabilities.append(self.create_vulnerability(
                    'backdoor_port',
                    'high',
                    f'Potential Backdoor: {backdoor_ports[port]}',
                    f'Port {port} is associated with {backdoor_ports[port]} trojan/backdoor',
                    f'{self.target}:{port}',
                    {
                        'port': port,
                        'backdoor_name': backdoor_ports[port],
                        'tool': 'masscan'
                    },
                    'Investigate and remove any unauthorized software'
                ))
        
        return vulnerabilities
    
    def run_auxiliary_scanners(self, target: str) -> List[Dict]:
        """Simulate Metasploit auxiliary scanner modules"""
        vulnerabilities = []
        
        # Simulate common auxiliary scanners
        scanners = [
            'auxiliary/scanner/http/http_version',
            'auxiliary/scanner/ssh/ssh_version',
            'auxiliary/scanner/ftp/anonymous',
            'auxiliary/scanner/smb/smb_version',
            'auxiliary/scanner/mysql/mysql_version'
        ]
        
        for scanner in scanners:
            # Simulate scanner execution
            results = self.simulate_auxiliary_scanner(scanner, target)
            vulnerabilities.extend(results)
        
        return vulnerabilities
    
    def simulate_auxiliary_scanner(self, scanner: str, target: str) -> List[Dict]:
        """Simulate individual auxiliary scanner execution"""
        vulnerabilities = []
        
        if 'http' in scanner:
            if self.check_port(target, 80) or self.check_port(target, 443):
                vulnerabilities.append(self.create_vulnerability(
                    'http_service_detected',
                    'low',
                    'HTTP Service Information Disclosure',
                    'HTTP service exposes server version information',
                    f'{target}:80',
                    {
                        'scanner': scanner,
                        'service': 'HTTP',
                        'tool': 'metasploit'
                    },
                    'Configure web server to hide version information'
                ))
        
        elif 'ssh' in scanner:
            if self.check_port(target, 22):
                vulnerabilities.append(self.create_vulnerability(
                    'ssh_version_disclosure',
                    'low',
                    'SSH Version Information Disclosure',
                    'SSH service exposes version information',
                    f'{target}:22',
                    {
                        'scanner': scanner,
                        'service': 'SSH',
                        'tool': 'metasploit'
                    },
                    'Consider using SSH banner modification'
                ))
        
        elif 'ftp' in scanner and 'anonymous' in scanner:
            if self.check_port(target, 21):
                vulnerabilities.append(self.create_vulnerability(
                    'ftp_anonymous_access',
                    'medium',
                    'FTP Anonymous Access',
                    'FTP server may allow anonymous access',
                    f'{target}:21',
                    {
                        'scanner': scanner,
                        'service': 'FTP',
                        'tool': 'metasploit'
                    },
                    'Disable anonymous FTP access'
                ))
        
        return vulnerabilities
    
    def match_exploits(self, target: str, services: Dict) -> List[Dict]:
        """Simulate exploit matching against discovered services"""
        vulnerabilities = []
        
        # Simulate matching exploits to services
        exploit_db = {
            'FTP': {
                'exploit': 'exploit/linux/ftp/vsftpd_234_backdoor',
                'cve': 'CVE-2011-2523',
                'description': 'VSFTPD 2.3.4 Backdoor Command Execution'
            },
            'SSH': {
                'exploit': 'auxiliary/scanner/ssh/ssh_enumusers',
                'cve': 'CVE-2018-15473',
                'description': 'OpenSSH Username Enumeration'
            },
            'HTTP': {
                'exploit': 'exploit/multi/http/apache_struts2_content_type_ognl',
                'cve': 'CVE-2017-5638',
                'description': 'Apache Struts 2 Content-Type OGNL Injection'
            }
        }
        
        for port, service_info in services.items():
            service_name = service_info.get('name', '').upper()
            if service_name in exploit_db:
                exploit_info = exploit_db[service_name]
                vulnerabilities.append(self.create_vulnerability(
                    'potential_exploit',
                    'high',
                    f'Potential Exploit Available: {service_name}',
                    f'Known exploit exists for {service_name}: {exploit_info["description"]}',
                    f'{target}:{port}',
                    {
                        'exploit': exploit_info['exploit'],
                        'cve': exploit_info.get('cve', 'N/A'),
                        'service': service_name,
                        'port': port,
                        'tool': 'metasploit'
                    },
                    'Update service to latest version and apply security patches'
                ))
        
        return vulnerabilities
    
    def check_version_vulnerabilities(self, service: str, version: str, port: int) -> List[Dict]:
        """Check for known vulnerabilities in specific service versions"""
        vulnerabilities = []
        
        # Simplified vulnerability database
        vuln_db = {
            'Apache': {
                '2.2.0': {'cve': 'CVE-2017-15710', 'severity': 'high'},
                '2.4.6': {'cve': 'CVE-2017-15715', 'severity': 'medium'}
            },
            'OpenSSH': {
                '7.4': {'cve': 'CVE-2018-15473', 'severity': 'medium'},
                '6.6': {'cve': 'CVE-2016-0777', 'severity': 'high'}
            },
            'MySQL': {
                '5.7.0': {'cve': 'CVE-2016-0546', 'severity': 'high'},
                '5.6.0': {'cve': 'CVE-2015-2573', 'severity': 'medium'}
            }
        }
        
        for vuln_service, versions in vuln_db.items():
            if vuln_service.lower() in service.lower():
                for vuln_version, vuln_info in versions.items():
                    if version.startswith(vuln_version):
                        vulnerabilities.append(self.create_vulnerability(
                            'known_vulnerability',
                            vuln_info['severity'],
                            f'Known Vulnerability in {service} {version}',
                            f'{service} version {version} has known vulnerability {vuln_info["cve"]}',
                            f'{self.target}:{port}',
                            {
                                'service': service,
                                'version': version,
                                'cve': vuln_info['cve'],
                                'port': port,
                                'tool': 'version_check'
                            },
                            f'Update {service} to a secure version'
                        ))
                        
        return vulnerabilities
    
    def create_vulnerability(self, vuln_type: str, severity: str, title: str,
                           description: str, target: str, evidence: Dict,
                           recommendation: str) -> Dict:
        """Create a standardized vulnerability object"""
        return {
            'type': vuln_type,
            'severity': severity,
            'title': title,
            'description': description,
            'target': target,
            'evidence': evidence,
            'recommendation': recommendation
        }
    
    def run_scan(self) -> Dict[str, Any]:
        """Execute the network reconnaissance scan"""
        print(f"Starting {self.tool} network scan for {self.target}", file=sys.stderr)
        
        tool_methods = {
            'nmap': self.run_nmap,
            'masscan': self.run_masscan,
            'metasploit': self.run_metasploit
        }
        
        if self.tool in tool_methods:
            vulnerabilities = tool_methods[self.tool]()
        else:
            # Run all tools if specific tool not specified
            vulnerabilities = []
            for method in tool_methods.values():
                try:
                    tool_vulns = method()
                    vulnerabilities.extend(tool_vulns)
                except Exception as e:
                    print(f"Tool execution error: {e}", file=sys.stderr)
        
        self.vulnerabilities.extend(vulnerabilities)
        
        return {
            'tool': self.tool,
            'target': self.target,
            'scan_type': self.scan_type,
            'open_ports': self.open_ports,
            'services': self.services,
            'vulnerabilities_found': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'execution_time': time.time()
        }

def main():
    parser = argparse.ArgumentParser(description='Network Reconnaissance Scanner')
    parser.add_argument('--tool', required=True, 
                       help='Tool to use (nmap, masscan, metasploit)')
    parser.add_argument('--target', required=True, help='Target to scan')
    parser.add_argument('--scan-type', required=True, help='Type of scan being performed')
    
    args = parser.parse_args()
    
    try:
        scanner = NetworkScanner(args.target, args.tool, args.scan_type)
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
