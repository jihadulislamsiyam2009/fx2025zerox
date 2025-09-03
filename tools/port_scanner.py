#!/usr/bin/env python3
"""
Advanced Port Scanner and Service Enumeration
Combines multiple port scanning techniques for comprehensive discovery
"""

import subprocess
import sys
import json
import socket
import threading
from datetime import datetime
import time
import requests

class PortScanner:
    def __init__(self, target):
        self.target = target
        self.results = {
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "banners": [],
            "ssl_info": []
        }
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
            135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900,
            6379, 8080, 8443, 8888, 9000, 9200, 27017
        ]
        self.all_ports = list(range(1, 1025))  # Common ports 1-1024

    def log_output(self, message):
        print(f"[PORT_SCANNER] {message}")

    def scan_port(self, port, timeout=3):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                return True
            return False
        except:
            return False

    def get_service_banner(self, port, timeout=5):
        """Try to get service banner information"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.target, port))
            
            # Send basic HTTP request for web services
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port in [443, 8443]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:  # FTP
                pass  # FTP usually sends banner immediately
            elif port == 22:  # SSH
                pass  # SSH sends banner immediately
            elif port == 25:  # SMTP
                pass  # SMTP sends banner immediately
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner
        except:
            return None

    def identify_service(self, port, banner=None):
        """Identify service running on port"""
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            135: "RPC",
            139: "NetBIOS",
            445: "SMB",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            8888: "HTTP-Alt",
            9000: "HTTP-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB"
        }
        
        service = service_map.get(port, "Unknown")
        
        # Try to identify service from banner
        if banner:
            banner_lower = banner.lower()
            if "apache" in banner_lower:
                service += " (Apache)"
            elif "nginx" in banner_lower:
                service += " (Nginx)"
            elif "microsoft" in banner_lower:
                service += " (Microsoft)"
            elif "openssh" in banner_lower:
                service += " (OpenSSH)"
            elif "vsftpd" in banner_lower:
                service += " (vsftpd)"
            elif "mysql" in banner_lower:
                service += " (MySQL)"
            elif "postgresql" in banner_lower:
                service += " (PostgreSQL)"
        
        return service

    def check_http_service(self, port):
        """Check HTTP service for additional information"""
        try:
            protocols = ["http", "https"] if port == 443 or port == 8443 else ["http"]
            
            for protocol in protocols:
                url = f"{protocol}://{self.target}:{port}"
                try:
                    response = requests.get(url, timeout=5, verify=False)
                    
                    service_info = {
                        "port": port,
                        "protocol": protocol,
                        "status_code": response.status_code,
                        "server": response.headers.get("Server", "Unknown"),
                        "content_type": response.headers.get("Content-Type", "Unknown"),
                        "content_length": len(response.content),
                        "title": self.extract_title(response.text),
                        "technologies": self.detect_technologies(response)
                    }
                    
                    self.results["services"].append(service_info)
                    
                    # Check for common vulnerabilities
                    self.check_web_vulnerabilities(url, response)
                    
                    return service_info
                except:
                    continue
                    
        except Exception as e:
            return None

    def extract_title(self, html):
        """Extract title from HTML"""
        try:
            start = html.lower().find("<title>")
            if start != -1:
                start += 7
                end = html.lower().find("</title>", start)
                if end != -1:
                    return html[start:end].strip()
        except:
            pass
        return "No title"

    def detect_technologies(self, response):
        """Detect web technologies from response"""
        technologies = []
        
        # Check headers
        headers = response.headers
        if "X-Powered-By" in headers:
            technologies.append(headers["X-Powered-By"])
        
        # Check content for common patterns
        content = response.text.lower()
        if "wordpress" in content or "wp-content" in content:
            technologies.append("WordPress")
        elif "drupal" in content:
            technologies.append("Drupal")
        elif "joomla" in content:
            technologies.append("Joomla")
        elif "laravel" in content:
            technologies.append("Laravel")
        elif "react" in content:
            technologies.append("React")
        elif "angular" in content:
            technologies.append("Angular")
        elif "vue" in content:
            technologies.append("Vue.js")
        
        return technologies

    def check_web_vulnerabilities(self, url, response):
        """Check for common web vulnerabilities"""
        try:
            # Check for missing security headers
            headers = response.headers
            missing_headers = []
            
            security_headers = [
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security",
                "Content-Security-Policy"
            ]
            
            for header in security_headers:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.results["vulnerabilities"].append({
                    "type": "Missing Security Headers",
                    "target": url,
                    "details": missing_headers,
                    "severity": "Medium"
                })
            
            # Check for directory listing
            if "Index of /" in response.text or "Directory Listing" in response.text:
                self.results["vulnerabilities"].append({
                    "type": "Directory Listing Enabled",
                    "target": url,
                    "details": "Directory listing is enabled",
                    "severity": "Low"
                })
            
            # Check for default pages
            content_lower = response.text.lower()
            if "apache" in content_lower and "test page" in content_lower:
                self.results["vulnerabilities"].append({
                    "type": "Default Apache Page",
                    "target": url,
                    "details": "Default Apache test page detected",
                    "severity": "Low"
                })
                
        except Exception as e:
            pass

    def scan_common_ports(self):
        """Scan common ports quickly"""
        self.log_output(f"Scanning common ports on {self.target}")
        
        open_ports = []
        for port in self.common_ports:
            if self.scan_port(port):
                open_ports.append(port)
                self.log_output(f"Port {port} is open")
                
                # Get banner information
                banner = self.get_service_banner(port)
                service = self.identify_service(port, banner)
                
                port_info = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner or "No banner",
                    "timestamp": datetime.now().isoformat()
                }
                
                self.results["open_ports"].append(port_info)
                
                if banner:
                    self.results["banners"].append({
                        "port": port,
                        "banner": banner,
                        "service": service
                    })
                
                # Check HTTP services
                if port in [80, 443, 8080, 8443, 8000, 8888, 9000]:
                    self.check_http_service(port)
        
        return open_ports

    def scan_all_ports(self):
        """Scan all ports (slower but comprehensive)"""
        self.log_output(f"Scanning all ports 1-1024 on {self.target}")
        
        def scan_port_range(start, end):
            for port in range(start, end):
                if self.scan_port(port, timeout=1):
                    banner = self.get_service_banner(port)
                    service = self.identify_service(port, banner)
                    
                    port_info = {
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner or "No banner",
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    self.results["open_ports"].append(port_info)
                    self.log_output(f"Port {port} is open - {service}")
        
        # Use threading for faster scanning
        threads = []
        chunk_size = 100
        
        for i in range(1, 1025, chunk_size):
            end = min(i + chunk_size, 1025)
            thread = threading.Thread(target=scan_port_range, args=(i, end))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    def scan(self, full_scan=False):
        """Run port scanning"""
        self.log_output(f"Starting port scan on {self.target}")
        start_time = time.time()
        
        if full_scan:
            self.scan_all_ports()
        else:
            self.scan_common_ports()
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Summary
        open_ports_count = len(self.results["open_ports"])
        services_count = len(self.results["services"])
        vulnerabilities_count = len(self.results["vulnerabilities"])
        
        self.log_output(f"Port scan completed in {scan_duration:.2f} seconds:")
        self.log_output(f"- Open ports: {open_ports_count}")
        self.log_output(f"- Services identified: {services_count}")
        self.log_output(f"- Vulnerabilities found: {vulnerabilities_count}")
        
        return self.results

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner.py <target> [--full]")
        sys.exit(1)
    
    target = sys.argv[1]
    full_scan = "--full" in sys.argv
    
    scanner = PortScanner(target)
    results = scanner.scan(full_scan)
    
    # Output results in JSON format
    print("RESULTS_START")
    print(json.dumps(results, indent=2))
    print("RESULTS_END")

if __name__ == "__main__":
    main()