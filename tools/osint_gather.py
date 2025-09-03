#!/usr/bin/env python3
"""
OSINT (Open Source Intelligence) Gathering Tool
Comprehensive information gathering from public sources
"""

import argparse
import json
import subprocess
import sys
import os
import re
import time
import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin
import dns.resolver
import whois
from datetime import datetime
import socket
import ssl
import concurrent.futures

class OSINTGatherer:
    def __init__(self, target: str, tool: str, scan_type: str):
        self.target = self.clean_target(target)
        self.tool = tool.lower()
        self.scan_type = scan_type
        self.vulnerabilities = []
        self.intelligence = {}
        self.timeout = int(os.getenv('TOOL_TIMEOUT', '300'))
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecureScan Pro OSINT Gatherer v2.4.1'
        })
        
    def clean_target(self, target: str) -> str:
        """Clean and normalize target domain"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.netloc
        return target.replace('www.', '')
    
    def run_osint_scan(self) -> List[Dict]:
        """Run comprehensive OSINT gathering"""
        vulnerabilities = []
        
        try:
            # Domain information gathering
            domain_info = self.gather_domain_info()
            self.intelligence['domain_info'] = domain_info
            
            # DNS enumeration
            dns_info = self.enumerate_dns_records()
            self.intelligence['dns_records'] = dns_info
            
            # SSL/TLS certificate analysis
            ssl_info = self.analyze_ssl_certificate()
            self.intelligence['ssl_info'] = ssl_info
            
            # Technology stack detection
            tech_stack = self.detect_technology_stack()
            self.intelligence['technology_stack'] = tech_stack
            
            # Social media presence
            social_media = self.gather_social_media_presence()
            self.intelligence['social_media'] = social_media
            
            # Email addresses and contacts
            contacts = self.gather_contact_information()
            self.intelligence['contacts'] = contacts
            
            # Search engine intelligence
            search_intel = self.gather_search_intelligence()
            self.intelligence['search_intelligence'] = search_intel
            
            # Analyze gathered intelligence for vulnerabilities
            analysis_vulns = self.analyze_intelligence()
            vulnerabilities.extend(analysis_vulns)
            
        except Exception as e:
            print(f"OSINT gathering error: {e}", file=sys.stderr)
            
        return vulnerabilities
    
    def gather_domain_info(self) -> Dict:
        """Gather domain registration and WHOIS information"""
        domain_info = {}
        
        try:
            # WHOIS lookup
            whois_data = whois.whois(self.target)
            
            domain_info = {
                'registrar': str(whois_data.registrar) if whois_data.registrar else 'Unknown',
                'creation_date': str(whois_data.creation_date) if whois_data.creation_date else 'Unknown',
                'expiration_date': str(whois_data.expiration_date) if whois_data.expiration_date else 'Unknown',
                'updated_date': str(whois_data.updated_date) if whois_data.updated_date else 'Unknown',
                'name_servers': whois_data.name_servers if whois_data.name_servers else [],
                'registrant_org': str(whois_data.org) if hasattr(whois_data, 'org') and whois_data.org else 'Unknown',
                'registrant_country': str(whois_data.country) if hasattr(whois_data, 'country') and whois_data.country else 'Unknown'
            }
            
            print(f"Domain registered by: {domain_info['registrar']}", file=sys.stderr)
            
        except Exception as e:
            print(f"WHOIS lookup failed: {e}", file=sys.stderr)
            domain_info = {'error': f'WHOIS lookup failed: {str(e)}'}
            
        return domain_info
    
    def enumerate_dns_records(self) -> Dict:
        """Enumerate various DNS record types"""
        dns_records = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                dns_records[record_type] = [str(answer) for answer in answers]
                print(f"Found {len(answers)} {record_type} records", file=sys.stderr)
                
            except dns.resolver.NXDOMAIN:
                dns_records[record_type] = []
            except dns.resolver.NoAnswer:
                dns_records[record_type] = []
            except Exception as e:
                dns_records[record_type] = [f'Error: {str(e)}']
        
        # Check for SPF, DKIM, DMARC records
        email_security = self.check_email_security()
        dns_records['email_security'] = email_security
        
        return dns_records
    
    def check_email_security(self) -> Dict:
        """Check email security configurations"""
        email_security = {}
        
        # Check SPF record
        try:
            txt_records = dns.resolver.resolve(self.target, 'TXT')
            spf_records = [str(record) for record in txt_records if 'v=spf1' in str(record)]
            email_security['spf'] = spf_records
        except:
            email_security['spf'] = []
        
        # Check DMARC record
        try:
            dmarc_domain = f'_dmarc.{self.target}'
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            email_security['dmarc'] = [str(record) for record in dmarc_records]
        except:
            email_security['dmarc'] = []
        
        # Check DKIM (common selector)
        try:
            dkim_domain = f'default._domainkey.{self.target}'
            dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
            email_security['dkim'] = [str(record) for record in dkim_records]
        except:
            email_security['dkim'] = []
        
        return email_security
    
    def analyze_ssl_certificate(self) -> Dict:
        """Analyze SSL/TLS certificate information"""
        ssl_info = {}
        
        try:
            # Get SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                        'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])]
                    }
                    
                    print(f"SSL certificate issued by: {ssl_info['issuer'].get('organizationName', 'Unknown')}", file=sys.stderr)
                    
        except Exception as e:
            print(f"SSL certificate analysis failed: {e}", file=sys.stderr)
            ssl_info = {'error': f'SSL analysis failed: {str(e)}'}
            
        return ssl_info
    
    def detect_technology_stack(self) -> Dict:
        """Detect web technologies and frameworks"""
        tech_stack = {
            'web_server': 'Unknown',
            'programming_languages': [],
            'frameworks': [],
            'cms': 'Unknown',
            'analytics': [],
            'cdn': 'Unknown'
        }
        
        try:
            response = self.session.get(f'https://{self.target}', timeout=10)
            
            # Analyze HTTP headers
            headers = response.headers
            
            # Web server detection
            server_header = headers.get('Server', '')
            if 'apache' in server_header.lower():
                tech_stack['web_server'] = 'Apache'
            elif 'nginx' in server_header.lower():
                tech_stack['web_server'] = 'Nginx'
            elif 'iis' in server_header.lower():
                tech_stack['web_server'] = 'IIS'
            elif server_header:
                tech_stack['web_server'] = server_header
            
            # Programming language detection
            x_powered_by = headers.get('X-Powered-By', '')
            if 'php' in x_powered_by.lower():
                tech_stack['programming_languages'].append('PHP')
            elif 'asp.net' in x_powered_by.lower():
                tech_stack['programming_languages'].append('ASP.NET')
            
            # Framework detection from headers
            if 'laravel' in str(headers).lower():
                tech_stack['frameworks'].append('Laravel')
            elif 'django' in str(headers).lower():
                tech_stack['frameworks'].append('Django')
            elif 'express' in str(headers).lower():
                tech_stack['frameworks'].append('Express.js')
            
            # CDN detection
            if 'cloudflare' in str(headers).lower():
                tech_stack['cdn'] = 'Cloudflare'
            elif 'cloudfront' in str(headers).lower():
                tech_stack['cdn'] = 'Amazon CloudFront'
            
            # Analyze HTML content
            html_content = response.text.lower()
            
            # CMS detection
            if 'wp-content' in html_content or 'wordpress' in html_content:
                tech_stack['cms'] = 'WordPress'
            elif 'drupal' in html_content:
                tech_stack['cms'] = 'Drupal'
            elif 'joomla' in html_content:
                tech_stack['cms'] = 'Joomla'
            
            # Analytics detection
            if 'google-analytics' in html_content or 'gtag' in html_content:
                tech_stack['analytics'].append('Google Analytics')
            if 'facebook.com/tr' in html_content:
                tech_stack['analytics'].append('Facebook Pixel')
            
            # JavaScript framework detection
            if 'react' in html_content:
                tech_stack['frameworks'].append('React')
            elif 'angular' in html_content:
                tech_stack['frameworks'].append('Angular')
            elif 'vue' in html_content:
                tech_stack['frameworks'].append('Vue.js')
            
            print(f"Detected web server: {tech_stack['web_server']}", file=sys.stderr)
            
        except Exception as e:
            print(f"Technology detection failed: {e}", file=sys.stderr)
            
        return tech_stack
    
    def gather_social_media_presence(self) -> Dict:
        """Gather social media presence information"""
        social_media = {}
        
        # Common social media platforms
        platforms = {
            'facebook': f'https://www.facebook.com/{self.target.split(".")[0]}',
            'twitter': f'https://twitter.com/{self.target.split(".")[0]}',
            'linkedin': f'https://www.linkedin.com/company/{self.target.split(".")[0]}',
            'instagram': f'https://www.instagram.com/{self.target.split(".")[0]}',
            'youtube': f'https://www.youtube.com/c/{self.target.split(".")[0]}'
        }
        
        for platform, url in platforms.items():
            try:
                response = self.session.head(url, timeout=5)
                if response.status_code == 200:
                    social_media[platform] = {
                        'url': url,
                        'status': 'Found',
                        'status_code': response.status_code
                    }
                    print(f"Found {platform} presence", file=sys.stderr)
                else:
                    social_media[platform] = {
                        'url': url,
                        'status': 'Not Found',
                        'status_code': response.status_code
                    }
            except:
                social_media[platform] = {
                    'url': url,
                    'status': 'Error',
                    'status_code': None
                }
        
        return social_media
    
    def gather_contact_information(self) -> Dict:
        """Gather contact information and email addresses"""
        contacts = {
            'emails': [],
            'phone_numbers': [],
            'addresses': []
        }
        
        try:
            # Get main page content
            response = self.session.get(f'https://{self.target}', timeout=10)
            content = response.text
            
            # Extract email addresses
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, content)
            contacts['emails'] = list(set(emails))  # Remove duplicates
            
            # Extract phone numbers (basic patterns)
            phone_patterns = [
                r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
                r'\+?[0-9]{1,3}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}'
            ]
            
            for pattern in phone_patterns:
                phones = re.findall(pattern, content)
                contacts['phone_numbers'].extend(phones)
            
            contacts['phone_numbers'] = list(set(contacts['phone_numbers']))
            
            # Try to get contact page for more information
            contact_urls = ['/contact', '/contact-us', '/about', '/about-us']
            for contact_url in contact_urls:
                try:
                    contact_response = self.session.get(f'https://{self.target}{contact_url}', timeout=5)
                    if contact_response.status_code == 200:
                        contact_emails = re.findall(email_pattern, contact_response.text)
                        contacts['emails'].extend(contact_emails)
                        
                        contact_phones = []
                        for pattern in phone_patterns:
                            phones = re.findall(pattern, contact_response.text)
                            contact_phones.extend(phones)
                        contacts['phone_numbers'].extend(contact_phones)
                        
                        break
                except:
                    continue
            
            # Remove duplicates
            contacts['emails'] = list(set(contacts['emails']))
            contacts['phone_numbers'] = list(set(contacts['phone_numbers']))
            
            print(f"Found {len(contacts['emails'])} email addresses", file=sys.stderr)
            
        except Exception as e:
            print(f"Contact information gathering failed: {e}", file=sys.stderr)
            
        return contacts
    
    def gather_search_intelligence(self) -> Dict:
        """Gather intelligence from search engines (simulated)"""
        search_intel = {
            'indexed_pages': 'Unknown',
            'cached_pages': [],
            'related_domains': [],
            'mentions': []
        }
        
        try:
            # In a real implementation, this would query search engines
            # For simulation, we'll provide realistic data structure
            
            # Check for robots.txt
            robots_response = self.session.get(f'https://{self.target}/robots.txt', timeout=5)
            if robots_response.status_code == 200:
                search_intel['robots_txt'] = {
                    'exists': True,
                    'content': robots_response.text[:500]  # First 500 chars
                }
                print("Found robots.txt file", file=sys.stderr)
            else:
                search_intel['robots_txt'] = {'exists': False}
            
            # Check for sitemap.xml
            sitemap_response = self.session.get(f'https://{self.target}/sitemap.xml', timeout=5)
            if sitemap_response.status_code == 200:
                search_intel['sitemap'] = {
                    'exists': True,
                    'content_length': len(sitemap_response.text)
                }
                print("Found sitemap.xml file", file=sys.stderr)
            else:
                search_intel['sitemap'] = {'exists': False}
            
        except Exception as e:
            print(f"Search intelligence gathering failed: {e}", file=sys.stderr)
            
        return search_intel
    
    def analyze_intelligence(self) -> List[Dict]:
        """Analyze gathered intelligence for security implications"""
        vulnerabilities = []
        
        # Analyze domain information
        domain_info = self.intelligence.get('domain_info', {})
        if domain_info.get('expiration_date') and domain_info['expiration_date'] != 'Unknown':
            try:
                # Check if domain is expiring soon (simplified check)
                if 'error' not in domain_info:
                    vulnerabilities.append(self.create_vulnerability(
                        'domain_information_disclosure',
                        'low',
                        'Domain Registration Information Exposed',
                        'Domain registration details are publicly available via WHOIS',
                        self.target,
                        {'whois_data': domain_info},
                        'Consider domain privacy protection services'
                    ))
            except:
                pass
        
        # Analyze email security
        dns_records = self.intelligence.get('dns_records', {})
        email_security = dns_records.get('email_security', {})
        
        if not email_security.get('spf'):
            vulnerabilities.append(self.create_vulnerability(
                'missing_spf_record',
                'medium',
                'Missing SPF Record',
                'Domain lacks SPF record, making it vulnerable to email spoofing',
                self.target,
                {'missing_record': 'SPF'},
                'Configure SPF record to prevent email spoofing'
            ))
        
        if not email_security.get('dmarc'):
            vulnerabilities.append(self.create_vulnerability(
                'missing_dmarc_record',
                'medium',
                'Missing DMARC Record',
                'Domain lacks DMARC record, reducing email security',
                self.target,
                {'missing_record': 'DMARC'},
                'Configure DMARC record for email authentication'
            ))
        
        # Analyze SSL certificate
        ssl_info = self.intelligence.get('ssl_info', {})
        if ssl_info and 'error' not in ssl_info:
            # Check certificate expiration (simplified)
            not_after = ssl_info.get('not_after')
            if not_after:
                vulnerabilities.append(self.create_vulnerability(
                    'ssl_certificate_info',
                    'low',
                    'SSL Certificate Information Disclosure',
                    'SSL certificate exposes organizational information',
                    f'{self.target}:443',
                    {'certificate_info': ssl_info},
                    'Monitor certificate expiration and consider certificate transparency'
                ))
        
        # Analyze technology stack
        tech_stack = self.intelligence.get('technology_stack', {})
        
        # Check for information disclosure in headers
        if tech_stack.get('web_server') != 'Unknown':
            vulnerabilities.append(self.create_vulnerability(
                'server_information_disclosure',
                'low',
                'Web Server Information Disclosure',
                f'Server header reveals web server: {tech_stack["web_server"]}',
                self.target,
                {'disclosed_server': tech_stack['web_server']},
                'Configure server to hide version information'
            ))
        
        # Check for outdated technologies
        if 'PHP' in tech_stack.get('programming_languages', []):
            vulnerabilities.append(self.create_vulnerability(
                'technology_disclosure',
                'low',
                'Technology Stack Information Disclosure',
                'Web application technology stack is detectable',
                self.target,
                {'technologies': tech_stack},
                'Minimize technology fingerprinting opportunities'
            ))
        
        # Analyze contact information exposure
        contacts = self.intelligence.get('contacts', {})
        if contacts.get('emails'):
            vulnerabilities.append(self.create_vulnerability(
                'email_disclosure',
                'low',
                'Email Address Exposure',
                f'Found {len(contacts["emails"])} email addresses exposed on website',
                self.target,
                {'exposed_emails': contacts['emails']},
                'Consider using contact forms instead of exposing email addresses'
            ))
        
        # Analyze search intelligence
        search_intel = self.intelligence.get('search_intelligence', {})
        robots_txt = search_intel.get('robots_txt', {})
        
        if robots_txt.get('exists') and robots_txt.get('content'):
            # Check for potentially sensitive paths in robots.txt
            sensitive_paths = ['admin', 'administrator', 'login', 'wp-admin', 'backup']
            robots_content = robots_txt.get('content', '').lower()
            
            for path in sensitive_paths:
                if path in robots_content:
                    vulnerabilities.append(self.create_vulnerability(
                        'robots_txt_information_disclosure',
                        'medium',
                        'Robots.txt Information Disclosure',
                        f'Robots.txt file reveals potentially sensitive path: {path}',
                        f'{self.target}/robots.txt',
                        {'robots_content': robots_content[:200]},
                        'Review robots.txt for sensitive path disclosures'
                    ))
                    break
        
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
        """Execute the OSINT gathering scan"""
        print(f"Starting OSINT gathering for {self.target}", file=sys.stderr)
        
        vulnerabilities = self.run_osint_scan()
        self.vulnerabilities.extend(vulnerabilities)
        
        return {
            'tool': self.tool,
            'target': self.target,
            'scan_type': self.scan_type,
            'intelligence_gathered': self.intelligence,
            'vulnerabilities_found': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'execution_time': time.time()
        }

def main():
    parser = argparse.ArgumentParser(description='OSINT Gathering Tool')
    parser.add_argument('--tool', required=True, help='Tool identifier for OSINT gathering')
    parser.add_argument('--target', required=True, help='Target domain to investigate')
    parser.add_argument('--scan-type', required=True, help='Type of scan being performed')
    
    args = parser.parse_args()
    
    try:
        gatherer = OSINTGatherer(args.target, args.tool, args.scan_type)
        result = gatherer.run_scan()
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
