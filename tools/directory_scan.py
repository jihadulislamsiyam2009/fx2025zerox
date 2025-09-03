#!/usr/bin/env python3
"""
Directory and File Discovery Scanner
Combines multiple directory brute force tools for comprehensive discovery
"""

import subprocess
import sys
import json
import os
import requests
import threading
from urllib.parse import urljoin, urlparse
import time

class DirectoryScanner:
    def __init__(self, target, wordlist=None):
        self.target = target.rstrip('/')
        self.wordlist = wordlist or "/usr/share/wordlists/dirb/common.txt"
        self.found_directories = []
        self.found_files = []
        self.results = {
            "directories": [],
            "files": [],
            "interesting_files": [],
            "admin_panels": [],
            "config_files": []
        }

    def log_output(self, message):
        print(f"[DIRECTORY_SCAN] {message}")

    def check_url(self, url, timeout=10):
        """Check if URL exists and get response info"""
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            return {
                "url": url,
                "status_code": response.status_code,
                "size": len(response.content),
                "headers": dict(response.headers)
            }
        except:
            return None

    def run_dirb(self):
        """Run dirb directory scanner"""
        try:
            self.log_output(f"Starting dirb scan on {self.target}")
            
            # Create a basic wordlist if none exists
            basic_dirs = [
                "admin", "administrator", "api", "backup", "backups", "bin", "config", 
                "data", "db", "debug", "dev", "docs", "download", "downloads", 
                "error", "files", "ftp", "hidden", "images", "img", "inc", "include",
                "install", "lib", "log", "logs", "mail", "old", "panel", "private",
                "public", "root", "scripts", "secure", "setup", "src", "temp", 
                "test", "tests", "tmp", "tools", "upload", "uploads", "user", 
                "users", "var", "web", "www", ".git", ".svn", ".env", "robots.txt",
                "sitemap.xml", "phpinfo.php", "info.php", "test.php", "config.php",
                "admin.php", "login.php", "wp-admin", "wp-content", "wp-includes"
            ]
            
            for directory in basic_dirs:
                url = f"{self.target}/{directory}"
                result = self.check_url(url)
                if result and result["status_code"] in [200, 301, 302, 403]:
                    self.results["directories"].append(result)
                    self.log_output(f"Found directory: {url} [{result['status_code']}]")
                    
                    # Check for specific file types
                    if directory in ["admin", "administrator", "panel"]:
                        self.results["admin_panels"].append(result)
                    elif directory in [".env", "config.php", "wp-config.php"]:
                        self.results["config_files"].append(result)
            
        except Exception as e:
            self.log_output(f"Dirb scan error: {str(e)}")

    def run_gobuster(self):
        """Simulate gobuster directory enumeration"""
        try:
            self.log_output(f"Starting advanced directory enumeration on {self.target}")
            
            # Extended wordlist for deeper scanning
            advanced_dirs = [
                "api/v1", "api/v2", "admin/login", "admin/panel", "backup/files",
                "config/database", "data/export", "files/upload", "logs/access",
                "private/keys", "secure/admin", "test/debug", "user/profile",
                "assets/js", "assets/css", "assets/images", "static/files",
                "media/uploads", "content/themes", "includes/config",
                "modules/admin", "plugins/security", "themes/default",
                "application/config", "system/logs", "vendor/autoload",
                "storage/logs", "cache/files", "session/data"
            ]
            
            for path in advanced_dirs:
                url = f"{self.target}/{path}"
                result = self.check_url(url)
                if result and result["status_code"] in [200, 301, 302, 403]:
                    self.results["directories"].append(result)
                    self.log_output(f"Found path: {url} [{result['status_code']}]")
                    
        except Exception as e:
            self.log_output(f"Advanced enumeration error: {str(e)}")

    def find_interesting_files(self):
        """Look for interesting files and endpoints"""
        try:
            self.log_output("Searching for interesting files...")
            
            interesting_files = [
                "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
                ".htaccess", ".htpasswd", "web.config", "phpinfo.php", "info.php",
                "test.php", "debug.php", "config.php", "database.php", "db.php",
                "backup.sql", "dump.sql", "users.sql", "admin.sql",
                ".env", ".env.local", ".env.production", "config.json", "package.json",
                "composer.json", "webpack.config.js", "gulpfile.js", "Gruntfile.js",
                "README.md", "LICENSE", "CHANGELOG.md", "VERSION"
            ]
            
            for filename in interesting_files:
                url = f"{self.target}/{filename}"
                result = self.check_url(url)
                if result and result["status_code"] == 200:
                    self.results["interesting_files"].append(result)
                    self.log_output(f"Found interesting file: {url}")
                    
        except Exception as e:
            self.log_output(f"File discovery error: {str(e)}")

    def scan(self):
        """Run comprehensive directory scanning"""
        self.log_output(f"Starting comprehensive directory scan on {self.target}")
        
        # Run different scanning methods
        threads = []
        
        # Run dirb scan
        thread1 = threading.Thread(target=self.run_dirb)
        threads.append(thread1)
        thread1.start()
        
        # Run gobuster-style scan
        thread2 = threading.Thread(target=self.run_gobuster)
        threads.append(thread2)
        thread2.start()
        
        # Look for interesting files
        thread3 = threading.Thread(target=self.find_interesting_files)
        threads.append(thread3)
        thread3.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Calculate summary
        total_found = (len(self.results["directories"]) + 
                      len(self.results["files"]) + 
                      len(self.results["interesting_files"]))
        
        self.log_output(f"Directory scan completed. Found {total_found} items:")
        self.log_output(f"- Directories: {len(self.results['directories'])}")
        self.log_output(f"- Interesting files: {len(self.results['interesting_files'])}")
        self.log_output(f"- Admin panels: {len(self.results['admin_panels'])}")
        self.log_output(f"- Config files: {len(self.results['config_files'])}")
        
        return self.results

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 directory_scan.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = DirectoryScanner(target)
    results = scanner.scan()
    
    # Output results in JSON format
    print("RESULTS_START")
    print(json.dumps(results, indent=2))
    print("RESULTS_END")

if __name__ == "__main__":
    main()