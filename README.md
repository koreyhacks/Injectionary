# Injectionary

Injectionary is a powerful SQL injection detection and exploitation tool designed for ethical hacking and penetration testing. With its intuitive interface and comprehensive testing capabilities, Injectionary helps security professionals identify and analyze SQL injection vulnerabilities in web applications.

![2025-03-11 22_10_57-KALI  Running  - Oracle VirtualBox _ 1](https://github.com/user-attachments/assets/5c8b8147-923c-46bb-a988-731597e04e98)


## Features

- Automatic detection of SQL injection vulnerabilities
- Support for multiple SQL injection techniques:
  - Authentication bypass
  - Union-based injections
  - Database enumeration
  - Error-based injections
  - Time-based blind injections
- Multi-threaded scanning for faster assessment
- Detailed reporting of discovered vulnerabilities
- Customizable request options (cookies, headers, etc.)
- Verbose output mode for detailed analysis

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/injectionary.git
cd injectionary

# Install dependencies
pip install requests colorama beautifulsoup4
```

## Usage

Basic usage:

```bash
python3 injectionary.py -t <target_url> -p <parameter> -v
```

Advanced usage:

```bash
python3 injectionary.py -t <target_url> -p <parameter> -m <method> -c <cookies> -H <headers> -v
```

### Command-line Options

- `-t, --target` - Target URL or host
- `-f, --file` - Use a file containing multiple targets
- `-p, --parameter` - Specific parameter to test
- `-m, --method` - HTTP method (GET or POST)
- `-c, --cookies` - HTTP cookies (format: name1=value1;name2=value2)
- `-H, --headers` - HTTP headers (format: header1:value1;header2:value2)
- `-d, --depth` - Scan depth level
- `-T, --threads` - Number of concurrent threads
- `--timeout` - Request timeout in seconds
- `-v, --verbose` - Verbose output
- `-o, --output` - Save results to file

## Example: Testing DVWA

[DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) is a great platform to practice using Injectionary. Follow these steps to set up and test DVWA:

### Setting Up DVWA

**🛠️ Step 1: Create/Reset the Database**
1. Log in to DVWA using the default credentials:
   * **Username:** `admin`
   * **Password:** `password`
2. In the left-hand menu, go to the **"Setup"** tab.
3. On the **Setup** page, click the `Create / Reset Database` button.
4. After a few seconds, you should see a success message like:
*"Database has been created successfully!"*
✅ This step initializes the database tables and populates them with default data — critical for testing SQL injection vulnerabilities.

**🛠️ Step 2: Set the Security Level to "Low"**
1. In the left-hand menu, go to the **"DVWA Security"** tab.
2. Set the **Security Level** to **Low** (this ensures SQL injection vulnerabilities are easier to exploit).
3. Click **Submit**.

**🛠️ Step 3: Confirm the Database is Working**
To verify everything is properly configured:
* Go to the **"SQL Injection"** tab from the left menu.
* In the **ID** input field, enter `1` and click **Submit**.
* If the database is working correctly, you should see user details like this:

```
ID: 1
First name: admin
Surname: admin
```

### Using Injectionary with DVWA

To scan DVWA for SQL injection vulnerabilities, use this command:

```bash
python3 injectionary.py -t "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" -p id -c "PHPSESSID=your_session_id;security=low" -v
```

Replace `your_session_id` with your actual PHPSESSID value (found in browser cookies after logging into DVWA).

The key to successful scanning is including both the `id` parameter and the `Submit` parameter, as DVWA's form requires both to process the request correctly.

## Success Indicators

When Injectionary detects a successful SQL injection vulnerability, you'll see output like:

```
[*] Trying authentication_bypass payloads...
[*] Testing payload: ' OR '1'='1
[+] Possible authentication bypass with: ' OR '1'='1
...
[*] Testing payload: ' OR 'x'='x
[+] Possible authentication bypass with: ' OR 'x'='x
```

![2025-03-11 22_13_30-KALI  Running  - Oracle VirtualBox _ 1](https://github.com/user-attachments/assets/eb862c4b-852b-4343-8b01-8ee76af9c4fd)


Lines with `[+]` indicate successful detection of a vulnerability.

## Finding Your PHPSESSID

1. Login to DVWA in your browser
2. Open your browser's Developer Tools (F12 or right-click > Inspect)
3. Go to the Application/Storage tab
4. Look for Cookies > localhost
5. Find and copy the PHPSESSID value

## Disclaimer

Injectionary is designed for ethical hacking and security testing only. Always ensure you have proper authorization before testing any system or application. The author is not responsible for any misuse or damage caused by this tool.


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
