# Broken Authentication

![image.png](image%20101.png)

Authentication is the process of verifying the identity of a system entity or user to ensure they are who they claim to be.

**Definition** (RFC 4949):*"The process of verifying a claim that a system entity or system resource has a certain attribute value."*

While **authentication** confirms identity, **authorization** determines if an entity is permitted to access resources.

- **Authentication** = Who you are
- **Authorization** = What you are allowed to do

## Common Authentication Methods

Authentication methods are generally categorized into three main types:

### 1. Knowledge-Based Authentication

Relies on **something the user knows** to verify identity.

- **Examples:**
    - Passwords
    - PINs
    - Security Questions

### 2. Ownership-Based Authentication

Relies on **something the user possesses** to verify identity.

- **Examples:**
    - ID Cards
    - Security Tokens
    - Authenticator Apps

### 3. Inherence-Based Authentication

Relies on **something the user is** or **does** to verify identity.

- **Examples:**
    - Fingerprints
    - Facial Recognition
    - Voice Patterns

## Comparison of Authentication Factors

| Knowledge | Ownership | Inherence |
| --- | --- | --- |
| Password | ID Card | Fingerprint |
| PIN | Security Token | Facial Pattern |
| Security Q. | Authenticator App | Voice Recognition |

## Single-Factor vs Multi-Factor Authentication (MFA)

### Single-Factor Authentication (SFA)

Relies on one method to verify identity (e.g., password only).

- **Example:** Login with just a password.

### Multi-Factor Authentication (MFA)

Uses two or more methods from different categories (Knowledge, Ownership, Inherence).

- **Example:**
    - Password (Knowledge) + TOTP (Ownership)
    - Fingerprint (Inherence) + Security Token (Ownership)

**2-Factor Authentication (2FA):** A subset of MFA using exactly two factors.

---

## Real-World Examples of Authentication

- **Login Forms:**
    
    Found in web apps like email, online banking, and Hack The Box (HTB) Academy:
    
- **Biometric Systems:**
    
    Facial recognition for smartphone unlocks.
    
- **Security Tokens:**
    
    Google Authenticator or YubiKey for second-layer verification.
    

---

## Importance in Penetration Testing

Authentication is the **first line of defense** against unauthorized access. As penetration testers, the goal is to identify vulnerabilities in authentication mechanisms that could lead to breaches.

This module focuses on exploiting and bypassing login forms to test the robustness of authentication methods.

# Attacks on Authentication

Authentication methods are vulnerable to various attacks, depending on their type. This section categorizes and explains the primary attack vectors targeting knowledge-based, ownership-based, and inherence-based authentication.

## Attacking Knowledge-Based Authentication

Knowledge-based authentication relies on static personal information (e.g., passwords, PINs).

**Common Attack Methods:**

- **Brute-Force Attacks** – Systematic guessing of passwords.
- **Dictionary Attacks** – Using lists of common passwords to gain unauthorized access.
- **Credential Stuffing** – Leveraging leaked username/password pairs from data breaches.
- **Social Engineering** – Tricking users into divulging their credentials.
- **Phishing** – Deceiving users into providing sensitive information through fake websites or emails.

**Example Attack:**

```bash
hydra -L usernames.txt -P passwords.txt IP -s PORT http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"
```

- Targets login forms by attempting multiple username/password combinations.

## Attacking Ownership-Based Authentication

Ownership-based methods rely on physical items (e.g., security tokens, ID cards).

**Common Attack Methods:**

- **Theft** – Physically stealing hardware tokens or smart cards.
- **Cloning** – Duplicating NFC badges or magnetic cards.
- **Cryptographic Attacks** – Exploiting weaknesses in the token's encryption algorithms.
- **Replay Attacks** – Intercepting and reusing valid authentication tokens.

**Example Attack:**

- **NFC Cloning** – Using an NFC reader to duplicate keycards in public spaces.

**Challenges in Attacking Ownership-Based Systems:**

- **Higher Security** – Difficult to replicate physical objects.
- **Cost and Logistics** – Distributing and managing tokens can be challenging for organizations.

## Attacking Inherence-Based Authentication

Inherence-based methods use biometric data (e.g., fingerprints, facial recognition).

**Common Attack Methods:**

- **Data Breaches** – Exposing stored biometric data (e.g., fingerprints, facial patterns).
- **Spoofing** – Using fake fingerprints or 3D face masks to bypass sensors.
- **Algorithm Bias** – Exploiting biases in biometric recognition systems.
- **Replay Attacks** – Replaying recorded biometric data.

**Real-World Example:**

In 2019, hackers breached a biometric smart lock company, exposing fingerprints, facial patterns, and personal data. Unlike passwords, compromised biometric data cannot be reset, highlighting the irreversible nature of inherence-based breaches.

## Comparison of Attack Vectors

| Authentication Type | Common Attacks | Mitigation Measures |
| --- | --- | --- |
| **Knowledge** | Brute-force, Phishing, Credential Stuffing | Strong passwords, MFA, and phishing awareness. |
| **Ownership** | Theft, Cloning, Replay Attacks | Token encryption, secure distribution. |
| **Inherence** | Biometric Spoofing, Data Breaches | Liveness detection, biometric data encryption. |

## Key Takeaways

- **Knowledge-Based** authentication is the most vulnerable to attacks.
- **Ownership-Based** authentication is harder to compromise but vulnerable to physical theft and cloning.
- **Inherence-Based** authentication offers convenience but poses irreversible risks if breached.

Penetration testers must evaluate the strengths and weaknesses of each authentication method and identify potential attack vectors to ensure comprehensive security assessments.

# Enumerating Users

User enumeration vulnerabilities occur when a web application reveals whether a username exists through differing responses to valid and invalid inputs. This can happen during login, registration, or password reset attempts. Attackers can leverage this to identify valid users and launch further attacks such as brute-forcing or credential stuffing.

---

## User Enumeration Theory

User enumeration can enhance user experience but introduces security risks. Developers may allow enumeration to aid legitimate users in identifying errors during login or registration. However, attackers can exploit these differences to gather valid usernames.

Even well-known applications like **WordPress** allow user enumeration by default. For example:

- **Invalid Username** – "Username does not exist."
- **Valid Username** – "Incorrect password."

While this behavior may be required for functionality (e.g., chat user search), minimizing user enumeration enhances security. A possible mitigation is using **email addresses** instead of usernames for login.

---

## Enumerating Users via Differing Error Messages

Attackers use wordlists (like those in **SecLists**) to test for valid usernames. By analyzing error messages, attackers can differentiate between valid and invalid users.

**Example Attack with ffuf**

```bash
ffuf -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -u http://94.237.57.213:50332/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=123" -fr "Unknown user." 
```

```php
ffuf -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt:USER -u http://94.237.54.42:52187/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: PHPSESSID=mm7nc3kjuo3799rphc14nf0ln5" -d "username=USER&password=dsfsd" -fr "Unknown username or password." -o userenum.txt -of json
```

**Explanation:**

- `w` – Specifies the wordlist.
- `u` – URL to attack.
- `X` – HTTP method (POST).
- `H` – HTTP header (content type).
- `d` – POST data, with `FUZZ` as the placeholder for usernames.
- `fr` – Filter responses containing "Unknown user." (invalid username).

**Output Example:**

```bash
[Status: 200, Size: 3271, Words: 754, Lines: 103, Duration: 310ms]
    * FUZZ: cookster
```

**Result:** The username **`cookster`**is valid. We can proceed to brute-force this user's password.

---

## User Enumeration via Side-Channel Attacks

Sometimes, web applications return identical responses for valid and invalid usernames. However, **side-channel attacks** can still reveal valid users by exploiting differences in **response timing** or **server behavior**.

### Example:

- **Valid Username** – Slight delay due to database lookup.
- **Invalid Username** – Immediate response without lookup.

Attackers measure these timing differences to infer valid usernames.

---

## Mitigation Techniques

- **Generic Error Messages:** Use uniform messages (e.g., "Invalid username or password") for all login failures.
- **Rate Limiting:** Limit login attempts to slow down enumeration.
- **MFA (Multi-Factor Authentication):** Adds additional layers of security even if the username is known.
- **Use Email for Login:** Reduces exposure of usernames.
- **Account Lockout Policies:** Temporarily lock accounts after repeated failed attempts.

---

## Tools for User Enumeration

| Tool | Description | Example Use Case |
| --- | --- | --- |
| ffuf | Fuzzer for discovering hidden files/dirs | Enumerating users by fuzzing login forms. |
| Hydra | Login cracker supporting many protocols | Brute-forcing discovered usernames. |
| Burp Suite | Web vulnerability scanner | Intercepting and modifying login requests. |
| Nmap | Network scanner | Scanning for open ports and services (FTP, SSH). |

---

## Key Takeaways

- User enumeration is a **common vulnerability** that can lead to **password attacks**.
- Differing error messages and response timing can reveal valid usernames.
- Preventing enumeration enhances web application security and reduces attack vectors.

# Brute-Forcing Passwords

**Why Password Brute-Forcing Works**

- **Password Reuse** – Users often reuse the same password across multiple accounts.
- **Weak Passwords** – Common phrases, dictionary words, and simple patterns are vulnerable.
- **Leaked Databases** – Attackers leverage password leaks to try known passwords on different platforms (password spraying).

---

When accessing the sample web application, we can see the following information on the login page:

![image.png](image%20102.png)

- We can use the **`rockyou`** pwlist
- we can use **`grep`** to match only those passwords that match the password policy implemented by our target web application, which brings down the wordlist to about 150,000 passwords, a reduction of about 99%:

### Step 1: Filter Passwords Based on Policy

Filter a large wordlist like **rockyou.txt** to match the target's password policy (e.g., 10+ characters, uppercase, lowercase, and digits).

```bash
grep '[[:upper:]]' /usr/share/wordlists/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt
```

- Creates a custom password list by filtering rockyou.txt to include only stronger passwords that meet the following criteria:
    - Contain at least one uppercase letter.
    - Contain at least one lowercase letter.
    - Contain at least one number.
    - Are at least 10 characters long.

**Wordlist Reduction:**

```bash
wc -l /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
# 14,344,391 passwords

wc -l custom_wordlist.txt
# 151,647 passwords
```

---

### Step 2: Brute-Force Passwords with ffuf

After discovering a valid username (e.g., admin), use ffuf to brute-force the password and finding the correct name of the POST parameter:

![image.png](image%20103.png)

```bash
ffuf -w rockyouTrimmed.txt -u http://94.237.58.102:49349/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username or password." -t 60
```

- `w` – Custom wordlist.
- `u` – Target URL.
- `X` – HTTP method (POST).
- `H` – HTTP header.
- `d` – POST data (replace `FUZZ` with passwords from the list).
- `fr` – Filter responses with "Invalid username."
- `-t`  – Use **60 threads** to speed up the attack (parallel requests).

**`[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 4764ms]
* FUZZ: Buttercup1`**

**Result:** Password `Buttercup1` is valid.

---

### Tools for Brute-Forcing

| Tool | Description | Example Use Case |
| --- | --- | --- |
| ffuf | Fuzzing tool for login forms and APIs | Brute-force passwords by fuzzing login forms. |
| Hydra | Parallelized login cracker | Attacking SSH, FTP, RDP, and web forms. |
| Burp Suite | Web vulnerability scanner | Repeating login attempts with Intruder. |
| Hashcat | Password cracker for hashes | Cracking password hashes offline. |

---

## Mitigation Techniques

- **Strong Password Policies:** Require long, complex passwords.
- **Account Lockouts:** Temporarily lock accounts after repeated failed attempts.
- **Rate Limiting:** Restrict login attempts within a timeframe.
- **Multi-Factor Authentication (MFA):** Adds another layer of security, even if the password is compromised.
- **Monitoring:** Implement logging and alerting for suspicious login activity.

# Brute-Forcing Password Reset Tokens

Password-reset functionalities are critical for account recovery but can introduce significant security vulnerabilities if reset tokens are weak or predictable. Attackers can exploit these tokens to hijack user accounts by brute-forcing the token space.

---

## Password Reset Flow

When users forget their passwords, they receive a reset token via email or SMS. This token acts as a temporary password/code that allows them to reset their password.

**`Attack Vector`:** Weak reset tokens (e.g., short numeric codes) can be brute-forced, allowing attackers to reset victims' passwords and gain unauthorized access.

---

## Example - Identifying Weak Reset Tokens

![image.png](image%20104.png)

A typical password reset email might look like this:

```
Hello,

We received a request to reset your password.
Click the link below to reset your password:
http://weak_reset.htb/reset_password.php?token=7351

This link will expire in 24 hours.
```

**Observation:** The reset token (`7351`) is a **4-digit number**. With only **10,000 possible values**, brute-forcing is feasible.

---

## Attacking Weak Reset Tokens with ffuf

### Step 1: Generate a Wordlist of Tokens

Use the `seq` command to create a list of all 4-digit tokens (0000 to 9999).

```bash
seq -w 0 9999 > tokens.txt
```

- `w` – Pads numbers to ensure uniform length (e.g., 0001, 0234).
- Verify the list:

```bash
head tokens.txt
0000
0001
0002
0003
```

---

### Step 2: Brute-Force the Reset Tokens

Use `ffuf` to brute-force the `/reset_password.php` endpoint by substituting the `FUZZ` parameter with each token from the list.

```bash
ffuf -w ./tokens.txt -u http://weak_reset.htb/reset_password.php?token=FUZZ -fr "The provided token is invalid"
```

- `w` – Use the generated token list.
- `u` – Target URL, with `FUZZ` replaced by tokens.
- `fr` – Filter responses containing "The provided token is invalid".

**Output Example:**

```bash
[Status: 200, Size: 2667, Words: 538, Lines: 90, Duration: 1ms]
    * FUZZ: 6182
```

**Result:** The token `6182` is valid, allowing password reset and account takeover.

- We would manipulate the link via Burp : [**`http://83.136.252.118:52537/reset_password.php?token=](http://83.136.252.118:52537/reset_password.php?token=)6182`**and provide the new password we want to change to.

---

## Mitigation Techniques

- **Increase Token Length:** Use tokens with **at least 12-16 characters**.
- **Alphanumeric Tokens:** Incorporate letters, numbers, and special characters.
- **Rate Limiting:** Restrict the number of reset attempts within a timeframe.
- **MFA (Multi-Factor Authentication):** Require additional verification before resetting passwords.
- **Token Expiry:** Ensure tokens expire after **short durations** (e.g., 5 minutes).
- **CAPTCHA:** Implement CAPTCHA during reset flows to prevent automated attacks.

---

## Tools for Brute-Forcing Reset Tokens

| Tool | Description | Example Use Case |
| --- | --- | --- |
| ffuf | Fuzzer for web applications | Brute-forcing reset tokens by fuzzing GET requests. |
| Burp Suite | Web vulnerability scanner | Repeating password reset requests with Intruder. |
| Hydra | Parallelized brute-force tool | Brute-forcing web form passwords or tokens. |
| curl | Command-line tool for HTTP requests | Manual testing of reset token vulnerabilities. |

---

## Key Takeaways

- **Weak reset tokens** present a significant vulnerability.
- **Brute-forcing short tokens** is trivial and can lead to account takeovers.
- **Implementing strong, unpredictable tokens** and adding secondary verification layers is critical for securing password-reset flows.

# Brute-Forcing 2FA Codes

Two-factor authentication (2FA) significantly enhances account security by requiring users to provide a second form of authentication, such as a one-time code from an app or SMS. However, weak or short codes (e.g., 4-digit TOTPs) can be brute-forced, exposing accounts to attacks.

---

## Common 2FA Implementations

- **Time-Based One-Time Passwords (TOTP):** Generated by authenticator apps (Google Authenticator, Authy).
- **SMS-based Codes:** Delivered via text message.
- **Email-based Codes:** Sent to the user's email.
- **Hardware Tokens:** Physical devices that generate codes.

**Weakness:** Short numeric codes (e.g., 4 or 6 digits) are vulnerable to brute-force attacks if the application lacks rate limiting or detection mechanisms.

---

## Example - Brute-Forcing 2FA Codes

### Scenario

- The application uses a 4-digit TOTP.
- After successful login (`admin:admin`), the web application prompts for a 2FA code at:`http://<SERVER_IP>:<PORT>/2fa.php`

---

### Step 1: Generate a List of 4-Digit Codes

Use `seq` to generate all possible 4-digit codes (0000 to 9999).

```bash
seq -w 0 9999 > tokens.txt
```

- `w` – Pads numbers to uniform length (e.g., 0001, 0234).
- Verify the list:

```bash
head tokens.txt
0000
0001
0002
```

---

### Step 2: Intercept the TOTP Request

Log in with valid credentials and intercept the 2FA request using Burp Suite or browser developer tools.

**Observation:**

- The TOTP is passed via the `otp` POST parameter.
- Session is tracked with the `PHPSESSID` cookie.

---

### Step 3: Brute-Force 2FA with ffuf

Use `ffuf` to brute-force the `/2fa.php` endpoint by testing each code in the wordlist.

```bash
ffuf -w ./tokens.txt -u http://bf_2fa.htb/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93" -d "otp=FUZZ" -fr "Invalid 2FA Code"
```

- `w` – Use the generated token list.
- `u` – Target URL.
- `X POST` – Send POST requests.
- `H` – Specify the content type.
- `b` – Include session cookie.
- `d` – Send `otp` parameter with `FUZZ` placeholder.
- `fr` – Filter responses with "Invalid 2FA Code".

---

**Output Example**

![image.png](image%20105.png)

**Result:** The valid TOTP is **`4733`**. Access is granted after this code is accepted, that’s why we get so many hits.

---

## Mitigation Techniques

- **Longer 2FA Codes:** Use at least **6-8 digit** codes to increase complexity.
- **Rate Limiting:** Limit the number of TOTP attempts (e.g., 5 attempts per minute).
- **Lockout Mechanism:** Temporarily lock accounts after multiple failed 2FA attempts.
- **IP Throttling:** Detect excessive attempts from the same IP and block them.
- **MFA (Multi-Factor Authentication):** Use hardware tokens or biometric data instead of short numeric codes.

---

## Tools for Brute-Forcing 2FA

| Tool | Description | Example Use Case |
| --- | --- | --- |
| ffuf | Web fuzzer for brute-forcing forms and codes | Brute-forcing 2FA codes in login flows. |
| Hydra | Parallelized brute-force tool | Testing 2FA codes on web forms. |
| Burp Suite | Web vulnerability scanner | Repeating intercepted requests with Intruder. |
| curl | Command-line HTTP tool | Manually testing 2FA endpoints. |

---

## Key Takeaways

- **Short 2FA codes are vulnerable** to brute-force attacks.
- **Adding rate limits and lockout policies** can drastically reduce attack feasibility.
- **Comprehensive 2FA security** requires longer tokens and secondary security checks.

# Weak Brute-Force Protection

Brute-force protection mechanisms are essential to mitigate automated attacks against authentication systems. This section explores common protective measures such as **rate limits** and **CAPTCHAs**, and discusses potential bypass techniques.

---

## 1. Rate Limits

**Rate limiting** controls the number of requests allowed within a specified time frame to:

- **Prevent server overload** and downtime.
- **Thwart brute-force attacks** by slowing down repeated login attempts.
- **Ensure fair resource usage** across users.

**How It Works:**

- After exceeding the allowed number of requests, the system:
    - Increments response time (slowing down responses).
    - Temporarily blocks access to the service.

**Key Considerations:**

- Rate limits must target **attackers without impacting regular users** to avoid accidental DoS scenarios.
- **Identification methods:**
    - **IP-based:** Attacker's IP is flagged and rate-limited.
    - **X-Forwarded-For (XFF):** Used when requests pass through proxies, load balancers, or reverse proxies.

**Bypassing Rate Limits (X-Forwarded-For Vulnerability):**

- **Problem:** Attackers can spoof the `X-Forwarded-For` header, evading IP-based rate limits.
- **Example (Exploit):**

```bash
curl -X POST -H "X-Forwarded-For: 192.168.1.1" -d "username=admin&password=pass" <http://target.htb/login>
```

- Randomizing the XFF header allows continued brute-force attempts without triggering rate limits.

```bash
for i in {1..1000}; do curl -X POST -H "X-Forwarded-For: 192.168.1.$i" -d "username=admin&password=pass" <http://target.htb/login>; done
```

---

## 2. CAPTCHAs

![image.png](image%20106.png)

**CAPTCHA (Completely Automated Public Turing Test to Tell Computers and Humans Apart):**

- **Purpose:** Distinguish between human users and automated bots.
- **Common Types:**
    - **Text-based:** Recognizing distorted letters.
    - **Image-based:** Selecting objects from images.
    - **Puzzle-based:** Simple interactive puzzles.

**How CAPTCHAs Prevent Brute-Force Attacks:**

- Users must solve a CAPTCHA before submitting forms (e.g., login attempts).
- Automated brute-force tools struggle to bypass CAPTCHAs without manual intervention.

**Weak CAPTCHA Implementations:**

- **Flawed Example:** The CAPTCHA solution is embedded in the response (visible to attackers).

```html
<img src="/captcha_image.png" />
<input type="hidden" value="captcha123" name="captcha_solution" />
```

- **Bypass:** Extract the hidden solution directly.

```bash
curl -X POST -d "username=admin&password=pass&captcha_solution=captcha123" <http://captcha.htb/login>
```

**Tools for CAPTCHA Bypass:**

- **AI-Based Solvers:** Leverage machine learning to break image/audio CAPTCHAs.
- Browser plugins that solve CAPTCHAs automatically.

---

## Real-World Example - X-Forwarded-For Bypass ([CVE-2020-35590)](https://nvd.nist.gov/vuln/detail/CVE-2020-35590)

- **Vulnerability:** Brute-force rate limits bypassed by altering `X-Forwarded-For`.
- **Impact:** Allowed attackers to bypass rate limits on authentication endpoints.
- **Mitigation:**
    - Use server-side tracking (session-based).
    - Implement request fingerprinting to detect anomalies.

---

## Mitigation Techniques

- **Enforce IP Rate Limits AND Session-Based Tracking:** Avoid relying solely on `X-Forwarded-For`.
- **Progressive Delays:** Increase delay after successive failed attempts.
- **Account Lockout:** Temporarily lock accounts after repeated failed logins.
- **CAPTCHA after Failed Logins:** Introduce CAPTCHAs after 3-5 failed attempts.
- **Multi-Factor Authentication (MFA):** Adds extra security beyond simple passwords.

---

## Tools for Testing and Bypassing Brute-Force Protection

| Tool | Description | Example Use Case |
| --- | --- | --- |
| ffuf | Web fuzzer for brute-forcing login forms | Bypassing weak rate limits on login endpoints. |
| Burp Suite | Web vulnerability scanner | Intercept and modify brute-force traffic. |
| CAPTCHA Solver | Automated CAPTCHA solving tools | AI-based solvers to break CAPTCHA barriers. |
| curl | Command-line HTTP tool | Testing rate limits manually. |

---

## Key Takeaways

- **Rate limits** and **CAPTCHAs** are essential for preventing brute-force attacks.
- **Poor implementations can be bypassed** by exploiting vulnerabilities in IP detection or hidden CAPTCHA solutions.
- **Continuous monitoring and secure configurations** are critical to thwarting automated attacks.

# Default Credential

Default credentials are often used in web applications and devices to allow initial access post-installation. If not changed after setup, these credentials become a significant security risk, providing an easy entry point for attackers. Testing for default credentials is a critical component of authentication testing as outlined by **OWASP's Web Application Security Testing Guide**.

---

## Why Default Credentials are a Risk

- **Initial Setup Convenience:** Developers configure default admin accounts to simplify installation.
- **Security Oversight:** Admins may forget to change these credentials post-deployment.
- **Common Patterns:** Default usernames and passwords (e.g., `admin:admin`, `root:toor`) are widely known.
- **Automated Attacks:** Attackers often scan for open services using pre-configured default credential lists.

---

## Testing for Default Credentials

Security testing often includes verifying if default credentials are still active. This is done by attempting to log in using well-known username/password pairs.

### Common Default Credentials

- **Username:** admin
- **Password:** password
- **Root/Admin Accounts:** root:root, admin:1234, or cisco:cisco

---

## Resources for Default Credentials

Various platforms maintain lists of default credentials across different applications and devices:

### 1. [CIRT.net](http://cirt.net/) Default Credentials Database

- **URL:** [https://www.cirt.net/passwords](https://www.cirt.net/passwords)
- **Description:** Comprehensive database covering networking devices, web applications, and SCADA systems.

**Example:** Searching for Cisco default credentials.

```bash
curl <https://www.cirt.net/passwords> -G --data-urlencode "search=cisco"
```

### 2. SecLists - Default Credentials

- **URL:** [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- **Location:** `SecLists/Passwords/Default-Credentials`
- **Use Case:** Useful for penetration tests and vulnerability assessments.

### 3. SCADA GitHub Repository

- **URL:** [https://github.com/apsdehal/awesome-scada](https://github.com/apsdehal/awesome-scada)
    - [https://github.com/scadastrangelove/SCADAPASS/tree/master](https://github.com/scadastrangelove/SCADAPASS/tree/master)
- **Description:** Collection of SCADA-related vulnerabilities, including default passwords for industrial control systems.

---

## Example: Finding Default Credentials

During a penetration test, if you encounter a [**BookStack**](https://github.com/BookStackApp/BookStack) web application:

```bash
<http://bookstack.htb>
```

A simple Google search for **"BookStack default credentials"** can reveal installation guides that include default admin logins.

```bash
<https://google.com/search?q=bookstack+default+credentials>
# Result
Default Admin Credentials: admin@admin.com / password
```

---

## Automating Default Credential Testing

Automation tools can streamline default credential testing. Here’s how to use Hydra to brute-force web logins with default credentials:

```bash
hydra -L usernames.txt -P default_passwords.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"
```

- **`L`**: Username list
- **`P`**: Password list
- **`/login`**: Target endpoint
- **`F=Invalid`**: Failure message that Hydra looks for

---

## Preventing Default Credential Attacks

- **Mandatory Password Change:** Enforce password updates during initial login.
- **Complex Default Passwords:** Use randomized passwords for each deployment.
- **Restrict Access:** Limit administrative interfaces to trusted IPs.
- **Continuous Monitoring:** Periodically audit for default or weak credentials.

---

## Key Takeaways

- **Default credentials are a leading cause of breaches.**
- **Lists of default credentials are widely available.**
- **Automated tools make exploiting default credentials easy.**
- **Regular audits and forced password updates can mitigate these risks.**

# Vulnerable Password Reset

Password reset functionality is essential for user convenience but can introduce significant security risks if implemented incorrectly. Attackers can exploit weak password reset processes to take over user accounts. This section explores vulnerabilities such as guessable security questions and parameter manipulation.

---

## Guessable Password Reset Questions

Many web applications use security questions to verify user identity during password resets. Users select predefined questions and provide answers during account registration. However, attackers can often guess or gather answers through Open-Source Intelligence (OSINT).

**Common Security Questions:**

- *What is your mother’s maiden name?*
- *What city were you born in?*

If the application does not implement brute-force protection, attackers can systematically guess answers using wordlists.

---

### Example: Brute-Forcing Security Questions

Assume the following scenario:

- A web application uses the question *“What city were you born in?”* during password reset.
- We want to target the *admin* user.

**1. Wordlist Creation (City Names):**

We can use a [CSV file](https://github.com/datasets/world-cities/blob/main/data/world-cities.csv) containing over 25,000 cities to generate a wordlist:

```bash
cat world-cities.csv | cut -d ',' -f1 > city_wordlist.txt
#
wc -l city_wordlist.txt 
# 29273 city_wordlist.txt
```

**2. Request Analysis:**

After submitting the username, the application prompts for a security question:

```php
POST /reset.php HTTP/1.1
Host: pwreset.htb
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=abcd1234

username=admin
```

We attempt to brute-force the security answer using ffuf:

```bash
ffuf -w ./city_wordlist.txt -u http://pwreset.htb/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=abcd1234" -d "security_response=FUZZ" -fr "Incorrect response."
```

**Output:**

```bash
[Status: 302, Size: 0, Words: 1, Lines: 1]
    * FUZZ: Houston
```

The correct answer is *Houston*. We can now proceed to reset the password.

---

## Manipulating the Reset Request

Another vulnerability arises if the password reset request includes a hidden username parameter. If this parameter can be altered, attackers can reset the password for other accounts.

**1. Request Example:**

```php
POST /reset_password.php HTTP/1.1
Host: pwreset.htb
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=abcd1234

password=NewPass123&username=htb-stdnt
```

**2. Manipulating the Request:**

We change the username to *admin* to hijack the admin account:

```php
POST /reset_password.php HTTP/1.1
Host: pwreset.htb
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=abcd1234

password=NewPass123&username=admin
```

---

### Mitigation Strategies

- **Avoid Predictable Security Questions:** Use random or user-defined questions.
- **Rate Limiting:** Implement restrictions on password reset attempts.
- **Token-Based Resets:** Use strong, random tokens rather than security questions.
- **Consistency:** Maintain state between reset stages to prevent parameter manipulation.

Thorough testing of password reset processes is critical to identifying and mitigating vulnerabilities before they can be exploited.

# Authentication Bypass via Direct Access

- This section highlights vulnerabilities that enable attackers to bypass authentication mechanisms by directly accessing protected resources.

## Direct Access Vulnerability

- Attackers can access protected resources directly without authentication if the application does not properly verify requests.

### Example Scenario:

- A web application redirects users to `/admin.php` after successful authentication.
- If the application only uses the login page to enforce authentication, an attacker can bypass it by directly accessing `/admin.php`.

```php
if(!$_SESSION['active']) {
    header("Location: index.php");
}
```

- If the session is inactive, the user is redirected to `/index.php`.
- However, the PHP script **does not stop execution**, leading to the admin page being sent in the response body.

This code redirects the user to **`/index.php`** if the session is not active, i.e., if the user is not authenticated. However, the PHP script does not stop execution, resulting in protected information within the page being sent in the response body:

![image.png](image%20107.png)

## Exploit Steps (Using Burp Suite):

1. Access `/admin.php` directly.
2. Intercept the server response using Burp Suite.
3. Right-click and select **Do intercept > Response to this request**.
    
    ![image.png](image%20108.png)
    
4. Modify the response status code:
    - Change `302 Found` to `200 OK`.
    
    ![image.png](image%20109.png)
    
5. Forward the response.
6. The admin page is now displayed in the browser.

**Example: `http://<SERVER_IP>:<PORT>/admin.php`**

## Fixing the Vulnerability:

- Modify the PHP script to **terminate execution** after issuing the redirect:

```php
if(!$_SESSION['active']) {
    header("Location: index.php");
    exit;
}
```

## Key Takeaways:

- Direct access vulnerabilities occur when session validation fails to halt execution.
- Always use `exit` after redirects to ensure sensitive data is not exposed.

# Authentication Bypass via Parameter Modification

- Authentication vulnerabilities can arise when web applications rely on HTTP parameters for authentication or authorization.
- This flaw can lead to:
    - Authentication bypass
    - Authorization bypass
    - Privilege escalation
- Closely related to **`Insecure Direct Object Reference (IDOR)`** vulnerabilities.

## Parameter Modification Example

- Target web application uses the parameter `user_id` for authentication.

### Scenario:

1. Log in with user credentials (`htb-stdnt`).
2. Redirected to:
    
    ```
    /admin.php?user_id=183
    ```
    
    ![image.png](image%20110.png)
    
3. Limited access to data – privileges appear restricted.
4. Removing the `user_id` from the URL:
    
    ```
    /admin.php
    ```
    
    - Results in redirection to the login page `/index.php`, even with a valid PHP session (`PHPSESSID`).

![image.png](image%20111.png)

1. Directly accessing:
    
    ```
    /admin.php?user_id=183
    ```
    
    - Bypasses the login page and restores access to restricted resources.

### Exploit Potential:

- The `user_id` parameter defines the access level.
- By guessing or brute-forcing the `user_id` of an admin, attackers can escalate privileges:
    
    ```
    /admin.php?user_id=<admin_id>
    ```
    
- Brute-force techniques from the **Brute-Force Attacks** section can be used to identify admin user IDs.
    
    ```bash
    ffuf -w ./numbers.txt -u http://94.237.54.60:42297/admin.php?user_id=FUZZ -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=r0s8hg51mtoh7kn5vg9hm4nnfo" -t 60
    ```
    

## Key Takeaways:

- Parameters such as `user_id` can lead to severe authentication bypass if not validated properly.
- Preventive measures:
    - Implement proper session checks beyond URL parameters.
    - Validate user privileges on the server-side, not through user-controlled input.

## Related Vulnerabilities:

- **Type Juggling** – Covered in the [**Whitebox Attacks**](https://academy.hackthebox.com/module/details/205) module.
- **Injection Vulnerabilities** – Covered in **Injection Attacks** and [**SQL Injection** modules](https://academy.hackthebox.com/module/details/33).
- **Logic Bugs** – Addressed in the [**Parameter Logic Bugs**](https://academy.hackthebox.com/module/details/239) module.

# Attacking Session Tokens

- Vulnerabilities in handling session tokens can lead to session hijacking and user impersonation.
- Session tokens are unique identifiers tied to a user’s session. If compromised, attackers can impersonate users.

---

## Brute-Force Attack

- **Weak or predictable session tokens** can be brute-forced.
- **Tokens with insufficient randomness (low entropy) are vulnerable**. (https://owasp.org/www-community/vulnerabilities/Insufficient_Entropy)

### Example 1: Short Session Tokens

![image.png](image%20112.png)

- A four-character session token: **`4d3f`**
    - Can be brute-forced easily using techniques from **Brute-Force Attacks**.

![image.png](image%20113.png)

### Example 2: Static Parts in Tokens

- Tokens with static components reduce randomness:
    
    ```bash
    2c0c58b27c71a2ec5bf2b4b6e892b9f9
    2c0c58b27c71a2ec5bf2b4546092b9f9
    2c0c58b27c71a2ec5bf2b497f592b9f9
    2c0c58b27c71a2ec5bf2b48bcf92b9f9
    2c0c58b27c71a2ec5bf2b4735e92b9f9
    ```
    
    - As we can see, all session tokens are very similar. In fact, of the 32 characters, 28 are the same for all five captured sessions. The session tokens consist of the static string `2c0c58b27c71a2ec5bf2b4` followed by four random characters and the static string `92b9f9`.
    - Only **4 characters** change, allowing attackers to brute-force the remaining part.

### Example 3: Incrementing Tokens

- Successive session tokens:
    
    ```
    141233
    141234
    141237
    141238
    141240
    ```
    
    - Predictable pattern allows enumeration and hijacking of sessions by incrementing/decrementing the token.

---

## Attacking Predictable Session Tokens

- **Predictable tokens** often contain encoded or structured data.

### Example 1: Base64 Encoded Tokens

![image.png](image%20114.png)

- Session token: **`dXNlcj1odGItc3RkbnQ7cm9sZT11c2Vy`**
- Decoded using base64: **`user=htb-stdnt;role=user`**
- **Exploit**: Modify `role=user` to `role=admin` and re-encode:
    
    ```bash
    echo -n 'user=htb-stdnt;role=admin' | base64
    ```
    
    - Send modified cookie to gain admin access.

![image.png](image%20115.png)

### Example 2: Hex Encoded Tokens

- Hex-encoded session token: **`757365723d6874622d7374646e743b726f6c653d61646d696e`**
- Decoded to reveal user role data: **`user=htb-stdnt;role=admin`**

```bash
echo 757365723d6874622d7374646e743b726f6c653d61646d696e | xxd -r -p
user=htb-stdnt;role=admin
```

![image.png](image%20116.png)

### Example 3: Encrypted Tokens

- Encrypted session tokens may also be vulnerable if:
    - Weak cryptographic algorithms are used.
    - User data is improperly injected into encryption functions.

---

## Key Takeaways

- **Capture and analyze** multiple session tokens to check for patterns or predictability.
- **Mitigation:**
    - Use long, truly random session tokens.
    - Avoid static/prepended values in tokens.
    - Implement strong cryptographic algorithms for session generation.
    - Monitor for brute-force attempts on session tokens.

# Further Session Attacks

- This section explores two additional attack vectors targeting session token handling in web applications:
    1. [Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
    2. Improper Session Timeout
- [Advanced attacks like **Session Puzzling** are covered in the **Abusing HTTP Misconfigurations** module.](https://academy.hackthebox.com/module/details/189)

---

## Session Fixation

- **Definition**: An attacker forces a victim to use a session token that the attacker knows, allowing session hijacking.
- **Cause**: Failure to assign a new session token after successful authentication.

### Attack Flow:

1. **Attacker Obtains Session Token**:
    - Attacker logs in and receives a valid session token (e.g., `a1b2c3d4e5f6`).
    - Logs out to invalidate their session but retains the token.
2. **Tricking the Victim**:
    - An attacker obtains a valid session token by authenticating to the web application. For instance, let us assume the session token is **`a1b2c3d4e5f6`**. Afterward, the attacker invalidates their session by logging out.
        
        ```php
        <http://vulnerable.htb/?sid=a1b2c3d4e5f6>
        ```
        
    - When the victim clicks this link, the web application sets the `session` cookie to the provided value, i.e., the response looks like this:
        
        ```php
        HTTP/1.1 200 OK
        Set-Cookie: session=a1b2c3d4e5f6
        ```
        
3. **Victim Logs In**:
    - The victim's browser already stores the attacker-provided session cookie, so it is sent along with the login request. The victim uses the attacker-provided session token since the web application does not assign a new one.
    - The attacker's session token (`a1b2c3d4e5f6`) is still active.
4. **Session Hijack**:
    - Attacker uses the known session token to access the victim's account.

### Mitigation:

- **Assign a New Session Token** after each successful authentication.
- Ensure session tokens are randomly generated and not reusable.

---

## Improper [Session Timeout](https://owasp.org/www-community/Session_Timeout)

- **Definition**: A web application allows session tokens to remain valid indefinitely by failing to enforce proper session timeouts.
- **Impact**:
    - Enables attackers to use stolen session tokens indefinitely.

### Example:

- A hijacked session token remains valid for hours/days if no timeout is defined.

### Session Timeout Best Practices:

- **Sensitive Applications (e.g., healthcare, finance)**:
    - Timeout: **Minutes** (e.g., 5-15 minutes of inactivity).
- **Less Sensitive Applications (e.g., social media)**:
    - Timeout: **Hours** (e.g., 2-8 hours).

### Mitigation:

- Implement **session timeout policies** based on the application’s sensitivity.
- Invalidate session tokens after a set period of inactivity.

---

## Key Takeaways

- **Session Fixation**: Always generate a new session token after login.
- **Session Timeout**: Set appropriate expiration times to prevent long-term session hijacking.
- Continuous monitoring and secure session management are critical for preventing session-based attacks.