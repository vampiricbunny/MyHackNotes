# Attacking Webapps with FFUF

```bash
ffuf -h	#ffuf help
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ	#Directory Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ	#Extension Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php	#Page Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v	#Recursive Fuzzing
ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/	#Sub-domain Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx	#VHost Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx	#Parameter Fuzzing - GET
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx	#Parameter Fuzzing - POST
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx	#Value Fuzzing
```

```bash
sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'	# Add DNS entry
for i in $(seq 1 1000); do echo $i >> ids.txt; done	# Create Sequence Wordlist
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'	# curl w/ POST
```

## Basic Fuzzing

### Dir Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.53.52:40397/FUZZ 
```

### Extension Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://94.237.53.52:40397/indexFUZZ 
```

And we can get this :

```bash
________________________________________________

.html                   [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 10ms]
.htm                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 10ms]
.hta                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 1223ms]
.phar                   [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 3233ms]
.php                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 3233ms]
.phps                   [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 4235ms]
.phtml                  [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 4238ms]
:: Progress: [41/41] :: Job [1/1] :: 9 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Before we start fuzzing, we must specify which file that extension would be at the end of! We can always use two wordlists and have a unique keyword for each, and then do `FUZZ_1.FUZZ_2` to fuzz for both. However, there is one file we can always find in most websites, which is `index.*`, so we will use it as our file and fuzz extensions on it.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ

# For example we found .php 
# we use
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```

### Recursive Fuzzing

In `ffuf`, we can enable recursive scanning with the `-recursion` flag, and we can specify the depth with the `-recursion-depth` flag. If we specify `-recursion-depth 1`, it will only fuzz the main directories and their direct sub-directories. If any sub-sub-directories are identified (like `/login/user`, it will not fuzz them for pages). When using recursion in `ffuf`, we can specify our extension with `-e .php`

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```

## Domain Fuzzing

Quick way of adding hosts to /etc/hosts :

```bash
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

`ffuf` to identify sub-domains (i.e., `*.website.com`) for any website.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```

**VHOST Fuzzing:**

`VHosts may or may not have public DNS records.`

To scan for VHosts, without manually adding the entire wordlist to our `/etc/hosts`, we will be fuzzing HTTP headers, specifically the `Host:` header. To do that, we can use the `-H` flag to specify a header and will use the `FUZZ` keyword within it, as follows:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```

### Filtering

```bash
ffuf -w /usr/share/seclists/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:35878 -H "Host: FUZZ.academy.htb" -fs 986
```

## Parameter Fuzzing

**Tip:** Fuzzing parameters may expose unpublished parameters that are publicly accessible. Such parameters tend to be less tested and less secured, so it is important to test such parameters for the web vulnerabilities we discuss in other modules.

### GET

Similarly to how we have been fuzzing various parts of a website, we will use `ffuf` to enumerate parameters. Let us first start with fuzzing for `GET` requests, which are usually passed right after the URL, with a `?` symbol, like:

- `http://admin.academy.htb:PORT/admin/admin.php?param1=key`.

So, all we have to do is replace `param1` in the example above with `FUZZ` and rerun our scan. Before we can start, however, we must pick an appropriate wordlist. Once again, `SecLists` has just that in `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`. With that, we can run our scan.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```

### POST

The main difference between `POST` requests and `GET` requests is that `POST` requests are not passed with the URL and cannot simply be appended after a `?` symbol. `POST` requests are passed in the `data` field within the HTTP request. Check out the [Web Requests](https://academy.hackthebox.com/module/details/35) module to learn more about HTTP requests.

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

Sending a POST request via cURL with the ‘id’ parameter:

```bash
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

### Value Fuzzing

The simplest way is to use the following command in Bash that writes all numbers from 1–1000 to a file:

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

```bash
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

Another fuzzing possible for usernames(if that’s a valid parameter that we can use) :

```bash
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ -u http://faculty.academy.htb:31886/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -t 1000 -fs 781

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://faculty.academy.htb:31886/courses/linux-security.php7
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 1000
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 781
________________________________________________

Harry                   [Status: 200, Size: 773, Words: 218, Lines: 53, Duration: 3ms]
HARRY                   [Status: 200, Size: 773, Words: 218, Lines: 53, Duration: 104ms]
harry                   [Status: 200, Size: 773, Words: 218, Lines: 53, Duration: 5ms]
```

And we use that data like this :

```bash
curl http://faculty.academy.htb:31886/courses/linux-security.php7 -X POST -d 'username=HARRY' -H 'Content-Type: application/x-www-form-urlencoded'
```