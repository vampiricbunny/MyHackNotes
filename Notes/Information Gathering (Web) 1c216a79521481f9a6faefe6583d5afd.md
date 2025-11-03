# Information Gathering (Web)

```bash
./finalrecon.py --headers --whois --url http://inlanefreight.com
```

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
./finalrecon.py --help

/// OR
sudo apt install finalrecon
```

Final Recon Install:

- [OSINT Framework](https://osintframework.com/): A collection of various tools and resources for open-source intelligence gathering. It covers a wide range of information sources, including social media, search engines, public records, and more.
- [SpiderFoot](https://github.com/smicallef/spiderfoot): An open-source intelligence automation tool that integrates with various data sources to collect information about a target, including IP addresses, domain names, email addresses, and social media profiles. It can perform DNS lookups, web crawling, port scanning, and more.
- [theHarvester](https://github.com/laramies/theHarvester): Specifically designed for gathering email addresses, subdomains, hosts, employee names, open ports, and banners from different public sources like search engines, PGP key servers, and the SHODAN database. It is a command-line tool written in Python.
- [Recon-ng](https://github.com/lanmaster53/recon-ng): A powerful framework written in Python that offers a modular structure with various modules for different reconnaissance tasks. It can perform DNS enumeration, subdomain discovery, port scanning, web crawling, and even exploit known vulnerabilities.
- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon): A Python-based reconnaissance tool offering a range of modules for different tasks like SSL certificate checking, Whois information gathering, header analysis, and crawling. Its modular structure enables easy customisation for specific needs.

These frameworks aim to provide a complete suite of tools for web reconnaissance:

## **Reconnaissance Frameworks**

# Automating Recon

- Locating Database Backups:
    - `site:example.com inurl:backup`
    - `site:example.com filetype:sql`
- Uncovering Configuration Files:
    - `site:example.com inurl:config.php`
    - `site:example.com (ext:conf OR ext:cnf)` (searches for extensions commonly used for configuration files)
- Identifying Exposed Files:
    - `site:example.com filetype:pdf`
    - `site:example.com (filetype:xls OR filetype:docx)`
- Finding Login Pages:
    - `site:example.com inurl:login`
    - `site:example.com (inurl:login OR inurl:admin)`

Here are some common examples of Google Dorks, for more examples, refer to the [Google Hacking Database](https://www.exploit-db.com/google-hacking-database):

Google Dorking, also known as Google Hacking, is a technique that leverages the power of search operators to uncover sensitive information, security vulnerabilities, or hidden content on websites, using Google Search.

### **Google Dorking**

| **Operator** | **Operator Description** | **Example** | **Example Description** |
| --- | --- | --- | --- |
| `site:` | Limits results to a specific website or domain. | `site:example.com` | Find all publicly accessible pages on example.com. |
| `inurl:` | Finds pages with a specific term in the URL. | `inurl:login` | Search for login pages on any website. |
| `filetype:` | Searches for files of a particular type. | `filetype:pdf` | Find downloadable PDF documents. |
| `intitle:` | Finds pages with a specific term in the title. | `intitle:"confidential report"` | Look for documents titled "confidential report" or similar variations. |
| `intext:` or `inbody:` | Searches for a term within the body text of pages. | `intext:"password reset"` | Identify webpages containing the term “password reset”. |
| `cache:` | Displays the cached version of a webpage (if available). | `cache:example.com` | View the cached version of example.com to see its previous content. |
| `link:` | Finds pages that link to a specific webpage. | `link:example.com` | Identify websites linking to example.com. |
| `related:` | Finds websites related to a specific webpage. | `related:example.com` | Discover websites similar to example.com. |
| `info:` | Provides a summary of information about a webpage. | `info:example.com` | Get basic details about example.com, such as its title and description. |
| `define:` | Provides definitions of a word or phrase. | `define:phishing` | Get a definition of "phishing" from various sources. |
| `numrange:` | Searches for numbers within a specific range. | `site:example.com numrange:1000-2000` | Find pages on example.com containing numbers between 1000 and 2000. |
| `allintext:` | Finds pages containing all specified words in the body text. | `allintext:admin password reset` | Search for pages containing both "admin" and "password reset" in the body text. |
| `allinurl:` | Finds pages containing all specified words in the URL. | `allinurl:admin panel` | Look for pages with "admin" and "panel" in the URL. |
| `allintitle:` | Finds pages containing all specified words in the title. | `allintitle:confidential report 2023` | Search for pages with "confidential," "report," and "2023" in the title. |
| `AND` | Narrows results by requiring all terms to be present. | `site:example.com AND (inurl:admin OR inurl:login)` | Find admin or login pages specifically on example.com. |
| `OR` | Broadens results by including pages with any of the terms. | `"linux" OR "ubuntu" OR "debian"` | Search for webpages mentioning Linux, Ubuntu, or Debian. |
| `NOT` | Excludes results containing the specified term. | `site:bank.com NOT inurl:login` | Find pages on bank.com excluding login pages. |
| `*` (wildcard) | Represents any character or word. | `site:socialnetwork.com filetype:pdf user* manual` | Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com. |
| `..` (range search) | Finds results within a specified numerical range. | `site:ecommerce.com "price" 100..500` | Look for products priced between 100 and 500 on an e-commerce website. |
| `" "` (quotation marks) | Searches for exact phrases. | `"information security policy"` | Find documents mentioning the exact phrase "information security policy". |
| `-` (minus sign) | Excludes terms from the search results. | `site:news.com -inurl:sports` | Search for news articles on news.com excluding sports-related content. |

# Dorking / Search Operators

- **`comments`**: HTML comments in the source code.
- **`audio`**: URLs to audio files (may be empty).
- **`videos`**: URLs to videos (may be empty).
- **`images`**: URLs to images.
- **`form_fields`**: Form fields (may be empty).
- **`js_files`**: URLs to JavaScript files used.
- **`external_files`**: URLs to external resources (e.g., PDFs).
- **`links`**: URLs of links within the domain.
- **`emails`**: Email addresses found on the site.

### Explanation of JSON Keys

- The data collected is stored in `results.json`, containing:
    
    ```json
    {
        "emails": ["lily.floid@inlanefreight.com", "cvs@inlanefreight.com", ...],
        "links": ["<https://www.themeansar.com>", "<https://www.inlanefreight.com/index.php/offices/>", ...],
        "external_files": ["<https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf>", ...],
        "js_files": ["<https://www.inlanefreight.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.2>", ...],
        "form_fields": [],
        "images": ["<https://www.inlanefreight.com/wp-content/uploads/2021/03/AboutUs_01-1024x810.png>", ...],
        "videos": [],
        "audio": [],
        "comments": ["<!-- #masthead -->", ...]
    }
    
    ```
    

### Output: `results.json`

1. Run the spider with:
    
    ```bash
    python3 ReconSpider.py <http://inlanefreight.com>
    ```
    
    - Replace `inlanefreight.com` with your target domain.
2. Download and extract ReconSpider:
    
    ```bash
    wget -O ReconSpider.zip <https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip>
    unzip ReconSpider.zip
    ```
    

### Setting Up ReconSpider

- A custom spider, **ReconSpider**, is used for tailored reconnaissance tasks.
- Install Scrapy using:
    
    ```bash
    sudo apt install scrapy
    ```
    

## Using Scrapy for Reconnaissance

- Avoid overloading servers with excessive requests.
- Always obtain permission before initiating crawls.

### Ethical Considerations

- **Apache Nutch**:
    - Extensible and scalable Java-based open-source crawler.
    - Suitable for large-scale crawls or focused domain-specific crawling.
    - Requires advanced setup but offers significant power and flexibility.
- **Scrapy (Python Framework)**:
    - A powerful, scalable Python framework for building custom web crawlers.
    - Ideal for structured data extraction and complex crawl automation.
- **OWASP ZAP (Zed Attack Proxy)**:
    - Open-source web security scanner with a spider component.
    - Useful for both automated and manual web app scans.
- **Burp Suite Spider**:
    - Part of Burp Suite, used for web app testing.
    - Maps out web applications, uncovers hidden content, and identifies vulnerabilities.

# Creepy Crawlies

- Provides structured and standardized access to key data, aiding in comprehensive security mapping.
- Experimenting with registered `.well-known` URIs allows for enhanced web reconnaissance.

## Benefits of Exploring the IANA Registry

- **Security Insights**:
    - Supported scopes, response types, and algorithms help map implementation details.
    - Algorithm support informs about cryptographic practices and security posture.
- **JWKS URI**: Information about the cryptographic keys used by the server.
- **Endpoint discovery**: Identify URLs for user authorization and token services.

## Analysis of Retrieved Metadata

- **`openid-configuration`** usage:
    - Accessed via `https://example.com/.well-known/openid-configuration`.
    - Provides JSON metadata including:
        - **Endpoints**: `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`.
        - **Supported types**: `response_types`, `scopes`, signing algorithms.
    - Example JSON:
        
        ```json
        {
          "issuer": "<https://example.com>",
          "authorization_endpoint": "<https://example.com/oauth2/authorize>",
          "token_endpoint": "<https://example.com/oauth2/token>",
          "userinfo_endpoint": "<https://example.com/oauth2/userinfo>",
          "jwks_uri": "<https://example.com/oauth2/jwks>",
          "response_types_supported": ["code", "token", "id_token"],
          "subject_types_supported": ["public"],
          "id_token_signing_alg_values_supported": ["RS256"],
          "scopes_supported": ["openid", "profile", "email"]
        }
        ```
        
- **Web security testing**: `.well-known` URIs aid in discovering endpoints and configurations.

## Application in Web Reconnaissance

- **Key examples**:
    - **`security.txt`**: Contact info for reporting vulnerabilities (Permanent, RFC 9116).
    - **`/change-password`**: URL for user password changes (Provisional, WebAppSec Spec).
    - **`openid-configuration`**: OpenID Connect configuration details (Permanent, OpenID Spec).
    - **`assetlinks.json`**: Verifies digital asset ownership (Permanent, Google Spec).
    - **`mta-sts.txt`**: Policy for MTA-STS, enhancing email security (Permanent, RFC 8461).
- IANA maintains a list of well-known URIs, each with specific purposes.

## IANA Registry Highlights

- Example URL: `https://example.com/.well-known/security.txt` for accessing a site's security policy.
- Facilitates easy access for web tools and clients.
- Typically accessed via `/.well-known/`, centralizing metadata, configuration files, and protocol info.
- **RFC 8615** standardizes the `.well-known` directory within a site's root domain.

## Overview of .well-known

# Extended Notes on Well-Known URIs

By analyzing this robots.txt, we can infer that the website likely has an admin panel located at `/admin/` and some private content in the `/private/` directory.

- The sitemap, located at `https://www.example.com/sitemap.xml`, is provided for easier crawling and indexing.
- The `Googlebot` (Google's web crawler) is specifically instructed to wait 10 seconds between requests.
- All user agents are allowed to access the `/public/` directory.
- All user agents are disallowed from accessing the `/admin/` and `/private/` directories.

This file contains the following directives:

```
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/

User-agent: Googlebot
Crawl-delay: 10

Sitemap: https://www.example.com/sitemap.xml
```

Here's an example of a robots.txt file:

### **Analyzing robots.txt**

| **Directive** | **Description** | **Example** |
| --- | --- | --- |
| `Disallow` | Specifies paths or patterns that the bot should not crawl. | `Disallow: /admin/` (disallow access to the admin directory) |
| `Allow` | Explicitly permits the bot to crawl specific paths or patterns, even if they fall under a broader `Disallow` rule. | `Allow: /public/` (allow access to the public directory) |
| `Crawl-delay` | Sets a delay (in seconds) between successive requests from the bot to avoid overloading the server. | `Crawl-delay: 10` (10-second delay between requests) |
| `Sitemap` | Provides the URL to an XML sitemap for more efficient crawling. | `Sitemap: https://www.example.com/sitemap.xml` |

Common directives include:

1. `Directives`: These lines provide specific instructions to the identified user-agent.
2. `User-agent`: This line specifies which crawler or bot the following rules apply to. A wildcard () indicates that the rules apply to all bots. Specific user agents can also be targeted, such as "Googlebot" (Google's crawler) or "Bingbot" (Microsoft's crawler).

Technically, `robots.txt` is a simple text file placed in the root directory of a website (e.g., `www.example.com/robots.txt`). It adheres to the Robots Exclusion Standard, guidelines for how web crawlers should behave when visiting a website. This file contains instructions in the form of "directives" that tell bots which parts of the website they can and cannot crawl.

## Robots.txt

- `Sensitive Files`: Web crawlers can be configured to actively search for sensitive files that might be inadvertently exposed on a website. This includes `backup files` (e.g., `.bak`, `.old`), `configuration files` (e.g., `web.config`, `settings.php`), `log files` (e.g., `error_log`, `access_log`), and other files containing passwords, `API keys`, or other confidential information. Carefully examining the extracted files, especially backup and configuration files, can reveal a trove of sensitive information, such as `database credentials`, `encryption keys`, or even source code snippets.
- `Metadata`: Metadata refers to `data about data`. In the context of web pages, it includes information like page titles, descriptions, keywords, author names, and dates. This metadata can provide valuable context about a page's content, purpose, and relevance to your reconnaissance goals.
- `Comments`: Comments sections on blogs, forums, or other interactive pages can be a goldmine of information. Users often inadvertently reveal sensitive details, internal processes, or hints of vulnerabilities in their comments.
- `Links (Internal and External)`: These are the fundamental building blocks of the web, connecting pages within a website (`internal links`) and to other websites (`external links`). Crawlers meticulously collect these links, allowing you to map out a website's structure, discover hidden pages, and identify relationships with external resources.

Crawlers can extract a diverse array of data, each serving a specific purpose in the reconnaissance process:

In contrast, `depth-first crawling` prioritizes depth over breadth. It follows a single path of links as far as possible before backtracking and exploring other paths. This can be useful for finding specific content or reaching deep into a website's structure.

![image.png](image%2014.png)

### **Depth-First Crawling**

`Breadth-first crawling` prioritizes exploring a website's width before going deep. It starts by crawling all the links on the seed page, then moves on to the links on those pages, and so on. This is useful for getting a broad overview of a website's structure and content.

![image.png](image%2015.png)

### **Breadth-First Crawling**

There are two primary types of crawling strategies.

This example illustrates how a web crawler discovers and collects information by systematically following links, distinguishing it from fuzzing which involves guessing potential links.

1. `Continuing the Crawl`: The crawler continues to follow these links systematically, gathering all accessible pages and their links.
2. `Visiting link1`: Visiting `link1` shows the homepage, `link2`, and also `link4` and `link5`.
    
    Code: txt
    
    ```
    link1 Page
    ├── Homepage
    ├── link2
    ├── link4
    └── link5
    ```
    
3. `Homepage`: You start with the homepage containing `link1`, `link2`, and `link3`.
    
    Code: txt
    
    ```
    Homepage
    ├── link1
    ├── link2
    └── link3
    ```
    

`Crawling`, often called `spidering`, is the `automated process of systematically browsing the World Wide Web`.

# Crawling

```bash
whatweb -a3 10.129.18.61 -H "Host: dev.inlanefreight.local" -v
nikto -h <> -Tuning b
```

| **Tool** | **Description** | **Features** |
| --- | --- | --- |
| `Wappalyzer` | Browser extension and online service for website technology profiling. | Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more. |
| `BuiltWith` | Web technology profiler that provides detailed reports on a website's technology stack. | Offers both free and paid plans with varying levels of detail. |
| `WhatWeb` | Command-line tool for website fingerprinting. | Uses a vast database of signatures to identify various web technologies. |
| `Nmap` | Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting. | Can be used with scripts (NSE) to perform more specialised fingerprinting. |
| `Netcraft` | Offers a range of web security services, including website fingerprinting and security reporting. | Provides detailed reports on a website's technology, hosting provider, and security posture. |
| `wafw00f` | Command-line tool specifically designed for identifying Web Application Firewalls (WAFs). | Helps determine if a WAF is present and, if so, its type and configuration. |

A variety of tools exist that automate the fingerprinting process, combining various techniques to identify web servers, operating systems, content management systems, and other technologies:

- `Analysing Page Content`: A web page's content, including its structure, scripts, and other elements, can often provide clues about the underlying technologies. There may be a copyright header that indicates specific software being used, for example.
- `Probing for Specific Responses`: Sending specially crafted requests to the target can elicit unique responses that reveal specific technologies or versions. For example, certain error messages or behaviours are characteristic of particular web servers or software components.
- `Analysing HTTP Headers`: HTTP headers transmitted with every web page request and response contain a wealth of information. The `Server` header typically discloses the web server software, while the `X-Powered-By` header might reveal additional technologies like scripting languages or frameworks.
- `Banner Grabbing`: Banner grabbing involves analysing the banners presented by web servers and other services. These banners often reveal the server software, version numbers, and other details.

## Techniques

- `Building a Comprehensive Profile`: Combining fingerprint data with other reconnaissance findings creates a holistic view of the target's infrastructure, aiding in understanding its overall security posture and potential attack vectors.
- `Prioritising Targets`: When faced with multiple potential targets, fingerprinting helps prioritise efforts by identifying systems more likely to be vulnerable or hold valuable information.
- `Identifying Misconfigurations`: Fingerprinting can expose misconfigured or outdated software, default settings, or other weaknesses that might not be apparent through other reconnaissance methods.
- `Targeted Attacks`: By knowing the specific technologies in use, attackers can focus their efforts on exploits and vulnerabilities that are known to affect those systems. This significantly increases the chances of a successful compromise.

Fingerprinting serves as a cornerstone of web reconnaissance for several reasons:

# Fingerprinting

- `sort -u`: This sorts the results alphabetically and removes duplicates.
- `jq -r '.[] | select(.name_value | contains("dev")) | .name_value'`: This part filters the JSON results, selecting only entries where the `name_value` field (which contains the domain or subdomain) includes the string "`dev.`" The `r` flag tells `jq` to output raw strings.
- `curl -s "https://crt.sh/?q=facebook.com&output=json"`: This command fetches the JSON output from crt.sh for certificates matching the domain `facebook.com`.

```bash
DarkSideDani@htb[/htb]$ curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
 
*.dev.facebook.com
*.newdev.facebook.com
*.secure.dev.facebook.com
dev.facebook.com
devvm1958.ftw3.facebook.com
facebook-amex-dev.facebook.com
facebook-amex-sign-enc-dev.facebook.com
newdev.facebook.com
secure.dev.facebook.com
```

While `crt.sh` offers a convenient web interface, you can also leverage its API for automated searches directly from your terminal. Let's see how to find all 'dev' subdomains on `facebook.com` using `curl` and `jq`:

### **crt.sh lookup**

| **Tool** | **Key Features** | **Use Cases** | **Pros** | **Cons** |
| --- | --- | --- | --- | --- |
| [crt.sh](https://crt.sh/) | User-friendly web interface, simple search by domain, displays certificate details, SAN entries. | Quick and easy searches, identifying subdomains, checking certificate issuance history. | Free, easy to use, no registration required. | Limited filtering and analysis options. |
| [Censys](https://search.censys.io/) | Powerful search engine for internet-connected devices, advanced filtering by domain, IP, certificate attributes. | In-depth analysis of certificates, identifying misconfigurations, finding related certificates and hosts. | Extensive data and filtering options, API access. | Requires registration (free tier available). |

There are two popular options for searching CT logs:

`Certificate Transparency` (`CT`) logs are public, append-only ledgers that record the issuance of SSL/TLS certificates. Whenever a Certificate Authority (CA) issues a new certificate, it must submit it to multiple CT logs. Independent organisations maintain these logs and are open for anyone to inspect.

# Certificate Transparency Logs

- `o`: Save output to a file for analysis.
- `k`: Ignore SSL/TLS certificate errors.
- `t`: Increase the number of threads for faster scanning.

### Additional Useful Gobuster Flags:

```bash
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

└─$ gobuster vhost -u http://inlanefreight.htb:52357 -w /usr/share/seclists/Discovery/DNS/namelist.txt --append-domain -t 50
```

### Command Example:

- `-append-domain`: Ensures that the base domain is appended to each word.
- `w`: Specifies the wordlist file path.
- `u`: Specifies the target URL (replace `<target_IP_address>`).

```bash
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```

### Basic Gobuster Command:

1. **Prepare a Wordlist**: Use or create a wordlist with potential hostnames (e.g., SecLists).
2. **Identify the Target**: Obtain the target web server's IP address.

### Using Gobuster for Virtual Host Discovery

- [**ffuf**](https://github.com/ffuf/ffuf): A fast fuzzer that can also probe virtual hosts by manipulating the Host header.
- [**Feroxbuster**](https://github.com/epi052/feroxbuster): A Rust-based tool, known for speed and recursion capabilities.
- [**Gobuster**](https://github.com/OJ/gobuster): A multi-purpose tool used for directory brute-forcing and virtual host discovery.

### Tools for VHost Discovery

## Discovery of Virtual Hosts

1. **Port-Based Virtual Hosting**:
    - Different sites use different ports (e.g., port 80 vs. 8080).
    - Less common and may require users to include the port in URLs.
2. **IP-Based Virtual Hosting**:
    - Assigns a unique IP for each hosted site.
    - Provides better isolation but requires more IP addresses.
3. **Name-Based Virtual Hosting**:
    - Uses the HTTP Host header to differentiate requests.
    - Cost-effective and easy to set up.
    - May have limitations with older SSL/TLS configurations.

## Types of Virtual Hosting

- **Local Hosts File**: Modify the local `hosts` file to map a domain name to an IP address manually, bypassing DNS.

### Accessing VHosts Without DNS Records

```bash
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

### Example of VHost Configuration in Apache

- **Subdomains vs. VHosts**:
    - **Subdomains**: DNS-based extensions of a domain (e.g., [blog.example.com](http://blog.example.com/)). They can point to the same or different IPs.
    - **Virtual Hosts (VHosts)**: Configurations within a web server that specify which content to serve for different domains or subdomains.
- **HTTP Host Header**: The core mechanism for virtual hosting. Web servers use the Host header in HTTP requests to determine the appropriate content to serve.

## How Virtual Hosts Work

Virtual hosting enables a single web server to host multiple websites or applications. This functionality allows differentiation between domains and subdomains, even when they share the same IP address.

# Virtual Hosts Overview

```bash
dig axfr <target-domain> @<dns-server>
```

Command to Request Zone Transfer:

### Exploitation Example Using `dig`

- **Awareness**: Regularly audit DNS server settings to prevent accidental misconfigurations.
- **Access Control**: Configure DNS servers to only allow zone transfers to trusted secondary servers.

### Remediation Steps

- **Consequences**:
    - **Subdomains**: Full visibility into subdomains, including non-public ones (e.g., dev, admin panels).
    - **IP Addresses**: Exposure of IP addresses linked to subdomains.
    - **Name Servers**: Insight into the hosting provider and potential misconfigurations.
- **Risk**: If access control is poorly configured, any client can request and download the zone file.

### Zone Transfer Vulnerability

- **Mechanism**:
    - **AXFR Request**: A secondary DNS server requests a zone transfer from the primary server.
    - **SOA Record**: The primary server sends the Start of Authority (SOA) record to the secondary server.
    - **Record Transmission**: DNS records (e.g., A, MX, CNAME, NS) are sent sequentially.
    - **Completion**: The primary server signals the end of the transfer.
    - **ACK**: The secondary server acknowledges receipt.
- **Definition**: A DNS zone transfer is the copying of DNS records within a zone from one name server to another, maintaining data consistency.

### What is a Zone Transfer?

![image.png](image%2016.png)

While brute-forcing can be a fruitful approach, there's a less invasive and potentially more efficient method for uncovering subdomains – DNS zone transfers. This mechanism, designed for replicating DNS records between name servers, can inadvertently become a goldmine of information for prying eyes if misconfigured.

## DNS Zone Transfers

```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
```

ex:

| **Tool** | **Description** |
| --- | --- |
| [dnsenum](https://github.com/fwaeytens/dnsenum) | Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains. |
| [fierce](https://github.com/mschwager/fierce) | User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface. |
| [dnsrecon](https://github.com/darkoperator/dnsrecon) | Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats. |
| [amass](https://github.com/owasp-amass/amass) | Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources. |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans. |
| [puredns](https://github.com/d3mondev/puredns) | Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively. |

There are several tools available that excel at brute-force enumeration:

### Subdomain Bruteforcing

`Active enumeration` can be more thorough but carries a higher risk of detection. Conversely, `passive enumeration` is stealthier but may not uncover all subdomains. Combining both techniques can significantly increase the likelihood of discovering a comprehensive list of subdomains associated with your target, expanding your understanding of their online presence and potential vulnerabilities.

| **Approach** | **Description** | **Examples** |
| --- | --- | --- |
| `Active Enumeration` | Directly interacts with the target's DNS servers or utilizes tools to probe for subdomains. | Brute-forcing, DNS zone transfers |
| `Passive Enumeration` | Collects information about subdomains without directly interacting with the target, relying on public sources. | Certificate Transparency (CT) logs, search engine queries |

The process of discovering subdomains is known as subdomain enumeration. There are two main approaches to subdomain enumeration:

From a reconnaissance perspective, subdomains are incredibly valuable. They can expose additional attack surfaces, reveal hidden services, and provide clues about the internal structure of a target's network. Subdomains might host development servers, staging environments, or even forgotten applications that haven't been properly secured.

### Subdomain

Caution: Some servers can detect and block excessive DNS queries. Use caution and respect rate limits. Always obtain permission before performing extensive DNS reconnaissance on a target.

| **Command** | **Description** |
| --- | --- |
| `dig domain.com` | Performs a default A record lookup for the domain. |
| `dig domain.com A` | Retrieves the IPv4 address (A record) associated with the domain. |
| `dig domain.com AAAA` | Retrieves the IPv6 address (AAAA record) associated with the domain. |
| `dig domain.com MX` | Finds the mail servers (MX records) responsible for the domain. |
| `dig domain.com NS` | Identifies the authoritative name servers for the domain. |
| `dig domain.com TXT` | Retrieves any TXT records associated with the domain. |
| `dig domain.com CNAME` | Retrieves the canonical name (CNAME) record for the domain. |
| `dig domain.com SOA` | Retrieves the start of authority (SOA) record for the domain. |
| `dig @1.1.1.1 domain.com` | Specifies a specific name server to query; in this case 1.1.1.1 |
| `dig +trace domain.com` | Shows the full path of DNS resolution. |
| `dig -x 192.168.1.1` | Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server. |
| `dig +short domain.com` | Provides a short, concise answer to the query. |
| `dig +noall +answer domain.com` | Displays only the answer section of the query output. |
| `dig domain.com ANY` | Retrieves all available DNS records for the domain (Note: Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as per [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482)). |

### **Common dig Commands**

The `dig` command (`Domain Information Groper`) is a versatile and powerful utility for querying DNS servers and retrieving various types of DNS records. Its flexibility and detailed and customizable output make it a go-to choice.

### dig

| **Tool** | **Key Features** | **Use Cases** |
| --- | --- | --- |
| `dig` | Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records. |
| `nslookup` | Simpler DNS lookup tool, primarily for A, AAAA, and MX records. | Basic DNS queries, quick checks of domain resolution and mail server records. |
| `host` | Streamlined DNS lookup tool with concise output. | Quick checks of A, AAAA, and MX records. |
| `dnsenum` | Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed). | Discovering subdomains and gathering DNS information efficiently. |
| `fierce` | DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection. | User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets. |
| `dnsrecon` | Combines multiple DNS reconnaissance techniques and supports various output formats. | Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis. |
| `theHarvester` | OSINT tool that gathers information from various sources, including DNS records (email addresses). | Collecting email addresses, employee information, and other data associated with a domain from multiple sources. |
| Online DNS Lookup Services | User-friendly interfaces for performing DNS lookups. | Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information |

DNS reconnaissance involves utilizing specialized tools designed to query DNS servers and extract valuable information. Here are some of the most popular and versatile tools in the arsenal of web recon professionals:

### DNS Tools

- `Monitoring for Changes`: Continuously monitoring DNS records can reveal changes in the target's infrastructure over time. For example, the sudden appearance of a new subdomain (`vpn.example.com`) might indicate a new entry point into the network, while a `TXT` record containing a value like `_1password=...` strongly suggests the organization is using 1Password, which could be leveraged for social engineering attacks or targeted phishing campaigns.
- `Mapping the Network Infrastructure`: You can create a comprehensive map of the target's network infrastructure by analysing DNS data. For example, identifying the name servers (`NS` records) for a domain can reveal the hosting provider used, while an `A` record for `loadbalancer.example.com` can pinpoint a load balancer. This helps you understand how different systems are connected, identify traffic flow, and pinpoint potential choke points or weaknesses that could be exploited during a penetration test.
- `Uncovering Assets`: DNS records can reveal a wealth of information, including subdomains, mail servers, and name server records. For instance, a `CNAME` record pointing to an outdated server (`dev.example.com` CNAME `oldserver.example.net`) could lead to a vulnerable system.

DNS is not merely a technical protocol for translating domain names; it's a critical component of a target's infrastructure that can be leveraged to uncover vulnerabilities and gain access during a penetration test:

### **Why DNS Matters for Web Recon**

| **Record Type** | **Full Name** | **Description** | **Zone File Example** |
| --- | --- | --- | --- |
| `A` | Address Record | Maps a hostname to its IPv4 address. | `www.example.com.` IN A `192.0.2.1` |
| `AAAA` | IPv6 Address Record | Maps a hostname to its IPv6 address. | `www.example.com.` IN AAAA `2001:db8:85a3::8a2e:370:7334` |
| `CNAME` | Canonical Name Record | Creates an alias for a hostname, pointing it to another hostname. | `blog.example.com.` IN CNAME `webserver.example.net.` |
| `MX` | Mail Exchange Record | Specifies the mail server(s) responsible for handling email for the domain. | `example.com.` IN MX 10 `mail.example.com.` |
| `NS` | Name Server Record | Delegates a DNS zone to a specific authoritative name server. | `example.com.` IN NS `ns1.example.com.` |
| `TXT` | Text Record | Stores arbitrary text information, often used for domain verification or security policies. | `example.com.` IN TXT `"v=spf1 mx -all"` (SPF record) |
| `SOA` | Start of Authority Record | Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. | `example.com.` IN SOA `ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400` |
| `SRV` | Service Record | Defines the hostname and port number for specific services. | `_sip._udp.example.com.` IN SRV 10 5 5060 `sipserver.example.com.` |
| `PTR` | Pointer Record | Used for reverse DNS lookups, mapping an IP address to a hostname. | `1.2.0.192.in-addr.arpa.` IN PTR `www.example.com.` |

Now that we've explored the fundamental concepts of DNS, let's dive deeper into the building blocks of DNS information – the various record types. These records store different types of data associated with domain names, each serving a specific purpose:

| **DNS Concept** | **Description** | **Example** |
| --- | --- | --- |
| `Domain Name` | A human-readable label for a website or other internet resource. | `www.example.com` |
| `IP Address` | A unique numerical identifier assigned to each device connected to the internet. | `192.0.2.1` |
| `DNS Resolver` | A server that translates domain names into IP addresses. | Your ISP's DNS server or public resolvers like Google DNS (`8.8.8.8`) |
| `Root Name Server` | The top-level servers in the DNS hierarchy. | There are 13 root servers worldwide, named A-M: `a.root-servers.net` |
| `TLD Name Server` | Servers responsible for specific top-level domains (e.g., .com, .org). | [Verisign](https://en.wikipedia.org/wiki/Verisign) for `.com`, [PIR](https://en.wikipedia.org/wiki/Public_Interest_Registry) for `.org` |
| `Authoritative Name Server` | The server that holds the actual IP address for a domain. | Often managed by hosting providers or domain registrars. |
| `DNS Record Types` | Different types of information stored in DNS. | A, AAAA, CNAME, MX, NS, TXT, etc. |

DNS servers store various resource records, each serving a specific purpose in the domain name resolution process. Let's explore some of the most common DNS concepts:

1. `Your Computer Connects`: Now that your computer knows the IP address, it can connect directly to the web server hosting the website, and you can start browsing.
2. `The DNS Resolver Returns the Information`: The resolver receives the IP address and gives it to your computer. It also remembers it for a while (caches it), in case you want to revisit the website soon.
3. `Authoritative Name Server Delivers the Address`: The authoritative name server is the final stop. It's like the street address of the website you want. It holds the correct IP address and sends it back to the resolver.
4. `TLD Name Server Narrows It Down`: The TLD name server is like a regional map. It knows which authoritative name server is responsible for the specific domain you're looking for (e.g., `example.com`) and sends the resolver there.
5. `Root Name Server Points the Way`: The root server doesn't know the exact address but knows who does – the Top-Level Domain (TLD) name server responsible for the domain's ending (e.g., .com, .org). It points the resolver in the right direction.
6. `The DNS Resolver Checks its Map (Recursive Lookup)`: The resolver also has a cache, and if it doesn't find the IP address there, it starts a journey through the DNS hierarchy. It begins by asking a root name server, which is like the librarian of the internet.
7. `Your Computer Asks for Directions (DNS Query)`: When you enter the domain name, your computer first checks its memory (cache) to see if it remembers the IP address from a previous visit. If not, it reaches out to a DNS resolver, usually provided by your internet service provider (ISP).

## DNS

| **Technique** | **Description** | **Example** | **Tools** | **Risk of Detection** |
| --- | --- | --- | --- | --- |
| `Search Engine Queries` | Utilising search engines to uncover information about the target, including websites, social media profiles, and news articles. | Searching Google for "`[Target Name] employees`" to find employee information or social media profiles. | Google, DuckDuckGo, Bing, and specialised search engines (e.g., Shodan) | Very Low: Search engine queries are normal internet activity and unlikely to trigger alerts. |
| `WHOIS Lookups` | Querying WHOIS databases to retrieve domain registration details. | Performing a WHOIS lookup on a target domain to find the registrant's name, contact information, and name servers. | whois command-line tool, online WHOIS lookup services | Very Low: WHOIS queries are legitimate and do not raise suspicion. |
| `DNS` | Analysing DNS records to identify subdomains, mail servers, and other infrastructure. | Using `dig` to enumerate subdomains of a target domain. | dig, nslookup, host, dnsenum, fierce, dnsrecon | Very Low: DNS queries are essential for internet browsing and are not typically flagged as suspicious. |
| `Web Archive Analysis` | Examining historical snapshots of the target's website to identify changes, vulnerabilities, or hidden information. | Using the Wayback Machine to view past versions of a target website to see how it has changed over time. | Wayback Machine | Very Low: Accessing archived versions of websites is a normal activity. |
| `Social Media Analysis` | Gathering information from social media platforms like LinkedIn, Twitter, or Facebook. | Searching LinkedIn for employees of a target organisation to learn about their roles, responsibilities, and potential social engineering targets. | LinkedIn, Twitter, Facebook, specialised OSINT tools | Very Low: Accessing public social media profiles is not considered intrusive. |
| `Code Repositories` | Analysing publicly accessible code repositories like GitHub for exposed credentials or vulnerabilities. | Searching GitHub for code snippets or repositories related to the target that might contain sensitive information or code vulnerabilities. | GitHub, GitLab | Very Low: Code repositories are meant for public access, and searching them is not suspicious. |

## Passive Recon

| **Technique** | **Description** | **Example** | **Tools** | **Risk of Detection** |
| --- | --- | --- | --- | --- |
| `Port Scanning` | Identifying open ports and services running on the target. | Using Nmap to scan a web server for open ports like 80 (HTTP) and 443 (HTTPS). | Nmap, Masscan, Unicornscan | High: Direct interaction with the target can trigger intrusion detection systems (IDS) and firewalls. |
| `Vulnerability Scanning` | Probing the target for known vulnerabilities, such as outdated software or misconfigurations. | Running Nessus against a web application to check for SQL injection flaws or cross-site scripting (XSS) vulnerabilities. | Nessus, OpenVAS, Nikto | High: Vulnerability scanners send exploit payloads that security solutions can detect. |
| `Network Mapping` | Mapping the target's network topology, including connected devices and their relationships. | Using traceroute to determine the path packets take to reach the target server, revealing potential network hops and infrastructure. | Traceroute, Nmap | Medium to High: Excessive or unusual network traffic can raise suspicion. |
| `Banner Grabbing` | Retrieving information from banners displayed by services running on the target. | Connecting to a web server on port 80 and examining the HTTP banner to identify the web server software and version. | Netcat, curl | Low: Banner grabbing typically involves minimal interaction but can still be logged. |
| `OS Fingerprinting` | Identifying the operating system running on the target. | Using Nmap's OS detection capabilities (`-O`) to determine if the target is running Windows, Linux, or another OS. | Nmap, Xprobe2 | Low: OS fingerprinting is usually passive, but some advanced techniques can be detected. |
| `Service Enumeration` | Determining the specific versions of services running on open ports. | Using Nmap's service version detection (`-sV`) to determine if a web server is running Apache 2.4.50 or Nginx 1.18.0. | Nmap | Low: Similar to banner grabbing, service enumeration can be logged but is less likely to trigger alerts. |
| `Web Spidering` | Crawling the target website to identify web pages, directories, and files. | Running a web crawler like Burp Suite Spider or OWASP ZAP Spider to map out the structure of a website and discover hidden resources. | Burp Suite Spider, OWASP ZAP Spider, Scrapy (customisable) | Low to Medium: Can be detected if the crawler's behaviour is not carefully configured to mimic legitimate traffic. |

## Active Recon

- `Gathering Intelligence`: Collecting information that can be leveraged for further exploitation or social engineering attacks. This includes identifying key personnel, email addresses, or patterns of behaviour that could be exploited.
- `Analysing the Attack Surface`: Examining the target's attack surface to identify potential vulnerabilities and weaknesses. This involves assessing the technologies used, configurations, and possible entry points for exploitation.
- `Discovering Hidden Information`: Locating sensitive information that might be inadvertently exposed, including backup files, configuration files, or internal documentation. These findings can reveal valuable insights and potential entry points for attacks.
- `Identifying Assets`: Uncovering all publicly accessible components of the target, such as web pages, subdomains, IP addresses, and technologies used. This step provides a comprehensive overview of the target's online presence.

The primary goals of web reconnaissance include: