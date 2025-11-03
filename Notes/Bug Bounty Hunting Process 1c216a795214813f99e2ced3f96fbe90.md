# Bug Bounty Hunting Process

# **Bug Bounty Programs Overview**

Bug bounty programs (BBPs), also referred to as **vulnerability rewards programs (VRPs)**, are initiatives that encourage ethical hackers to discover and report vulnerabilities. They play a significant role in supplementing internal security audits and penetration tests by providing continuous, proactive security testing.

---

### **Types of Bug Bounty Programs**

1. **Private Bug Bounty Programs**:
    - Invitation-only programs restricted to a select group of hunters.
    - Typically used during the initial phase of a program.
    - Invitations are based on:
        - Track record of valid findings.
        - Consistency and quality of reports.
        - No prior code of conduct violations.
    - May require background checks for participation.
2. **Public Bug Bounty Programs**:
    - Open to the entire ethical hacking community.
    - Usually launched after a successful private program phase.
3. **Parent/Child Programs**:
    - Shared bounty pool and security team between a parent organization and its subsidiaries.
    - Subsidiary programs (child programs) are linked to the parent program.

---

### **Bug Bounty Programs vs. Vulnerability Disclosure Programs**

- **Bug Bounty Programs (BBPs)**:
    - Offer monetary rewards for finding vulnerabilities.
    - Incentivize security researchers to report bugs.
- [**Vulnerability Disclosure Programs (VDPs)**:](https://docs.hackerone.com/en/articles/8368965-vdp-vs-bbp#gatsby-focus-wrapper)
    - Focus on receiving information about vulnerabilities without necessarily offering rewards.
    - Provide guidance on how to report issues ethically.

---

### **Bug Bounty Program Code of Conduct**

- Follow the **code of conduct** or policy of the platform or organization hosting the bug bounty program.
- Adhere to **responsible disclosure** practices.
- Maintain **professionalism and technical capability** to establish a good reputation.
- Review [HackerOne's **Code of Conduct**](https://www.hacker101.com/resources/articles/code_of_conduct) for an example of expectations.

---

### **Typical Bug Bounty Program Structure**

1. **Vendor Response SLAs**:
    - Timelines and methods for vendor replies to submissions.
2. **Access**:
    - Guidelines on obtaining accounts or permissions for testing.
3. **Eligibility Criteria**:
    - Requirements to qualify for rewards (e.g., first valid report).
4. **Responsible Disclosure Policy**:
    - Safe disclosure practices, timelines, and coordination actions.
5. **Rules of Engagement**:
    - Do’s and don’ts during testing.
6. **Scope**:
    - Defined in-scope IP ranges, domains, apps, or vulnerabilities.
7. **Out of Scope**:
    - Explicitly excluded targets or vulnerabilities.
8. **Reporting Format**:
    - Clear guidelines on how to structure vulnerability reports.
9. **Rewards**:
    - Information on payout ranges or types of rewards.
10. **Safe Harbor**:
    - Legal protections for ethical hackers.
11. **Legal Terms and Conditions**:
    - Applicable laws and terms for participation.
12. **Contact Information**:
    - Details for program administrators or vendor support.

---

### **Best Practices for Bug Bounty Hunters**

1. **Thoroughly Read Program Policies**:
    - Understand rules, scope, and expectations before starting.
    - Avoid wasting time on out-of-scope targets.
2. **Focus on Responsible Disclosure**:
    - Never exploit or share vulnerabilities publicly without permission.
3. **Efficient Reporting**:
    - Provide clear, concise, and reproducible steps in your report.
    - Use standard reporting formats (e.g., severity levels, PoCs).
4. **Time Management**:
    - Act quickly, as programs often reward the first valid submission.
5. **Build a Good Reputation**:
    - Avoid violating the code of conduct or program rules.

---

### **Where to Find Bug Bounty Programs**

1. [**HackerOne Directory**](https://hackerone.com/directory/programs):
    - Comprehensive list of active bug bounty programs.
    - Provides scope, rewards, and contact details.
2. **Bugcrowd**:
    - Another platform with a variety of public and private programs.
3. **Open Bug Bounty**:
    - Focuses on responsible disclosure without monetary rewards.
4. **Direct Company Listings**:
    - Many organizations list bug bounty programs on their websites.

---

### **Key Takeaways**

Bug bounty programs provide a platform for ethical hackers to improve an organization’s security while receiving rewards. Adhering to program policies, practicing responsible disclosure, and maintaining professionalism are essential for success in the bug bounty community.

# [**Crafting a Good Bug Report**](https://academy.hackthebox.com/module/161/section/1506)

A clear and concise bug report helps security teams reproduce and understand the impact of a vulnerability. Below are the **essential elements** of a well-structured bug report:

---

### **1. Vulnerability Title**

- Include:
    - **Type of vulnerability** (e.g., SQL Injection, Cross-Site Scripting).
    - **Affected component/domain/endpoint.**
    - **Impact** (e.g., data exposure, privilege escalation).
- Example:**"SQL Injection in `/api/login` Allows Access to User Data"**

---

### **2. CWE & CVSS Score**

- **CWE (Common Weakness Enumeration):**
    - Identify the underlying weakness type (e.g., CWE-89 for SQL Injection).
    - Reference: [CWE Official Website](https://cwe.mitre.org/).
- **CVSS (Common Vulnerability Scoring System):**
    - Use the CVSS calculator (e.g., [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)) to communicate severity.
    - Include **Base Score**, **Attack Vector**, and **Impact Metrics**.
- Example:**CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')CVSS v3.1 Score: 9.8 (Critical)**

---

### **3. Vulnerability Description**

- Provide a brief overview of the vulnerability.
- Describe:
    - How the vulnerability arises.
    - Why it is a security risk.
- Example:**"The `/api/login` endpoint does not properly sanitize user input, allowing an attacker to inject SQL commands. This can lead to unauthorized access to sensitive user data."**

---

### **4. Proof of Concept (PoC)**

- Provide **clear, step-by-step instructions** for reproducing the vulnerability.
- Include:
    - Tools or commands used (e.g., `curl`, Burp Suite, browser steps).
    - Exploit payloads.
    - Screenshots, if applicable.
- Example:
    
    ```bash
    curl -X POST -d '{"username": "admin' OR '1'='1'; -- ", "password": "password"}' https://example.com/api/login
    ```
    
    - Expected Result: **Access to admin account.**

---

### **5. Impact**

- Clearly explain **what an attacker can achieve** by exploiting the vulnerability:
    - Unauthorized access.
    - Compromising sensitive data.
    - System shutdown or denial of service.
- Include **business implications** or maximum potential damage.
- Example:**"This vulnerability allows attackers to gain unauthorized access to the admin panel, exfiltrate sensitive customer data, and disrupt business operations by modifying configurations."**

---

### **6. Remediation**

- (Optional but helpful) Provide actionable recommendations to fix the issue.
- Example:
    - **Input Validation:** Use prepared statements or parameterized queries to prevent SQL Injection.
    - **Sanitization:** Implement proper input sanitization for all user-supplied data.
    - **Regular Updates:** Keep libraries and frameworks up-to-date to avoid outdated dependencies.

---

### **Example Report**

```
**Title:** SQL Injection in `/api/login` Allows Unauthorized Access to User Data
**CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**CVSS Score:** 9.8 (Critical)

**Description:**
The `/api/login` endpoint does not sanitize user inputs, allowing an attacker to inject SQL commands. Exploiting this vulnerability grants unauthorized access to sensitive user data, bypassing authentication.

**Proof of Concept (PoC):**
1. Intercept the login request using Burp Suite.
2. Modify the username parameter as follows: `admin' OR '1'='1'; -- `.
3. Forward the request.
4. Observe successful login to the admin account.

**Impact:**
- Unauthorized access to sensitive user data.
- Potential to modify or delete user records.
- Business impact includes loss of customer trust and regulatory penalties.

**Remediation:**
- Implement input validation and sanitization.
- Use prepared statements or parameterized queries for database interactions.
- Conduct regular security testing and code reviews.

**References:**
- CWE-89: [https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html)
- CVSS Calculator: [https://www.first.org/cvss/calculator/3.1](https://www.first.org/cvss/calculator/3.1)
```

Find below some examples of using CVSS 3.1 to communicate the severity of vulnerabilities.

|  |  |
| --- | --- |
| `Title:` | Cisco ASA Software IKEv1 and IKEv2 Buffer Overflow Vulnerability (CVE-2016-1287) |
| `CVSS 3.1 Score:` | 9.8 (Critical) |
| `Attack Vector:` | Network - The Cisco ASA device was exposed to the internet since it was used to facilitate connections to the internal network through VPN. |
| `Attack Complexity:` | Low - All the attacker has to do is execute the available exploit against the device |
| `Privileges Required:` | None - The attack could be executed from an unauthenticated/unauthorized perspective |
| `User Interaction:` | None - No user interaction is required |
| `Scope:` | Unchanged - Although you can use the exploited device as a pivot, you cannot affect other components by exploiting the buffer overflow vulnerability. |
| `Confidentiality:` | High - Successful exploitation of the vulnerability results in unrestricted access in the form of a reverse shell. Attackers have total control over what information is obtained. |
| `Integrity:` | High - Successful exploitation of the vulnerability results in unrestricted access in the form of a reverse shell. Attackers can modify all or critical data on the vulnerable component. |
| `Availability:` | High - Successful exploitation of the vulnerability results in unrestricted access in the form of a reverse shell. Attackers can deny the service to users by powering the device off |

|  |  |
| --- | --- |
| `Title:` | Stored XSS in an admin panel (Malicious Admin -> Admin) |
| `CVSS 3.1 Score:` | 5.5 (Medium) |
| `Attack Vector:` | Network - The attack can be mounted over the internet. |
| `Attack Complexity:` | Low - All the attacker (malicious admin) has to do is specify the XSS payload that is eventually stored in the database. |
| `Privileges Required:` | High - Only someone with admin-level privileges can access the admin panel. |
| `User Interaction:` | None - Other admins will be affected simply by browsing a specific (but regularly visited) page within the admin panel. |
| `Scope:` | Changed - Since the vulnerable component is the webserver and the impacted component is the browser |
| `Confidentiality:` | Low - Access to DOM was possible |
| `Integrity:` | Low - Through XSS, we can slightly affect the integrity of an application |
| `Availability:` | None - We cannot deny the service through XSS |

---

### **Why CWE & CVSS Matter?**

- **CWE**: Provides a standardized way to categorize vulnerabilities. It helps developers and security teams understand the root cause of issues.
- **CVSS**: Communicates the **severity** of vulnerabilities using a universally recognized scoring system.

**CVSS v3.1 Example for SQL Injection:**

- **Attack Vector:** Network (N)
- **Attack Complexity:** Low (L)
- **Privileges Required:** None (N)
- **User Interaction:** None (N)
- **Scope:** Unchanged (U)
- **Confidentiality, Integrity, Availability:** High (H), High (H), High (H)

---

# **Interacting with Organizations/BBP Hosts**

---

Suppose that you have submitted a bug report. How should you interact with the security/triage team after that?

- Well, to begin with, do not interact with them. Allow the security/triage team some time to process your report, validate your finding, and maybe ask questions. Some bug bounty programs/platforms include vendor response SLAs or response efficiency metrics, which can give you an idea of how long it can take for them to get back to a submission. Also, make sure that you do not spam the security/triage team within a short period of time.
- If the security/triage team does not get back to you in a reasonable amount of time, then if the submission was through a bug bounty platform, you can contact [Mediation](https://docs.hackerone.com/hackers/hacker-mediation.html).
- Once the security/triage team gets back to you, note the team member's username and tag them in any future communications since they will probably be dealing with your submission. Do not interact with the security/triage team through any unofficial communication channel (social media etc.)
- A professional bug report should be accompanied by professional communication. Remain calm and interact with the security/triage team as a security professional would.

During your interaction with the security/triage team, there could be disagreements about the severity of the bug or the bounty. A bug's impact and severity play a significant role during the bounty amount assignment. In the case of such a disagreement, proceed as follows.

- Explain your rationale for choosing this severity score and guide the security/triage team through each metric value you specified in the CVSS calculator. Eventually, you will come to an agreement.
- Go over the bug bounty program's policy and scope and ensure that your submission complies with both. Also, make sure that the bounty amount resembles the policy of the bug bounty program.
- If none of the above was fruitful, contact mediation or a similar platform service.

# Example Reports

[**Example 1: Reporting Stored XSS**](https://academy.hackthebox.com/module/161/section/1507)

[**Example 2: Reporting CSRF**](https://academy.hackthebox.com/module/161/section/1510)

[**Example 3: Reporting RCE**](https://academy.hackthebox.com/module/161/section/1511)