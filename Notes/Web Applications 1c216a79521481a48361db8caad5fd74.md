# Web Applications

![image.png](image%203.png)

### Web App Distribution

There are many open-source web applications used by organizations worldwide that can be customized to meet each organization's needs. Some common open source web applications include:

- [WordPress](https://wordpress.com/)
- [OpenCart](https://www.opencart.com/)
- [Joomla](https://www.joomla.org/)

There are also proprietary 'closed source' web applications, which are usually developed by a certain organization and then sold to another organization or used by organizations through a subscription plan model. Some common closed source web applications include:

- [Wix](https://www.wix.com/)
- [Shopify](https://www.shopify.com/)
- [DotNetNuke](https://www.dnnsoftware.com/)

### Security Risks of WebApps

One of the most common procedures is to start by reviewing a web application's front end components, such as `HTML`, `CSS` and `JavaScript` (also known as the front end trinity), and attempt to find vulnerabilities such as [Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure) and [Cross-Site Scripting (XSS)](https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)). 

### Attacking WebApps

| **Flaw** | **Real-world Scenario** |
| --- | --- |
| [SQL injection](https://owasp.org/www-community/attacks/SQL_Injection) | Obtaining Active Directory usernames and performing a password spraying attack against a VPN or email portal. |
| [File Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion) | Reading source code to find a hidden page or directory which exposes additional functionality that can be used to gain remote code execution. |
| [Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) | A web application that allows a user to upload a profile picture that allows any file type to be uploaded (not just images). This can be leveraged to gain full control of the web application server by uploading malicious code. |
| [Insecure Direct Object Referencing (IDOR)](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | When combined with a flaw such as broken access control, this can often be used to access another user's files or functionality. An example would be editing your user profile browsing to a page such as /user/701/edit-profile. If we can change the `701` to `702`, we may edit another user's profile! |
| [Broken Access Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control) | Another example is an application that allows a user to register a new account. If the account registration functionality is designed poorly, a user may perform privilege escalation when registering. Consider the `POST` request when registering a new user, which submits the data `username=bjones&password=Welcome1&email=bjones@inlanefreight.local&roleid=3`. What if we can manipulate the `roleid` parameter and change it to `0` or `1`. We have seen real-world applications where this was the case, and it was possible to quickly register an admin user and access many unintended features of the web application. |

## Front End

### **URL Encoding**

An important concept to learn in HTML is [URL Encoding](https://en.wikipedia.org/wiki/Percent-encoding), or percent-encoding. For a browser to properly display a page's contents, it has to know the charset in use. In URLs, for example, browsers can only use [ASCII](https://en.wikipedia.org/wiki/ASCII) encoding, which only allows alphanumerical characters and certain special characters. Therefore, all other characters outside of the ASCII character-set have to be encoded within a URL. URL encoding replaces unsafe ASCII characters with a `%` symbol followed by two hexadecimal digits.

For example, the single-quote character '`'`' is encoded to '`%27`', which can be understood by browsers as a single-quote. URLs cannot have spaces in them and will replace a space with either a `+` (plus sign) or `%20`. Some common character encodings are:

| **Character** | **Encoding** |
| --- | --- |
| space | %20 |
| ! | %21 |
| " | %22 |
| # | %23 |
| $ | %24 |
| % | %25 |
| & | %26 |
| ' | %27 |
| ( | %28 |
| ) | %29 |

A full character encoding table can be seen [here](https://www.w3schools.com/tags/ref_urlencode.ASP).

[HTTP response codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status):

| **Code** | **Description** |
| --- | --- |
| **Successful responses** |  |
| `200 OK` | The request has succeeded |
| **Redirection messages** |  |
| `301 Moved Permanently` | The URL of the requested resource has been changed permanently |
| `302 Found` | The URL of the requested resource has been changed temporarily |
| **Client error responses** |  |
| `400 Bad Request` | The server could not understand the request due to invalid syntax |
| `401 Unauthorized` | Unauthenticated attempt to access page |
| `403 Forbidden` | The client does not have access rights to the content |
| `404 Not Found` | The server can not find the requested resource |
| `405 Method Not Allowed` | The request method is known by the server but has been disabled and cannot be used |
| `408 Request Timeout` | This response is sent on an idle connection by some servers, even without any previous request by the client |
| **Server error responses** |  |
| `500 Internal Server Error` | The server has encountered a situation it doesn't know how to handle |
| `502 Bad Gateway` | The server, while working as a gateway to get a response needed to handle the request, received an invalid response |
| `504 Gateway Timeout` | The server is acting as a gateway and cannot get a response in time |