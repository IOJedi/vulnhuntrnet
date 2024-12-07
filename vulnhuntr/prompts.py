LFI_TEMPLATE = """
Combine the code in <file_code> and <context_code> then analyze the code for remotely-exploitable Local File Inclusion (LFI) vulnerabilities by following the remote user-input call chain of code.

LFI-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - System.IO.File.ReadAllText(), System.IO.File.ReadAllBytes(), System.IO.File.ReadAllLines()
   - System.IO.File.Open()
   - System.IO.Path.Combine() for file paths
   - Custom file reading functions

2. Path Traversal Opportunities:
   - User-controlled file paths or names
   - Dynamic inclusion of files or modules

3. File Operation Wrappers:
   - Templating engines or view engines that load files based on user input
   - Custom file management classes

4. Indirect File Inclusion:
   - Configuration file parsing
   - Plugin or extension loading systems
   - Log file viewers

5. Example LFI-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags

When analyzing, consider:
- How user input influences file paths or names
- Effectiveness of path sanitization and validation
- Potential for directory traversal sequences
- Interaction with file system access controls
"""

RCE_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Remote Code Execution (RCE) vulnerabilities by following the remote user-input call chain of code.

RCE-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - System.Diagnostics.Process.Start()
   - Reflection-based dynamic invocation (e.g., Assembly.LoadFrom(), Type.InvokeMember())
   - Unsafe deserialization (e.g., BinaryFormatter.Deserialize())

2. Indirect Code Execution:
   - Dynamic code compilation or evaluation mechanisms
   - Server-side template injection
   - Reflection/introspection misuse

3. Command Injection Vectors:
   - Shell command composition with user input passed to Process.Start()

4. Deserialization Vulnerabilities:
   - Unsafe deserialization of user-controlled data

5. Example RCE-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input flows into these high-risk areas
- Potential for filter evasion or sanitization bypasses
- .NET framework and OS-specific factors affecting exploitability
"""

XSS_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Cross-Site Scripting (XSS) vulnerabilities by following the remote user-input call chain of code.

XSS-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - Razor views or ASP.NET pages that directly render user input without encoding
   - System.Web.UI controls that emit HTML
   - JavaScript generation or manipulation that includes user input

2. Output Contexts:
   - Unescaped output in HTML views
   - Attribute value insertion without encoding
   - JavaScript code or JSON data embedding

3. Input Handling:
   - User input reflection in responses
   - HtmlEncode or AntiXSS usage
   - Custom input filters or cleaners

4. Indirect XSS Vectors:
   - Stored user input (e.g., in databases, files)
   - URL parameter reflection
   - HTTP header injection points

5. Example XSS-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input flows into HTML, JavaScript, or JSON contexts
- Effectiveness of input validation, sanitization, and output encoding
- Potential for filter evasion or encoding tricks
- Impact of Content Security Policy (CSP) if implemented
"""

AFO_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Arbitrary File Overwrite (AFO) vulnerabilities by following the remote user-input call chain of code.

AFO-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - System.IO.File.WriteAllText(), System.IO.File.WriteAllBytes(), System.IO.File.Create()
   - System.IO.File.Move(), System.IO.File.Copy()
   - Custom file writing functions

2. Path Traversal Opportunities:
   - User-controlled file paths
   - Directory creation or manipulation

3. File Operation Wrappers:
   - Custom file management classes
   - Framework methods that accept file paths influenced by user input

4. Indirect File Writes:
   - Log file manipulation
   - Configuration file updates
   - Cache file creation

5. Example AFO-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input influences file paths or names
- Effectiveness of path sanitization and validation
- Potential for race conditions in file operations
"""

SSRF_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Server-Side Request Forgery (SSRF) vulnerabilities by following the remote user-input call chain of code.

SSRF-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - System.Net.Http.HttpClient.GetAsync(), WebRequest.Create()
   - System.Net.WebClient.DownloadString()
   - Custom HTTP clients

2. URL Parsing and Validation:
   - Uri parsing and UriBuilder usage
   - Custom URL validation routines

3. Indirect SSRF Vectors:
   - File inclusion functions reading from URLs
   - XML parsers with external entity processing
   - PDF generators, image processors using remote resources

4. Cloud Metadata Access:
   - Requests to cloud provider metadata URLs

5. Example SSRF-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input influences outgoing network requests
- Effectiveness of URL validation and whitelisting approaches
- Potential for DNS rebinding or other SSRF tricks
"""

SQLI_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable SQL Injection (SQLI) vulnerabilities by following these steps:

1. Identify Entry Points:
   - Locate all points where remote user input is received (e.g., MVC action parameters, Web API parameters).

2. Trace Input Flow:
   - Follow the user input as it flows through the application.

3. Locate SQL Operations:
   - ADO.NET commands (System.Data.SqlClient.SqlCommand.CommandText)
   - Entity Framework raw SQL (context.Database.ExecuteSqlCommand())
   - Dapper or other ORM raw SQL execution

4. Analyze Input Handling:
   - Look for string concatenation or interpolation of user input into queries
   - Check if parameterized queries (SqlParameter) are used
   - Inspect dynamic table or column name usage from user input

5. Evaluate Security Controls:
   - Identify any input validation, sanitization, or escaping mechanisms
   - Assess their effectiveness

6. Consider Bypass Techniques:
   - Potential ways to bypass identified security controls

7. Assess Impact:
   - Potential impact if exploited
   - Sensitivity of accessed data

When analyzing, consider:
- The complete path from user input to SQL execution
- Any gaps where more context is needed
- Effectiveness of security measures
- Potential filter evasion
"""

IDOR_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Insecure Direct Object Reference (IDOR) vulnerabilities.

IDOR-Specific Focus Areas:
1. Look for IDs or unique identifiers controlled by the user
2. Common Locations:
   - MVC routes (e.g., /users/{id})
   - Query parameters, form fields

3. Ensure Authorization is Enforced:
   - Verify that authorization checks exist (e.g., [Authorize] attributes)
   - Look for checks after the object reference is received

4. Common Functions:
   - Direct object returns by ID without permission checks
   - Repository or service methods that return resources by ID without verifying permissions

5. Example IDOR-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input is used to retrieve resources
- Presence and correctness of authorization logic
"""
