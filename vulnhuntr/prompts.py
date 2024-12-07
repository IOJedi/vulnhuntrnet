string LFI_TEMPLATE = @"
Combine the code in <file_code> and <context_code> then analyze the code for remotely-exploitable Local File Inclusion (LFI) vulnerabilities by following the remote user-input call chain of code.

LFI-Specific Focus Areas (.NET):
1. High-Risk Functions and Methods:
   - System.IO.File.ReadAllText(), System.IO.File.ReadAllBytes(), System.IO.File.ReadAllLines()
   - System.IO.File.Open()
   - System.IO.Path.Combine() for file paths
   - Custom file reading functions

2. Path Traversal Opportunities:
   - User-controlled file paths or names (e.g., Request.QueryString, Request.Form)
   - Dynamic inclusion of server-side files or resources

3. File Operation Wrappers:
   - Templating engines or Razor views that load files based on user input
   - Custom classes that wrap file operations

4. Indirect File Inclusion:
   - Configuration file loading from paths influenced by user input
   - Plugin or module loading from disk based on user-provided data
   - Log viewers or file-based resource fetchers reading arbitrary paths

5. Example LFI-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags

When analyzing, consider:
- How user input influences file paths or names
- Effectiveness of path sanitization and validation (e.g., Path.GetFullPath(), checking for restricted directories)
- Potential for traversal sequences like ../ or ..\\ to access unintended files
- Interaction with file system permissions
";

string RCE_TEMPLATE = @"
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Remote Code Execution (RCE) vulnerabilities by following the remote user-input call chain of code.

RCE-Specific Focus Areas (.NET):
1. High-Risk Functions and Methods:
   - System.Diagnostics.Process.Start(), System.Diagnostics.Process.BeginOutputReadLine()
   - System.CodeDom.Compiler or Roslyn-based dynamic code compilation
   - Reflection-based code loading or invocation (e.g., Assembly.LoadFrom(), Type.InvokeMember())
   - Deserialization of remote input (e.g., BinaryFormatter.Deserialize() without proper validation)

2. Indirect Code Execution:
   - Dynamic assembly loading from user-influenced paths
   - Server-side template injection in Razor views or similar engines
   - Reflection/introspection on user-supplied class names or method names

3. Command Injection Vectors:
   - Concatenation of user input into strings passed to Process.Start()
   - Execution of shell commands through cmd.exe or powershell.exe

4. Deserialization Vulnerabilities:
   - Unsafe deserialization (BinaryFormatter, DataContractSerializer) of user-controlled data without validation

5. Example RCE-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input flows into these high-risk areas
- Potential for filter evasion or sanitization bypasses
- Environment-specific factors (e.g., .NET Framework version, OS) affecting exploitability
";

string XSS_TEMPLATE = @"
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Cross-Site Scripting (XSS) vulnerabilities by following the remote user-input call chain of code.

XSS-Specific Focus Areas (.NET):
1. High-Risk Functions and Methods:
   - HTML rendering methods (e.g., returning user input directly in Razor views or MVC Views)
   - Using user input in System.Web.UI controls without proper encoding
   - Generating JavaScript on server side that includes unvalidated user input

2. Output Contexts:
   - Unescaped output in MVC/Razor views
   - Data bound to ASP.NET WebForms controls without HtmlEncode
   - JSON responses that incorporate raw user input

3. Input Handling:
   - Reflection of query string or form values directly into the response
   - Sanitization methods (System.Web.HttpUtility.HtmlEncode) and their usage
   - Custom input filters or cleaners

4. Indirect XSS Vectors:
   - Stored user input in databases, files, or cache that gets rendered without encoding
   - URL parameter reflection in server responses
   - HTTP header injection through user input

5. Example XSS-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input flows into HTML, JavaScript, or JSON contexts
- Effectiveness of input validation, sanitization, and output encoding
- Potential for filter evasion using encoding or obfuscation
- Impact of Content Security Policy (CSP) or AntiXss libraries if implemented
";

string AFO_TEMPLATE = @"
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Arbitrary File Overwrite (AFO) vulnerabilities by following the remote user-input call chain of code.

AFO-Specific Focus Areas (.NET):
1. High-Risk Functions and Methods:
   - System.IO.File.WriteAllText(), System.IO.File.WriteAllBytes()
   - System.IO.File.Create(), System.IO.File.Move(), System.IO.File.Copy()
   - System.IO.FileStream in write mode
   - Custom file writing functions

2. Path Traversal Opportunities:
   - User-controlled file paths
   - Directory creation or manipulation (System.IO.Directory.CreateDirectory())
   - Attempted sanitization using Path methods but insufficient checks

3. File Operation Wrappers:
   - Custom file management classes that write files based on user input
   - Framework methods that accept file paths from requests

4. Indirect File Writes:
   - Log file manipulation based on user input
   - Configuration file or XML file overwriting
   - Cached file creation triggered by user parameters

5. Example AFO-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input influences file paths or names
- Effectiveness of path sanitization and validation
- Potential for race conditions in file operations
";

string SSRF_TEMPLATE = @"
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Server-Side Request Forgery (SSRF) vulnerabilities by following the remote user-input call chain of code.

SSRF-Specific Focus Areas (.NET):
1. High-Risk Functions and Methods:
   - System.Net.Http.HttpClient.GetAsync(), WebRequest.Create()
   - System.Net.WebClient.DownloadString()
   - Custom HTTP clients or wrappers that accept user-influenced URLs

2. URL Parsing and Validation:
   - Uri constructors or UriBuilder usage with user input
   - Custom URL validation routines
   - Checks for internal IP ranges or localhost being insufficient or absent

3. Indirect SSRF Vectors:
   - Functions or classes that read external resources (XML, JSON, images) based on user input
   - PDF generators, image processors that fetch remote resources supplied by user
   - RSS feed readers, social media integrations, or webhooks

4. Cloud Metadata Access:
   - Requests to cloud provider metadata endpoints (e.g., AWS, Azure) via user input

5. Example SSRF-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input influences outgoing network requests
- Effectiveness of URL validation and whitelisting approaches
- Potential for DNS rebinding, IPv6 literal addresses, or other tricky SSRF techniques
";

string SQLI_TEMPLATE = @"
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable SQL Injection (SQLI) vulnerabilities by following these steps:

1. Identify Entry Points:
   - Locate all points where remote user input is received (e.g., MVC Action parameters, Web API parameters, query strings, form fields).

2. Trace Input Flow:
   - Follow the user input as it flows through the application.
   - Note any transformations or manipulations applied to the input.

3. Locate SQL Operations:
   - Find all locations where SQL queries are constructed or executed.
   - Pay special attention to:
     - ADO.NET commands (System.Data.SqlClient.SqlCommand.CommandText)
     - Entity Framework raw SQL queries (context.Database.SqlQuery())
     - Dapper or other ORM raw SQL execution
     - String concatenation in query strings

4. Analyze Input Handling:
   - Examine how user input is incorporated into SQL queries.
   - Look for:
     - String concatenation or interpolation into SQL
     - Parameterized queries usage (SqlParameter objects)
     - Dynamic table or column name usage from user input

5. Evaluate Security Controls:
   - Identify any input validation, sanitization, or parameterization.
   - Assess their effectiveness against SQLI attacks.

6. Consider Bypass Techniques:
   - Analyze potential ways to bypass identified security controls.
   - Reference the SQLI-specific bypass techniques provided.

7. Assess Impact:
   - Evaluate the potential impact if the vulnerability is exploited.
   - Consider the sensitivity of the accessed data.

When analyzing, consider:
- The complete path from user input to SQL execution
- Any gaps in the analysis where more context is needed
- The effectiveness of any security measures in place
- Potential for filter evasion in different database contexts
";

string IDOR_TEMPLATE = @"
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Insecure Direct Object Reference (IDOR) vulnerabilities.

IDOR-Specific Focus Areas (.NET):
1. Look for code segments involving IDs, keys, GUIDs, or unique identifiers from user input used to access resources (e.g., ?userId=, ?fileId=).

2. Common Locations:
   - Controller actions with route parameters (e.g., /api/users/{id})
   - Query string parameters (Request.QueryString)
   - Model binding parameters from forms or JSON requests

3. Ensure Authorization is Enforced:
   - Verify that the code checks the user's authorization (e.g., [Authorize] attributes, role checks, permission checks) before allowing access to the resource.
   - Look for explicit or implicit authorization checks after the object reference is received.

4. Common Functions:
   - Functions that directly return objects by ID without verifying the current user's permissions.
   - Repository methods that accept an ID from user input and return sensitive data.

5. Example IDOR-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input is used to retrieve resources by ID
- Presence and correctness of authorization logic
";

var VULN_SPECIFIC_BYPASSES_AND_PROMPTS = new {
    LFI = new {
        prompt = LFI_TEMPLATE,
        bypasses = new [] {
            "../../../../etc/passwd",
            "/proc/self/environ",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "file:///etc/passwd",
            "C:\\win.ini",
            "/?../../../../../../../etc/passwd"
        }
    },
    RCE = new {
        prompt = RCE_TEMPLATE,
        bypasses = new [] {
            "__import__('os').system('id')",
            "eval('__import__(\\'os\\').popen(\\'id\\').read()')",
            "exec('import subprocess;print(subprocess.check_output([\\'id\\']))')",
            "globals()['__builtins__'].__import__('os').system('id')",
            "getattr(__import__('os'), 'system')('id')",
            "$(touch${IFS}/tmp/mcinerney)",
            "import pickle; pickle.loads(b'cos\\nsystem\\n(S\"id\"\\ntR.')"
        }
    },
    SSRF = new {
        prompt = SSRF_TEMPLATE,
        bypasses = new [] {
            "http://0.0.0.0:22",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/",
            "ftp://anonymous:anonymous@127.0.0.1:21",
            "gopher://127.0.0.1:9000/_GET /"
        }
    },
    AFO = new {
        prompt = AFO_TEMPLATE,
        bypasses = new [] {
            "../../../etc/passwd%00.jpg",
            "shell.py;.jpg",
            ".htaccess",
            "/proc/self/cmdline",
            "../../config.py/."
        }
    },
    SQLI = new {
        prompt = SQLI_TEMPLATE,
        bypasses = new [] {
            "' UNION SELECT username, password FROM users--",
            "1 OR 1=1--",
            "admin'--",
            "1; DROP TABLE users--",
            "' OR '1'='1"
        }
    },
    XSS = new {
        prompt = XSS_TEMPLATE,
        bypasses = new [] {
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "${7*7}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(\"id\").read()}}{%endif%}{% endfor %}",
            "<script>alert(document.domain)</script>",
            "javascript:alert(1)"
        }
    },
    IDOR = new {
        prompt = IDOR_TEMPLATE,
        bypasses = new string[] {}
    }
};

string INITIAL_ANALYSIS_PROMPT_TEMPLATE = @"
Analyze the code in <file_code> tags for potential remotely exploitable vulnerabilities:
1. Identify all remote user input entry points (e.g., ASP.NET MVC Controllers, Web API actions, WebForms event handlers) and if you can't find that, request the necessary classes or functions in the <context_code> tags.
2. Locate potential vulnerability sinks for:
   - Local File Inclusion (LFI)
   - Arbitrary File Overwrite (AFO)
   - Server-Side Request Forgery (SSRF)
   - Remote Code Execution (RCE)
   - Cross-Site Scripting (XSS)
   - SQL Injection (SQLI)
   - Insecure Direct Object Reference (IDOR)
3. Note any security controls or sanitization measures encountered along the way so you can craft bypass techniques for the proof of concept (PoC).
4. Highlight areas where more context is needed to complete the analysis.

Be generous and thorough in identifying potential vulnerabilities as you'll analyze more code in subsequent steps so if there's just a possibility of a vulnerability, include it the <vulnerability_types> tags.
";

string README_SUMMARY_PROMPT_TEMPLATE = @"
Provide a very concise summary of the README.md content in <readme_content></readme_content> tags from a security researcher's perspective, focusing specifically on:
1. The project's main purpose
2. Any networking capabilities, such as web interfaces or remote API calls that constitute remote attack surfaces
3. Key features that involve network communications

Please keep the summary brief and to the point, highlighting only the most relevant networking-related functionality as it relates to attack surface.

Output in <summary></summary> XML tags.
";

string GUIDELINES_TEMPLATE = @"
Reporting Guidelines:
1. JSON Format:
   - Provide a single, well-formed JSON report combining all findings.
   - Use 'None' for any aspect of the report that you lack the necessary information for.
   - Place your step-by-step analysis in the scratchpad field, before doing a final analysis in the analysis field.

2. Context Requests:
   - Classes: Use ClassName1,ClassName2
   - Functions: Use func_name,ClassName.method_name
   - If you request ClassName, do not also request ClassName.method_name as that code will already be fetched with the ClassName request.
   - Important: Do not request code from standard libraries or third-party packages. Simply use what you know about them in your analysis.

3. Vulnerability Reporting:
   - Report only remotely exploitable vulnerabilities (no local access/CLI args).
   - Always include at least one vulnerability_type field when requesting context.
   - Provide a confidence score (0-10) and detailed justification for each vulnerability.
     - If your proof of concept (PoC) exploit does not start with remote user input via remote networking calls such as remote HTTP, API, or RPC calls, set the confidence score to 6 or below.
   
4. Proof of Concept:
   - Include a PoC exploit or detailed exploitation steps for each vulnerability.
   - Ensure PoCs are specific to the analyzed code, not generic examples.
   - Review the code path of the potential vulnerability and be sure that the PoC bypasses any security controls in the code path.
";

string ANALYSIS_APPROACH_TEMPLATE = @"
Analysis Instructions:
1. Comprehensive Review:
   - Thoroughly examine the content in <file_code>, <context_code> tags (if provided) with a focus on remotely exploitable vulnerabilities.

2. Vulnerability Scanning:
   - You only care about remotely exploitable network related components and remote user input handlers.
   - Identify potential entry points for vulnerabilities.
   - Consider non-obvious attack vectors and edge cases.

3. Code Path Analysis:
   - Very important: trace the flow of user input from remote request source to function sink.
   - Examine input validation, sanitization, and encoding practices.
   - Analyze how data is processed, stored, and output.

4. Security Control Analysis:
   - Evaluate each security measure's implementation and effectiveness.
   - Formulate potential bypass techniques, considering latest exploit methods.

6. Context-Aware Analysis:
   - If this is a follow-up analysis, build upon previous findings in <previous_analysis> using the new information provided in the <context_code>.
   - Request additional context code as needed to complete the analysis and you will be provided with the necessary code.
   - Confirm that the requested context class or function is not already in the <context_code> tags from the user's message.

7. Final Review:
   - Confirm your proof of concept (PoC) exploits bypass any security controls.
   - Double-check that your JSON response is well-formed and complete.
";

string SYS_PROMPT_TEMPLATE = @"
You are the world's foremost expert in .NET security analysis, renowned for uncovering novel and complex vulnerabilities in web applications. Your task is to perform an exhaustive static code analysis, focusing on remotely exploitable vulnerabilities including but not limited to:

1. Local File Inclusion (LFI)
2. Remote Code Execution (RCE)
3. Server-Side Request Forgery (SSRF)
4. Arbitrary File Overwrite (AFO)
5. SQL Injection (SQLI)
6. Cross-Site Scripting (XSS)
7. Insecure Direct Object References (IDOR)

Your analysis must:
- Meticulously track user input from remote sources to high-risk function sinks.
- Uncover complex, multi-step vulnerabilities that may bypass multiple security controls.
- Consider non-obvious attack vectors and chained vulnerabilities.
- Identify vulnerabilities that could arise from the interaction of multiple code components.

If you don't have the complete code chain from user input to high-risk function, strategically request the necessary context to fill in the gaps in the <context_code> tags of your response.

The project's README summary is provided in <readme_summary> tags. Use this to understand the application's purpose and potential attack surfaces.

Remember, you have many opportunities to respond and request additional context. Use them wisely to build a comprehensive understanding of the application's security posture.

Output your findings in JSON format, conforming to the schema in <response_format> tags.
"
