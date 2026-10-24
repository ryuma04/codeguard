"""Step 3: language-agnostic rule layer.

Each rule: (category, kind, weight, regex, reason). Rules run line by line so
every hit carries a line number for `vulnerable_lines`.
Pattern ideas adapted (not copied) from DataDog GuardDog (Apache-2.0),
Gitleaks (MIT) and Yelp detect-secrets (Apache-2.0).
"""
import re
from .findings import Finding, CAPABILITY as C, THREAT as T

_HOME = r"(~|\$HOME|\$\{HOME\}|/home/[\w.\-]+|/root|%USERPROFILE%|C:\\\\Users\\\\[\w.\-]+)"
_ROOTISH = r"(/|/\*|~|~/|~/\*|\$HOME/?\*?|/(etc|usr|var|home|boot|bin|sbin|lib|opt|srv|root)/?\*?)(?=[\s'\"`;)|&]|$)"
# An actual env-var read: the accessor must be a whole token followed by a real lookup
# (os.environ["X"], os.environ.get("X"), os.getenv("X"), process.env.X, $_ENV['X']), so words
# like "environment_secret_exposure" in a YAML label or a comment do not count.
_ENV_READ = r"(\benviron\b|\bgetenv\b|\bprocess\.env\b|\$ENV\b|\$_ENV\b)\s*(\.get\s*\(|\[|\(|\.|\{)\s*['\"]?"

RULES = [
    # ---------------- secret_access ----------------
    ("secret_access", T, 0.80, _HOME + r"?/?\.ssh/(?!authorized_keys|[\w*.-]*\.pub\b)(id_[\w]+|known_hosts|config)?", "accesses SSH keys/config"),
    ("secret_access", T, 0.80, r"\.aws/credentials|\.aws/config|\.docker/config\.json|\.kube/config|\.netrc\b|\.git-credentials|\.npmrc|\.pypirc|\.gnupg|gcloud/(credentials|application_default)", "accesses a credential store file"),
    ("secret_access", T, 0.75, r"/etc/(shadow|gshadow|master\.passwd)\b", "reads system password/sudo files"),
    ("secret_access", T, 0.55, r"(open|read|cat|readFile\w*|file_get_contents|Get-Content|type)\W{1,4}[^\n]*?(^|[\s'\"/\\])\.env(\.\w+)?\b", "reads a .env secrets file"),
    ("secret_access", T, 0.70, r"(?-i:Login Data|[/\\]Cookies\b|key[34]\.db|logins\.json|Local State|login\.keychain|\.kdbx|wallet\.dat|Local Storage/leveldb)", "touches browser/wallet credential store"),
    ("secret_access", T, 0.60, r"-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{36}\b|\bxox[bpas]-[A-Za-z0-9-]{10,}|\bsk_live_[A-Za-z0-9]{20,}", "handles a private key / live API token"),
    ("secret_access", T, 0.55, _ENV_READ + r"(AWS_SECRET\w*|AWS_ACCESS_KEY\w*|\w*PRIVATE_KEY|\w*CLIENT_SECRET)", "reads a cloud/private secret from the environment"),
    ("secret_access", T, 0.45, _ENV_READ + r"(\w*API_KEY|\w*SECRET\w*|\w*TOKEN|\w*PASSWORD|\w*PASSWD|DATABASE_URL)", "reads a secret environment variable"),
    ("secret_access", T, 0.65, r"(print|console\.log|echo|logger\.\w+|puts|Write-(Host|Output))\W[^\n]*(\benviron\s*\[|\bgetenv\s*\(|\bprocess\.env\.|\$\w*(TOKEN|SECRET|PASSWORD|API_KEY)\b)", "prints secrets from the environment"),
    ("secret_access", T, 0.55, r"dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)|json\.dumps\(\s*(dict\()?os\.environ|JSON\.stringify\(\s*process(\.env|\[\s*['\"]env['\"]\s*\])\s*\)|(push|send|write|post)\([^\n]*\bprocess\.env\b(?!\.)|\bprintenv\b\s*(\||>|$)|(^|[;&(]\s*|\|\s*|\$\(\s*)env\s*\|(?!\|)", "dumps the whole environment"),
    ("secret_access", C, 0.20, r"os\.environ|os\.getenv|process\.env|\bgetenv\(", "reads environment variables"),
    ("secret_access", T, 0.50, r"(security\s+find-generic-password|secret-tool\s+lookup|keyring\.get_password|mimikatz|lsass)", "queries OS credential manager"),

    # ---------------- data_exfiltration ----------------
    ("data_exfiltration", T, 0.75, r"(discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|api\.telegram\.org/bot|webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|pastebin\.com/api|transfer\.sh|interact\.sh|oastify\.com|burpcollaborator|0x0\.st|file\.io)", "sends data to a known exfiltration endpoint"),
    ("data_exfiltration", T, 0.65, r"\bcurl\b[^\n]*(\s-d\s*@|--data(-binary|-raw)?\s*@|\s-F\s*['\"]?\w+=@|--upload-file|\s-T\s)", "uploads a local file with curl"),
    ("data_exfiltration", T, 0.60, r"\bwget\b[^\n]*--post-(file|data)", "uploads data with wget"),
    ("data_exfiltration", T, 0.60, r"\b(nc|ncat|netcat|socat)\b[^\n]*<\s*\S+|\b(tar|zip)\b[^\n]*\|\s*(nc|ncat|curl|ssh)\b", "streams local files over the network"),
    ("data_exfiltration", T, 0.60, r"(^|[;&|(]\s*)(nslookup|dig|host)\s+\S*(\$\(|`)|\.resolve\([^\n]*(b64|base64|hex)", "encodes data into DNS lookups"),
    ("data_exfiltration", T, 0.55, r"\b(scp|rsync)\b[^\n]*" + _HOME + r"?/?\.(ssh|aws|gnupg)", "copies credential folders to a remote host"),
    ("data_exfiltration", T, 0.60, r"(post|put|patch|request|send|connect)\w*\([^\n]*['\"](https?://)?(?!(10|127|0|192\.168|172\.(1[6-9]|2\d|3[01])|169\.254)\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "sends data to a hard-coded public IP"),
    # Markdown image pointing at a tracking/collector endpoint with data in the query: rendering it leaks the data.
    ("data_exfiltration", T, 0.60, r"!\[[^\]]*\]\(\s*https?://[^)\s]*?(pixel|beacon|track(ing|er)?|collect(or)?|telemetry)[^)\s]*\?[^)\s]*\w=[^)\s]+\)", "markdown image beacon sends data to a tracking endpoint"),
    ("dependency_risk", T, 0.75, r"\bimport\(\s*['\"`]https?://", "imports and runs a module from a remote URL"),
    ("data_exfiltration", T, 0.35, r"os\.(hostname|userInfo|networkInterfaces)\(\)|getpass\.getuser\(\)|socket\.gethostname\(\)|platform\.node\(\)|os\.getlogin\(\)|\$env:(COMPUTERNAME|USERNAME)", "collects host fingerprint"),
    ("data_exfiltration", C, 0.20, r"requests\.(post|put|patch)|urllib\.request|urlopen\(|http\.client|httpx\.|aiohttp|\bfetch\(|axios|XMLHttpRequest|https?\.(request|get)\(|require\(['\"]https?['\"]\)|net\.connect|new\s+WebSocket|\bcurl\b|\bwget\b|Invoke-(WebRequest|RestMethod)|socket\.(socket|create_connection)|\.sendall\(|smtplib|ftplib|curl_exec|fsockopen|\b(nc|ncat|netcat|socat|telnet|scp|rsync|ssh)\s+\S", "makes an outbound network call"),

    # ---------------- destructive_command ----------------
    ("destructive_command", T, 0.92, r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*\s+|--recursive\s+|-[a-zA-Z]*f[a-zA-Z]*\s+)+(-[a-zA-Z]+\s+)*(--no-preserve-root\s+)?['\"]?" + _ROOTISH, "recursively deletes root/home"),
    ("destructive_command", T, 0.90, r"--no-preserve-root", "disables rm root protection"),
    ("destructive_command", T, 0.75, r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*\s+|--recursive\s+)(-[a-zA-Z]+\s+)*['\"]?/(etc|usr|boot|bin|sbin|lib|lib64|opt|srv|root|home|var/lib|var/www|var/backups|mnt|data)/", "recursively deletes a system/data directory"),
    ("destructive_command", T, 0.90, r"\bmkfs(\.\w+)?\b|\bdd\b[^\n]*of=/dev/(sd|hd|nvme|xvd|disk|mmcblk)|\bwipefs\b|\bshred\b[^\n]*(/dev/|-u)|>\s*/dev/(sd[a-z]|nvme\d|disk\d)", "overwrites or formats a disk"),
    ("destructive_command", T, 0.85, r"\bformat\s+[a-zA-Z]:|\bdel\s+/[sfq][^\n]*[a-zA-Z]:\\|\brd\s+/s\s+/q\s+[a-zA-Z]:\\|Remove-Item[^\n]*-Recurse[^\n]*(-Force)?[^\n]*([a-zA-Z]:\\|\$env:USERPROFILE|~)", "deletes a Windows drive/profile"),
    ("destructive_command", T, 0.80, r"\bchmod\s+-R\s+[0-7]{3,4}\s+/((etc|usr|bin|sbin|boot|lib|lib64|var|root|home)/?)?(\s|$)|\bchown\s+-R\s+\S+\s+/((etc|usr|bin|sbin|boot|lib|var|root|home)/?)?(\s|$)", "recursively changes permissions on / or a system directory"),
    # `DROP TABLE IF EXISTS tmp_x` on a temp/staging table is the idempotent-migration idiom, not destruction.
    ("destructive_command", T, 0.80, r"\bDROP\s+(TABLE|DATABASE|SCHEMA|USER)\b(?!\s+IF\s+EXISTS\s+[\w.\"`\[\]]*?(te?mp|staging|scratch|_old\b|backup_))|\bTRUNCATE\s+(TABLE\s+)?\w+", "drops or truncates database objects"),
    ("destructive_command", T, 0.70, r"\bgit\s+push\s+[^\n]*(--force|-f)\b[^\n]*(main|master)|\bgit\s+(clean\s+-[a-z]*f[a-z]*d|reset\s+--hard\s+HEAD~\d{2,})", "rewrites/destroys git history"),
    ("destructive_command", T, 0.75, r"\bkill\s+-9\s+-1\b|\bkillall5\b|\bpkill\s+-9\s+-u\s+root|\b(shutdown|halt|poweroff|reboot)\b(\s+-[a-zA-Z]+|\s+now)?\s*$|init\s+0\b", "kills all processes / shuts the machine down"),
    # Only from / , home or a top-level system dir: `find /srv/app/backups -name '*.bak' -mtime +30 -delete` is retention cleanup.
    ("destructive_command", T, 0.65, r"\bfind\s+['\"]?(/|~/?|\$HOME/?|/(etc|usr|var|home|boot|bin|sbin|lib|opt|srv|root)/?)['\"]?\s[^\n]*(-delete|-exec\s+rm)", "mass-deletes files with find"),
    ("destructive_command", T, 0.90, r"\b(rmSync|rmdirSync|rimraf(\.sync)?|removeSync|remove|rm|rmdir|emptyDir(Sync)?)\(\s*['\"`](/|~|~/|[A-Za-z]:\\\\?|/(etc|usr|home|root|var|boot|bin|lib))['\"`]\s*[,)]", "recursively deletes root/home from code"),
    ("destructive_command", T, 0.70, r"\b(aws\s+s3\s+rb|aws\s+s3\s+rm[^\n]*--recursive|gsutil\s+(-m\s+)?rm\s+-r|kubectl\s+delete\s+(ns|namespace|--all)|terraform\s+destroy[^\n]*-auto-approve)", "deletes cloud resources"),
    ("destructive_command", T, 0.75, r"\b(FLUSHALL|FLUSHDB)\b|dropDatabase\(\)|\.drop\(\)", "wipes a datastore"),
    ("destructive_command", C, 0.30, r"\brm\s+-[a-zA-Z]*[rf]|shutil\.rmtree|os\.(remove|unlink|rmdir)|fs\.(rmSync|rmdirSync|unlinkSync|rm)\(|rimraf|Remove-Item|\bunlink\(", "deletes files"),

    # ---------------- persistence_or_privesc ----------------
    ("persistence_or_privesc", T, 0.75, r"\bcrontab\b(?!\s+-l\b)|/etc/cron(tab|\.d|\.daily|\.hourly)|/var/spool/cron|@reboot", "installs a cron job"),
    ("persistence_or_privesc", T, 0.65, r"(>>?|write|appendFile\w*|tee\s+-a|open\()[^\n]*" + r"(\.bashrc|\.bash_profile|\.profile|\.zshrc|\.zprofile|/etc/profile|/etc/rc\.local|/etc/init\.d|\.config/autostart)", "modifies a shell/autostart file"),
    ("persistence_or_privesc", T, 0.55, r"\.bashrc|\.bash_profile|\.zshrc|/etc/rc\.local|/etc/init\.d/|\.config/autostart|LaunchAgents|LaunchDaemons", "references an autostart location"),
    ("persistence_or_privesc", T, 0.70, r"systemctl\s+(enable|daemon-reload)|/etc/systemd/system/|\.service\b[^\n]*(ExecStart|>)", "creates/enables a system service"),
    ("persistence_or_privesc", T, 0.75, r"CurrentVersion\\\\?Run|\bschtasks\b[^\n]*/create|New-ScheduledTask|Register-ScheduledTask|HKLM\\\\|HKCU\\\\[^\n]*Run", "Windows run key / scheduled task"),
    ("persistence_or_privesc", T, 0.85, r"(>>|tee\s+-a|appendFile\w*|write)[^\n]*authorized_keys", "adds an SSH authorized key"),
    ("persistence_or_privesc", T, 0.85, r"NOPASSWD|/etc/sudoers|visudo|\busermod\s+-aG\s+(sudo|wheel|admin|docker|root)\b|\buseradd\b[^\n]*(-o\s+-u\s*0|-G\s*(sudo|wheel|root))", "grants sudo/root privileges"),
    ("persistence_or_privesc", T, 0.80, r"\bchmod\s+([ugoa]*\+[a-z]*s|[24][0-7]{3})\b|os\.chmod\([^\n]*0o?[24][0-7]{3}|setuid\(\s*0\s*\)|setgid\(\s*0\s*\)|os\.setuid", "sets setuid/setgid bits or uid 0"),
    ("persistence_or_privesc", T, 0.75, r"privileged:\s*true|--privileged\b|-v\s+/:/\w+|hostPID:\s*true|hostNetwork:\s*true|SYS_ADMIN|allowPrivilegeEscalation:\s*true|/var/run/docker\.sock|\bnsenter\b", "container escape / privileged container"),
    ("persistence_or_privesc", T, 0.60, r"\bpasswd\s+root\b|echo[^\n]*\|\s*chpasswd|/etc/passwd[^\n]*(>>|write|append)|>>\s*/etc/passwd", "modifies system accounts"),
    ("persistence_or_privesc", T, 0.60, r"LD_PRELOAD=|/etc/ld\.so\.preload|PROMPT_COMMAND=|\balias\s+sudo=", "hijacks loader/shell"),
    ("persistence_or_privesc", C, 0.25, r"\bsudo\b|\bsu\s+-|\bdoas\b|runas\s", "runs with elevated privileges"),

    # ---------------- obfuscated_execution ----------------
    ("obfuscated_execution", T, 0.90, r"\b(eval|exec)\s*\(\s*[^\n]*(b64decode|base64|atob\(|Buffer\.from\([^)]*base64|fromhex|unhexlify|zlib\.decompress|marshal\.loads|codecs\.decode|rot13|decompress|\.decode\()", "decodes then executes a hidden payload"),
    ("obfuscated_execution", T, 0.90, r"base64\s+(-d|--decode|-D)[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*base64\s+(-d|--decode)\s*\|\s*(ba)?sh|echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64", "pipes decoded data into a shell"),
    ("obfuscated_execution", T, 0.90, r"\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|rawurldecode)|\bassert\s*\(\s*\$_(GET|POST|REQUEST)|preg_replace\s*\(\s*['\"][^'\"]*/e['\"]|create_function\s*\(", "PHP decode-and-eval webshell pattern"),
    ("obfuscated_execution", T, 0.85, r"eval\s*\(\s*String\.fromCharCode|eval\s*\(\s*unescape|eval\s*\(\s*function\s*\(p,a,c,k,e|new\s+Function\s*\(\s*atob|Function\s*\(\s*['\"]return this", "JavaScript decode-and-eval"),
    ("obfuscated_execution", T, 0.85, r"powershell[^\n]*-(e|enc|EncodedCommand)\s+[A-Za-z0-9+/=]{16,}|FromBase64String[^\n]*(Invoke-Expression|iex)|\biex\s*\(", "PowerShell encoded command"),
    ("obfuscated_execution", T, 0.70, r"(exec|eval)\s*\(\s*(['\"]\s*\+|\w+\s*\+\s*\w+|chr\(|''\.join|\"\"\.join|\w+\[::-1\])", "executes a dynamically built string"),
    ("obfuscated_execution", T, 0.65, r"getattr\(\s*(__builtins__|builtins|os|subprocess|__import__\([^)]*\))\s*,\s*[^'\")]|__import__\(\s*['\"][^'\"]+['\"]\s*\)\.(system|popen|exec|startfile|spawn)|(__dict__\s*\[\s*['\"]|__getattribute__\(\s*['\"])(system|popen|startfile|spawn\w*|exec\w*|eval|Popen|check_output|getoutput|remove|rmtree|unlink)['\"]|__import__\([^'\"\n]*[+\]]|globals\(\)\[[^\]]*\]\(|__builtins__\[|__subclasses__\(\)", "hides an import/function name at runtime"),
    ("obfuscated_execution", T, 0.60, r"\b_0x[0-9a-fA-F]{4,}\b", "JavaScript identifier mangling"),
    ("obfuscated_execution", T, 0.45, r"(\\x[0-9a-fA-F]{2}){12,}|(chr\(\d+\)\s*\+\s*){6,}|String\.fromCharCode\((\s*\d+\s*,){8,}", "long escaped/char-coded string"),
    ("obfuscated_execution", T, 0.55, r"\b(curl|wget)\b[^\n]*\|\s*(python3?|node|perl|ruby|php)\b(?![^\n|;&]*\s-[a-zA-Z]*[cemrE]\b)|\b(python3?|perl|ruby)\s+-c\s+['\"][^'\"]*(exec|eval|base64)", "pipes remote/decoded code into an interpreter"),
    ("obfuscated_execution", C, 0.30, r"\b(eval|exec)\s*\(|\bcompile\(|new\s+Function\(|\bvm\.run|\bsetTimeout\(\s*['\"]", "dynamic code execution"),

    # ---------------- dependency_risk ----------------
    ("dependency_risk", T, 0.85, r"\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(bash|sh)\s+<\(\s*(curl|wget)", "pipes a remote script into the shell"),
    ("dependency_risk", T, 0.85, r"\b(iwr|irm|curl|wget|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b[^\n]*\|\s*(iex|Invoke-Expression)\b|\b(iex|Invoke-Expression)\b[^\n]*\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b", "downloads a remote script and runs it (PowerShell)"),
    ("dependency_risk", T, 0.70, r"\bpip3?\s+install\b[^\n]*(https?://(?!files\.pythonhosted|pypi\.org)|git\+http|\d{1,3}(\.\d{1,3}){3})", "installs a package from an untrusted URL"),
    ("dependency_risk", T, 0.60, r"--trusted-host|--extra-index-url\s+http://|--index-url\s+http://|npm\s+(i|install)\s+[^\n]*https?://|registry\s*=\s*http://|--allow-unauthenticated|--no-check-certificate|--insecure\b|-k\s+https?://", "disables package/TLS integrity checks"),
    ("dependency_risk", T, 0.65, r"(wget|curl)[^\n]*(-o|-O|>)\s*\S+[^\n]*(&&|;)\s*(chmod\s+\+x|\./|sh\s|bash\s|python\s)", "downloads then executes a binary"),
    ("dependency_risk", T, 0.60, r"['\"](preinstall|postinstall|install)['\"]\s*:\s*['\"][^'\"]*(curl|wget|node\s+-e|bash|sh\s|powershell)|post-(install|update)-cmd", "package install hook runs commands"),
    ("dependency_risk", C, 0.15, r"\b(pip3?|npm|yarn|pnpm|gem|cargo|go|composer)\s+(install|add|get|i|require)\b", "installs a package"),

    # ---------------- resource_exhaustion ----------------
    ("resource_exhaustion", T, 0.95, r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\b(\w+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}", "fork bomb"),
    ("resource_exhaustion", T, 0.75, r"while\s*(true|:|\[\s*1\s*\]|\(\(\s*1\s*\)\))\s*;\s*do\s*[^\n]*(&|fork|\$0)\s*;?\s*done|\$0\s*&\s*\$0|%0\|%0", "self-replicating shell loop"),
    ("resource_exhaustion", T, 0.70, r"\[\s*0\s*\]\s*\*\s*\(?\s*10\s*\*\*\s*(1[0-9]|[2-9]\d)|['\"][^'\"]?['\"]\s*\*\s*\d{10,}|\bnew\s+Array\(\s*\d{9,}|Array\(1e(9|1\d)\)|bytearray\(\s*10\s*\*\*\s*1[0-9]|\bfallocate\s+-l\s*\d+[GT]|\bdd\b[^\n]*if=/dev/(zero|urandom)(?![^\n]*(count=|of=/dev/))", "allocates huge memory/disk"),
    ("resource_exhaustion", T, 0.60, r"\byes\s*>\s*/dev/null\s*&|\bstress(-ng)?\s+--(cpu|vm)|for\s*\(\s*;\s*;\s*\)\s*\{\s*(fork|cluster\.fork|new\s+Worker|child_process)", "CPU/process exhaustion"),
    ("resource_exhaustion", T, 0.65, r"(while\s*\(\s*(true|1)\s*\)|for\s*\(\s*;\s*;\s*\))\s*\{(?![^\n}]*\b(break|return|throw|await|exit)\b)[^\n}]*(new\s+Array|\.push\(|Buffer\.alloc|\.fill\(|fork\(|spawn\(|new\s+Worker)", "infinite JS loop that allocates or spawns"),
    ("resource_exhaustion", T, 0.55, r"ulimit\s+-[un]\s+unlimited|sys\.setrecursionlimit\(\s*10\s*\*\*\s*\d|setrecursionlimit\(\s*\d{6,}", "removes resource limits"),
    ("resource_exhaustion", C, 0.25, r"while\s+True\s*:|while\s*\(\s*(true|1)\s*\)|for\s*\(\s*;\s*;\s*\)|while\s+(true|:)\s*;\s*do|\bos\.fork\(|\bfork\(\)", "unbounded loop or fork"),

    # ---------------- ssrf_network_exfil ----------------
    ("ssrf_network_exfil", T, 0.90, r"169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|metadata\.azure\.com|/computeMetadata/v1|/latest/meta-data|/metadata/instance", "queries a cloud metadata endpoint"),
    ("ssrf_network_exfil", T, 0.85, r"/dev/tcp/|/dev/udp/|\b(nc|ncat|netcat)\b[^\n]*\s-(e|c)\s*\S*(sh|bash|cmd)|\bsocat\b[^\n]*exec:|pty\.spawn\(|os\.dup2\(\s*\w*(sock|conn|client|\bs)\w*\.fileno|mkfifo[^\n]*\|\s*(ba)?sh|Net\.Sockets\.TCPClient", "reverse shell"),
    ("ssrf_network_exfil", T, 0.65, r"\b(gopher|dict|tftp)://|\bfile:///(etc|proc|root|home|var|c:)|\$\{jndi:(ldap|rmi|dns)", "dangerous URL scheme / JNDI lookup"),
    ("ssrf_network_exfil", T, 0.50, r"https?://(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1?\]|0x7f|2130706433)(:\d+)?/(admin|internal|debug|actuator|_|env|metrics|api/v\d/(secrets|keys))", "calls an internal admin endpoint"),
    ("ssrf_network_exfil", T, 0.45, r"https?://(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})", "calls a private-network address"),
    ("ssrf_network_exfil", T, 0.55, r"kubernetes\.default(\.svc)?|/var/run/secrets/kubernetes\.io|:2375\b|:10250\b|:6443\b", "reaches cluster/docker control plane"),
    ("ssrf_network_exfil", T, 0.45, r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?", "connects to a raw IP address"),
    ("ssrf_network_exfil", T, 0.50, r"\bnmap\b|\bmasscan\b|for\s+\w+\s+in\s+\$\(seq\s+1\s+(254|255)\)", "network scanning"),
]

_COMPILED = [(c, k, w, re.compile(p, re.I), r) for c, k, w, p, r in RULES]


def scan_text(code: str, line_offset: int = 0, source: str = "rule", weight_scale: float = 1.0):
    """Run every rule on every line; returns a list of Findings."""
    out = []
    lines = code.splitlines() or [code]
    for i, line in enumerate(lines, start=1):
        if len(line) > 4000:  # guard regex cost on minified blobs
            line = line[:4000]
        for cat, kind, w, rx, reason in _COMPILED:
            if rx.search(line):
                out.append(Finding(cat, kind, round(w * weight_scale, 3), i + line_offset, reason, source))
    return out
