"""Language registry: what each language is called, how it is recognised, and how deeply we analyse it.

Support tiers (stated in `reason` for light/unsupported, and as `language_support` in debug output):
  deep         a structural analyser: Python (ast), SQL (statement analysis), YAML and Markdown
               (structure + embedded code re-routed through the cascade)
  carrier      formats that only carry code (JSON, Dockerfile, Makefile, HTML): the code inside is
               extracted and analysed in its own language (HTML: <script> blocks; its text, comments and
               visually hidden elements are read by the prompt-injection layer)
  light        no structural analyser, but the shared rule layer (rules.py) was written with these
               languages' idioms in it (child_process, PHP eval/base64_decode, PowerShell -enc, shell pipes)
  unsupported  everything else, including languages the router can name (Go, OCaml, Java, ...) and text it
               cannot identify: only the generic rules apply, and the reason says so

Move a language up a tier only when it gets checks of its own (e.g. per-language sink/source rules).
Detection signals here are merged into router._SIGNALS. Weights are tuned on the CyberNative
labelled snippets (eval/language_eval.py); keep new signals distinctive, not generic.
"""

DEEP = {"python", "sql", "yaml", "markdown"}
CARRIER = {"json", "dockerfile", "makefile", "html"}
LIGHT = {"javascript", "typescript", "bash", "php", "powershell"}

DISPLAY = {"cpp": "C++", "csharp": "C#", "fsharp": "F#", "javascript": "JavaScript", "typescript": "TypeScript",
           "php": "PHP", "sql": "SQL", "yaml": "YAML", "ocaml": "OCaml", "vbscript": "VBScript", "powershell": "PowerShell"}


def support(language: str) -> str:
    if language in DEEP:
        return "deep"
    if language in CARRIER:
        return "carrier"
    if language in LIGHT:
        return "light"
    return "unsupported"


def display(language: str) -> str:
    return DISPLAY.get(language, language.capitalize() if language != "unknown" else "unknown")


# (regex, weight). Case-sensitive unless the language is listed in CASE_INSENSITIVE.
SIGNALS = {
    "go": [
        (r"^package\s+\w+\s*$", 6), (r"^import\s*\(\s*$", 4), (r"\bfunc\s+(\(\w+\s+\*?\w+\)\s*)?\w+\s*\(", 4),
        (r"\w\s*:=\s*", 2), (r"\bfmt\.\w+\(", 4), (r"\berr\s*!=\s*nil\b", 5), (r"\bdefer\s+\w", 3),
        (r"\bgo\s+func\b", 4), (r"\[\](byte|string|int)\b", 3), (r"\bchan\s+\w+", 3), (r"\bexec\.Command\(", 4),
        (r"\bos\.(Getenv|ReadFile|WriteFile|RemoveAll|Exit)\(", 3),
    ],
    "rust": [
        (r"\bfn\s+\w+\s*(<[^>]*>)?\s*\(", 4), (r"\blet\s+mut\s+", 5), (r"^\s*use\s+(std|crate|super|self|\w+)::", 5),
        (r"\b(println|format|vec|panic|eprintln|write|writeln|assert|assert_eq)!\s*[(\[]", 5), (r"\.unwrap\(\)", 3),
        (r"&(mut\s+)?(str|self)\b", 3), (r"\bimpl(<[^>]*>)?\s+\w+", 4), (r"#\[(derive|test|cfg)", 6),
        (r"\bpub\s+(fn|struct|enum|mod|trait)\b", 4), (r"->\s*(Result|Option|Self|String|Vec|i32|i64|u8|u32|u64|usize|bool)\b", 3),
        (r"\b\w+::new\(", 1), (r"\bmatch\s+[\w.&]+\s*\{", 2),
    ],
    "java": [
        (r"\bpublic\s+static\s+void\s+main\s*\(\s*(final\s+)?String", 8), (r"\bSystem\.(out|err)\.print", 6),
        (r"^import\s+(java|javax|org|com)\.[\w.*]+;", 6), (r"^package\s+[\w.]+;", 6),
        (r"\b(public|private|protected)\s+(static\s+)?(final\s+)?(class|interface|enum)\s+\w+", 3),
        (r"\b(public|private|protected)\s+(static\s+)?(final\s+)?(synchronized\s+)?[\w<>\[\],]+\s+\w+\s*\([^)]*\)\s*(throws\s+[\w, ]+)?\s*\{", 3),
        (r"@Override\b", 3), (r"\bthrows\s+\w+(Exception|Error)\b", 4), (r"\bString\[\]", 3), (r"\bRuntime\.getRuntime\(\)", 5),
        (r"\b(ArrayList|HashMap|StringBuilder|Scanner|BufferedReader)\s*<?", 2), (r"\bnew\s+\w+(<[^>]*>)?\s*\(", 1),
    ],
    "kotlin": [
        (r"\bfun\s+(<[^>]*>\s*)?[\w.]+\s*\(", 5), (r"\bval\s+\w+\s*(:\s*[\w<>?]+)?\s*=", 3), (r"^import\s+kotlin(x)?\.", 8),
        (r"\b(data|sealed|open|enum|inner)\s+class\b", 3), (r"\?\.\w|!!\.|\s\?:\s", 2), (r"\bwhen\s*(\([^)]*\))?\s*\{", 3),
        (r"\bcompanion\s+object\b", 5), (r"\bprintln\(\s*\"[^\"]*\$", 3), (r"\blistOf\(|\bmutableListOf\(|\bmapOf\(", 4),
    ],
    "scala": [
        (r"\bobject\s+\w+(\s+extends\s+\w+)?\s*\{", 4), (r"\bdef\s+\w+(\[[^\]]*\])?\s*(\([^)]*\))?\s*(:\s*[\w\[\], ]+)?\s*=", 4),
        (r"^import\s+scala\.", 8), (r"\bcase\s+class\b", 5), (r"\bsys\.process\b", 6), (r"\bimplicit\s+(val|def)\b", 5),
        (r"\bval\s+\w+\s*(:\s*[\w\[\]]+)?\s*=", 1),
    ],
    "c": [
        (r"^#include\s*<(stdio|stdlib|string|unistd|signal|fcntl|errno|time|stdint|math|ctype|pthread|dirent|windows|winsock2)\.h>", 5),
        (r"^#include\s*<(sys|netinet|arpa)/\w+\.h>", 5), (r"\bint\s+main\s*\(", 4), (r"\bprintf\s*\(", 2),
        (r"\b(malloc|calloc|free|memset|memcpy)\s*\(", 2), (r"\bchar\s*\*\s*\w+", 2), (r"\b(strcpy|strcat|strncpy|sprintf|snprintf|fgets|scanf)\s*\(", 2),
        (r"#define\s+\w+", 3), (r"\bstruct\s+\w+\s*\{", 2), (r"\bvoid\s*\*", 2), (r"\breturn\s+0\s*;", 1),
    ],
    "cpp": [
        (r"^#include\s*<(iostream|string|vector|map|memory|fstream|sstream|algorithm|cstring|cstdlib|cstdio|thread|mutex|array|set|unordered_map|iomanip|limits|stdexcept|exception|cstdint|filesystem|chrono|functional|climits|cmath|cctype|list|queue|deque)>", 7),
        (r"\bstd::\w+", 4), (r"\busing\s+namespace\s+std\s*;", 8), (r"\b(cout|cerr)\s*<<|\bcin\s*>>", 6),
        (r"^\s*(public|private|protected)\s*:", 4), (r"\btemplate\s*<", 5), (r"\bnullptr\b", 4),
        (r"\b\w+::\w+\s*\(", 1), (r"\bclass\s+\w+\s*(:\s*(public|private)\s+\w+)?\s*\{", 2), (r"\bdelete\s*\[\]", 4),
    ],
    "csharp": [
        (r"^using\s+System(\.[\w.]+)?\s*;", 8), (r"^\s*namespace\s+[\w.]+\s*\{?\s*;?$", 3), (r"\bConsole\.(Write|Read)\w*\(", 6),
        (r"\bstatic\s+(async\s+)?(void|int|Task)\s+Main\s*\(", 6), (r"\{\s*get;\s*(private\s+)?(set;|init;)?\s*\}", 6),
        (r"\b(public|private|internal|protected)\s+(static\s+)?(async\s+)?(override\s+)?[\w<>\[\],?]+\s+\w+\s*\(", 2),
        (r"\bvar\s+\w+\s*=\s*new\b", 3), (r"\bstring(\[\])?\s+\w+\s*[=,);]", 3), (r"\w\.Length\b", 2), (r"\bProcess\.Start\(", 4), (r"\$\"[^\"]*\{", 2),
        (r"\b(SqlConnection|SqlCommand|HttpClient|StreamReader|Environment)\b", 2),
    ],
    "ruby": [
        (r"^\s*require(_relative)?\s+['\"][\w/.\-]+['\"]\s*$", 3), (r"^\s*def\s+(self\.)?\w+[?!]?(\s*\(.*\))?\s*$", 4),
        (r"^\s*end\s*$", 2), (r"\bputs\s", 4), (r"\.each(_with_index)?\s+do\s*\|", 6), (r"\bdo\s*\|\w+(,\s*\w+)*\|", 5),
        (r"#\{[^}]+\}", 2), (r"\battr_(accessor|reader|writer)\b", 6), (r"\belsif\b", 3), (r"\bunless\b", 2),
        (r"^\s*@\w+\s*=", 2), (r"\bclass\s+\w+\s*<\s*[\w:]+", 4), (r"^\s*module\s+\w+\s*$", 3), (r"\.new\(", 1),
        (r"\b(nil|\.nil\?|\.empty\?)", 1),
    ],
    "perl": [
        (r"^\s*use\s+(strict|warnings)\s*;", 8), (r"\bmy\s+[\$@%]\w+", 6), (r"\$ENV\{|@ARGV|\$_\b|\$0\b", 4),
        (r"\bsub\s+\w+\s*\{", 5), (r"=~\s*(s|m|tr|y)?[/{]", 4), (r"\bqw\s*[(\[{/]", 4), (r"\bforeach\s+my\b", 5),
        (r"\bdie\s+\"", 2), (r"^#!.*perl", 8), (r"\bprint\s+\"[^\"]*\\n\"\s*;", 2), (r"\$\w+\s*->\s*\{", 3),
    ],
    "lua": [
        (r"\blocal\s+(function\s+)?\w+", 5), (r"\bfunction\s+[\w.:]+\s*\([^)]*\)\s*$", 2), (r"\bthen\s*$", 3),
        (r"\b(os\.execute|io\.popen|loadstring)\s*\(", 6), (r"\bio\.(open|read|write|lines)\s*\(", 2), (r"\w\s*\.\.\s*['\"\w]", 2),
        (r"~=", 3), (r"\b(i?pairs)\s*\(", 5), (r"--\[\[", 5), (r"^\s*end\s*$", 1),
    ],
    "ocaml": [
        (r"\blet\s+\(\)\s*=", 8), (r"\blet\s+rec\s+\w+", 6), (r"^\s*let\b[^\n]*\bin\s*$", 4), (r"\bmatch\s+.+\s+with\s*$", 5),
        (r"\b(Printf|Sys|Unix|List|String|Array|Hashtbl|Filename|Buffer|Lwt|Option|Result|Bytes)\.[a-z_]\w*", 3),
        (r"\(\*.*?\*\)", 4), (r"\)\s*;;\s*$", 3), (r"^\s*open\s+[A-Z]\w*\s*$", 4), (r"\bprint_(string|endline|int|newline)\b", 6),
        (r"\bfun\s+[\w()]+(\s+\w+)*\s*->", 4), (r"\s\^\s", 2), (r"\bignore\s*\(", 3), (r"\blet\s+\w+(\s+\w+)*\s*=", 1),
        (r"\[\|", 4), (r"\bbegin\b", 1), (r"\bmodule\s+\w+\s*=\s*struct\b", 6),
    ],
    "haskell": [
        (r"^module\s+[\w.]+(\s*\([^)]*\))?\s+where", 8), (r"^import\s+(qualified\s+)?[A-Z][\w.]+(\s+as\s+\w+)?(\s*\(.*\))?\s*$", 5),
        (r"^\w+\s*::\s*", 5), (r"\bwhere\s*$", 2), (r"^\s+\w+\s*<-\s", 3), (r"\b(putStrLn|mapM_|forM_|readFile|getLine|getArgs)\b", 5),
        (r"^main\s*=\s*", 5), (r"^data\s+\w+", 3), (r"\$\s", 1), (r"\bdo\s*$", 2),
    ],
    "swift": [
        (r"^import\s+(Foundation|UIKit|SwiftUI|Cocoa|Darwin|AppKit|Combine)\s*$", 8),
        (r"\bfunc\s+\w+\s*(<[^>]*>)?\([^)]*\)\s*(throws\s*)?(->\s*[\w?\[\]<>: ]+)?\s*\{", 4),
        (r"\b(guard|if)\s+let\b", 6), (r"\\\(\w[^)]*\)", 3), (r"\b(NSString|URLSession|FileManager|DispatchQueue|NSObject|UIViewController)\b", 4),
        (r"\boverride\s+func\b", 5), (r"\bvar\s+\w+\s*:\s*[\w?\[\]]+\s*(=|$|\{)", 2), (r"\blet\s+\w+\s*(:\s*[\w?\[\]]+)?\s*=", 1),
        (r"\b(struct|class|enum)\s+\w+\s*:\s*\w+", 2), (r"\binit\s*\(", 2),
    ],
    "r": [
        (r"\w\s*<-\s*(function\s*\(|c\(|read\.\w+\(|data\.frame\(|list\(|matrix\()", 6), (r"^\s*library\(\w+\)", 6),
        (r"^\s*\w+\s*<-\s*", 3), (r"\b(paste0|sapply|lapply|nrow|ncol|data\.frame)\s*\(", 3),
    ],
    "elixir": [
        (r"\bdefmodule\s+[\w.]+\s+do\b", 8), (r"\bdefp?\s+\w+[?!]?(\(.*\))?\s+do\b", 6), (r"\|>", 3), (r"\bIO\.(puts|inspect)\b", 6),
        (r"\bSystem\.cmd\(", 4), (r"\b(Enum|Map|String|File)\.\w+[?!]?\(", 2), (r"%\{", 2),
    ],
    "dart": [
        (r"^import\s+'(dart|package):", 8), (r"\bvoid\s+main\s*\(\s*(List<String>\s+\w+)?\s*\)", 4), (r"\bFuture<", 3),
        (r"\bfinal\s+\w+\s*=", 2), (r"\bawait\s+\w", 1), (r"\b(StatelessWidget|StatefulWidget)\b", 6),
    ],
    "fortran": [
        (r"^\s*program\s+\w+", 6), (r"\bimplicit\s+none\b", 8), (r"^\s*end\s+(program|subroutine|function|module)\b", 6),
        (r"\b(integer|real|character|logical)\s*(\([^)]*\))?\s*(,\s*\w+(\([^)]*\))?)*\s*::", 6), (r"\bwrite\s*\(\s*\*\s*,", 5),
        (r"\bprint\s+\*\s*,", 6), (r"^\s*subroutine\s+\w+", 5), (r"\bexecute_command_line\b", 4), (r"\ballocate\s*\(", 3),
    ],
    "vbscript": [
        (r"\bCreateObject\s*\(\s*\"", 6), (r"\bWScript\.\w+", 6), (r"^\s*Dim\s+\w+", 4), (r"^\s*Set\s+\w+\s*=", 3),
        (r"^\s*(End\s+(If|Sub|Function)|Next|Wend)\s*$", 3), (r"^\s*On\s+Error\s+Resume\s+Next", 6), (r"\bMsgBox\b", 4),
    ],
    "batch": [
        (r"^\s*@?echo\s+off\b", 8), (r"%~?d?p?\d%|%~dp0", 5), (r"^\s*set\s+(/[ap]\s+)?\w+=", 4), (r"^\s*rem\s", 3),
        (r"^\s*goto\s+:?\w+", 4), (r"^:\w+\s*$", 3), (r"%\w+%", 2), (r"\bif\s+(not\s+)?(exist|errorlevel|defined)\b", 5),
        (r"\^[a-z]\^", 3), (r"%\w+:~-?\d+(,-?\d+)?%", 5),
    ],
    "groovy": [
        (r"^\s*pipeline\s*\{", 6), (r"\bdef\s+\w+\s*=", 2), (r"\"[^\"]*\"\.execute\(\)", 8), (r"\bprintln\s+['\"]", 3),
        (r"^import\s+groovy\.", 8),
    ],
    "typescript": [
        (r"\b(let|const|var)\s+\w+\s*:\s*[\w\[\]<>|]+\s*=", 4), (r"\binterface\s+\w+(<[^>]*>)?\s*\{", 5),
        (r"^\s*(export\s+)?type\s+\w+(<[^>]*>)?\s*=", 4), (r"\):\s*(string|number|boolean|void|any|unknown|never|Promise<)", 5),
        (r"\b(private|public|readonly)\s+\w+\s*:", 3), (r"\bas\s+(string|number|any|unknown|const)\b", 3),
    ],
    "html": [
        # Line-start tags only: programs that build HTML in strings ("<html><body>...") are not HTML documents.
        (r"^\s*<!DOCTYPE\s+html", 10), (r"^\s*<(html|head|body)\b[^>]*>", 5),
        (r"^\s*<(div|span|p|a|ul|li|table|section|article|header|footer|nav|img|form|input|button|meta|link|script|style|h[1-6])\b[^>]*>", 1),
        (r"</(div|span|p|a|li|table|section|article|body|html|h[1-6])>", 1),
        (r"\bstyle\s*=\s*[\"'][^\"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)", 4),
    ],
    # ---- named only (no tier of their own) ----
    "julia": [(r"^\s*using\s+[A-Z]\w+", 3), (r"^\s*function\s+\w+\(.*\)\s*$", 3), (r"\bprintln\(", 1), (r"\bend\s*$", 1), (r"::\s*(Int|Float64|String|Vector)\b", 4), (r"\brun\(`", 6)],
    "erlang": [(r"^-module\(", 8), (r"^-export\(", 8), (r"\bio:format\(", 6), (r"\bos:cmd\(", 6)],
    "clojure": [(r"^\(ns\s", 8), (r"\(defn-?\s", 6), (r"\(println\s", 3), (r"\(let\s+\[", 4)],
    "fsharp": [(r"^\s*let\s+\w+.*=\s*$", 1), (r"\bprintfn\b", 6), (r"^open\s+System", 5), (r"\|>\s*\w", 2)],
    "cobol": [(r"IDENTIFICATION\s+DIVISION", 10), (r"PROCEDURE\s+DIVISION", 10)],
    "assembly": [(r"^\s*section\s+\.(text|data|bss)", 8), (r"^\s*(mov|push|pop|xor|jmp|call|int|syscall|lea)\s+\w+", 2), (r"^\s*global\s+_start", 8)],
    "zig": [(r"@import\(\"std\"\)", 10), (r"\bpub\s+fn\s+main\(\)", 4)],
    "nim": [(r"^\s*proc\s+\w+\*?\(.*\)\s*(:\s*\w+)?\s*=", 6), (r"\becho\s+\"", 1)],
    "crystal": [],
    "lisp": [(r"^\(defun\s", 8), (r"^\(defvar\s", 6), (r"^\(define\s", 6)],
    "prolog": [(r"^\w+\([^)]*\)\s*:-", 8)],
    "pascal": [(r"^\s*program\s+\w+\s*;", 8), (r"^\s*begin\s*$", 2), (r"\bwriteln\(", 5), (r"^\s*end\.\s*$", 6)],
}
CASE_INSENSITIVE = {"fortran", "batch", "vbscript", "cobol", "pascal", "html"}
