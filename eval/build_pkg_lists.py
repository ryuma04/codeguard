"""Build the package-reputation lists used at runtime by the dependency_risk check.

    python eval/build_pkg_lists.py      # downloads 3 JSON files, writes codeguard/data/*.txt

Sources:
  * hugovk/top-pypi-packages: top 15,000 PyPI projects by downloads (public PyPI
    statistics; we keep only the names, which are facts).
  * DataDog/malicious-software-packages-dataset (Apache-2.0): ONLY the
    samples/{pypi,npm}/manifest.json name lists. The malware samples themselves
    are never downloaded.
"""
import json
import os
import re
import urllib.request

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
RAW = os.path.join(ROOT, "data", "external", "raw", "pkgs")
OUT = os.path.join(ROOT, "codeguard", "data")
URLS = {
    "top-pypi-packages.min.json": "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json",
    "pypi_manifest.json": "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json",
    "npm_manifest.json": "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json",
}


def norm(name):
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def main():
    os.makedirs(RAW, exist_ok=True)
    os.makedirs(OUT, exist_ok=True)
    for fn, url in URLS.items():
        p = os.path.join(RAW, fn)
        if not os.path.exists(p):
            urllib.request.urlretrieve(url, p)

    with open(os.path.join(RAW, "top-pypi-packages.min.json"), encoding="utf-8") as f:
        top = [norm(r["project"]) for r in json.load(f)["rows"]]
    top_set = set(top)

    def manifest(fn, ecosystem):
        with open(os.path.join(RAW, fn), encoding="utf-8") as f:
            data = json.load(f)
        bad, compromised, skipped = [], [], 0
        for name, versions in data.items():
            n = name.strip().lower() if ecosystem == "npm" else norm(name)
            if versions is None:
                if ecosystem == "pypi" and n in top_set:
                    skipped += 1  # never hard-block a top-15k project by name alone
                    continue
                bad.append(n)
            else:
                compromised.append(f"{n} {' '.join(map(str, versions))}")
        return sorted(set(bad)), sorted(set(compromised)), skipped

    files = {"top_pypi.txt": top}
    for eco in ("pypi", "npm"):
        bad, comp, skipped = manifest(f"{eco}_manifest.json", eco)
        files[f"malicious_{eco}.txt"] = bad
        files[f"compromised_{eco}.txt"] = comp
        print(f"{eco}: {len(bad)} malicious names, {len(comp)} compromised packages (version-specific), {skipped} skipped (top-15k)")
    for fn, lines in files.items():
        with open(os.path.join(OUT, fn), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
    print(f"top PyPI names: {len(top)}  -> {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    main()
