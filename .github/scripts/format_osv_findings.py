#!/usr/bin/env python3
"""Format OSV-Scanner JSON results in the same console-output style as
HashiCorp's real `security-scanner` tool, and honor triage/suppression
rules from the repo's `.release/security-scan.hcl` (the same file the real
scanner reads), so a finding can be resolved by either fixing the
dependency or adding it to that file -- exactly like the real CRT gate.

Usage: format_osv_findings.py <osv-results.json> <security-scan.hcl> <target-name>

Exit code: 0 if no unsuppressed findings remain, 1 otherwise (mirrors the
real security-scanner binary, whose non-zero exit is what CRT/PLC gates on).
"""
import fnmatch
import json
import re
import sys


def load_suppressions(hcl_path):
    """Extract every `vulnerabilities = [...]` and `paths = [...]` list in
    the HCL file (both the `container` and `binary` blocks are unioned --
    this stand-in scan doesn't distinguish container vs. binary targets).
    Uses a small regex/line-based scan rather than a full HCL parser, since
    security-scan.hcl only ever contains simple flat string lists here."""
    try:
        with open(hcl_path) as f:
            text = f.read()
    except FileNotFoundError:
        return set(), []

    suppressed_vulns = set()
    suppressed_paths = []

    for match in re.finditer(r"vulnerabilities\s*=\s*\[(.*?)\]", text, re.DOTALL):
        for line in match.group(1).splitlines():
            code = line.split("//", 1)[0]  # strip trailing // comments
            suppressed_vulns.update(re.findall(r'"([^"]+)"', code))

    for match in re.finditer(r"paths\s*=\s*\[(.*?)\]", text, re.DOTALL):
        for line in match.group(1).splitlines():
            code = line.split("//", 1)[0]
            suppressed_paths.extend(re.findall(r'"([^"]+)"', code))

    return suppressed_vulns, suppressed_paths


def normalize_path(path, workspace_prefix):
    if workspace_prefix and path.startswith(workspace_prefix):
        path = path[len(workspace_prefix):]
    return path.lstrip("/")


def is_path_suppressed(path, suppressed_paths):
    return any(fnmatch.fnmatch(path, pattern) for pattern in suppressed_paths)


def main():
    if len(sys.argv) < 4:
        print("usage: format_osv_findings.py <osv-results.json> <security-scan.hcl> <target-name> [workspace-prefix]", file=sys.stderr)
        return 2
    results_path, hcl_path, target_name = sys.argv[1], sys.argv[2], sys.argv[3]
    workspace_prefix = sys.argv[4] if len(sys.argv) > 4 else "/src/"

    suppressed_vulns, suppressed_paths = load_suppressions(hcl_path)

    try:
        with open(results_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"no OSV-Scanner results found at {results_path}", file=sys.stderr)
        return 2

    total_findings = 0
    printed_header = False

    for result in data.get("results", []):
        raw_path = result.get("source", {}).get("path", "")
        path = normalize_path(raw_path, workspace_prefix)

        if is_path_suppressed(path, suppressed_paths):
            continue

        file_findings = []
        for pkg in result.get("packages", []):
            name = pkg.get("package", {}).get("name", "unknown")
            version = pkg.get("package", {}).get("version", "unknown")
            for vuln in pkg.get("vulnerabilities", []) or []:
                vuln_id = vuln.get("id", "unknown")
                if vuln_id in suppressed_vulns:
                    continue
                file_findings.append((vuln_id, name, version))

        if not file_findings:
            continue

        if not printed_header:
            print(" » Go Modules Scanner")
            printed_header = True

        print(f'Scanned file:{{path:"{path}"}} - found {len(file_findings)} result(s)')
        for vuln_id, name, version in file_findings:
            print(f" ⚠︎ found OSV reported vulnerability {vuln_id} in {name}@{version}")
            print(f" {path}:1:1")
        total_findings += len(file_findings)

    if total_findings > 0:
        print(f"Error: Security scanner found issue in: {target_name}", file=sys.stderr)
        return 1

    print(f"Security scanner found no un-triaged issues in: {target_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
