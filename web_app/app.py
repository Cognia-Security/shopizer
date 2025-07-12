from flask import Flask, request, send_file, render_template, jsonify
import os, time, json, requests, tempfile, zipfile
from datetime import datetime
from bs4 import BeautifulSoup
import re

app = Flask(__name__)

SONAR_API_BASE = "https://sonarcloud.io"
SONAR_PROJECT_KEY = "aprajita-bhowal_shopizer"
ORGANIZATION = "aprajita-bhowal"

def get_github_token():
    return (request.json.get("github_token") if request.json else None) or os.getenv("GITHUB_PAT")

def get_sonar_token():
    return (request.json.get("sonar_token") if request.json else None) or os.getenv("SONAR_TOKEN")

def get_semgrep_token():
    return (request.json.get("semgrep_token") if request.json else None) or os.getenv("SEMGREP_TOKEN")

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/trigger-codeql', methods=['POST'])
def trigger_codeql():
    repo_url = request.json.get("repo_url")
    owner, repo = "aprajita-bhowal", "shopizer"
    branch = "3.2.7"
    workflow_file = "codeql-analysis.yml"

    dispatch_url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_file}/dispatches"
    headers = {
        "Authorization": f"Bearer {get_github_token()}",
        "Accept": "application/vnd.github+json"
    }
    response = requests.post(dispatch_url, headers=headers, json={"ref": branch})
    if response.status_code != 204:
        return jsonify({"error": "Failed to trigger workflow", "detail": response.text}), 500

    time.sleep(10)
    run_id = None
    for _ in range(30):
        runs_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs"
        runs_response = requests.get(runs_url, headers=headers).json()
        for run in runs_response.get("workflow_runs", []):
            if run["name"].lower().startswith("codeql") and run["head_branch"] == branch:
                run_id = run["id"]
                status = run["status"]
                conclusion = run["conclusion"]
                if status == "completed":
                    if conclusion != "success":
                        return jsonify({"error": f"Run failed: {conclusion}"}), 500
                    break
        if run_id:
            break
        time.sleep(15)

    if not run_id:
        return jsonify({"error": "Timed out waiting for workflow run"}), 504

    artifacts_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
    artifacts_response = requests.get(artifacts_url, headers=headers).json()
    artifact = next((a for a in artifacts_response.get("artifacts", []) if "codeql-report" in a["name"]), None)
    if not artifact:
        return jsonify({"error": "SARIF artifact not found"}), 404

    download_url = artifact["archive_download_url"]
    zip_resp = requests.get(download_url, headers=headers)
    zip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
    with open(zip_path, "wb") as f:
        f.write(zip_resp.content)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        extract_dir = tempfile.mkdtemp()
        zip_ref.extractall(extract_dir)
        sarif_file = os.path.join(extract_dir, zip_ref.namelist()[0])

    with open(sarif_file) as f:
        report_json = json.load(f)

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    with open(tmp_file.name, 'w') as f:
        json.dump(report_json, f, indent=2)

    return send_file(tmp_file.name, as_attachment=True, download_name="codeql-report.json", mimetype="application/json")

def extract_cwe_owasp_from_html(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator="\n")

    cwe_match = re.search(r"(CWE-\d+)", text, re.IGNORECASE)
    owasp_match = re.search(r"(OWASP[\s-]*Top\s*10[\s-]*\d{4}[\s-]*[A-Z]?\d+|OWASP[\s-]*[A-Z]?\d+)", text, re.IGNORECASE)

    return {
        "cweId": cwe_match.group(1).upper() if cwe_match else None,
        "owaspCategory": owasp_match.group(1).upper().replace(" ", "").replace("_", "-") if owasp_match else None
    }

def parse_html_sections(html):
    print("parse_html_sections() has been called!")
    soup = BeautifulSoup(html, "html.parser")
    print(f"Soup: {soup}")
    sections = {"where": "", "why": "", "how": "", "more": ""}
    current = None

    for tag in soup.find_all(["h2", "h3", "p", "ul"]):
        text = tag.get_text(strip=True)
        tag_name = tag.name.lower()

        if tag_name in ["h2", "h3"]:
            lowered = text.lower()
            if "where" in lowered:
                current = "where"
            elif "why" in lowered:
                current = "why"
            elif "how" in lowered:
                current = "how"
            elif "more" in lowered or "see" in lowered:
                current = "more"
            else:
                current = None
        elif tag_name in ["p", "ul"]:
            if current:
                sections[current] += text + "\n"
            else:
                sections["why"] += text + "\n"  # default fallback bucket

    return {k: v.strip() for k, v in sections.items() if v.strip()}

@app.route('/trigger-sonar', methods=['POST'])
def trigger_sonar():
    API_URL = f"{SONAR_API_BASE}/api/issues/search?componentKeys={SONAR_PROJECT_KEY}"
    auth = (get_sonar_token(), "")
    headers = {"Accept": "application/json"}

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SonarCloud",
                    "informationUri": SONAR_API_BASE,
                    "rules": []
                }
            },
            "results": []
        }]
    }

    all_issues = []
    page = 1
    page_size = 100
    while True:
        response = requests.get(f"{API_URL}&p={page}&ps={page_size}", headers=headers, auth=auth)
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch issues", "detail": response.text}), 500
        data = response.json()
        issues = data["issues"]
        security_issues = [
            i for i in issues
            if i.get("type") == "VULNERABILITY" or i.get("securityCategory") == "SECURITY_HOTSPOT"
        ]
        all_issues.extend(security_issues)
        if data["paging"]["total"] <= page * page_size:
            break
        page += 1

    rules_map = {}
    rule_metadata_cache = {}

    for issue in all_issues:
        rule_id = issue["rule"]
        severity = issue["severity"]
        message = issue["message"]
        file_path = issue.get("component", "").split(":")[-1]
        line = issue.get("line", 1)
        issue_tags = issue.get("tags", [])

        # Fetch rule metadata (cached)
        if rule_id not in rule_metadata_cache:
            rule_response = requests.get(f"{SONAR_API_BASE}/api/rules/show?key={rule_id}&organization={ORGANIZATION}", headers=headers, auth=auth)
            if rule_response.status_code == 200:
                rule_data = rule_response.json().get("rule", {})
                rule_tags = rule_data.get("tags", [])
                html_desc = rule_data.get("htmlDesc", "")
                parsed_sections = parse_html_sections(html_desc)
                id_matches = extract_cwe_owasp_from_html(html_desc)
                rule_metadata_cache[rule_id] = {
                    "tags": rule_tags,
                    "sections": parsed_sections,
                    "title": rule_data.get("name", ""),
                    "html": html_desc,
                    "cweId": id_matches["cweId"],
                    "owaspCategory": id_matches["owaspCategory"]
                }
            else:
                rule_metadata_cache[rule_id] = {
                    "tags": [], "sections": {}, "title": "", "html": ""
                }

        rule_info = rule_metadata_cache[rule_id]
        combined_tags = list(set(issue_tags + rule_info["tags"]))

        # Extract CWE and OWASP from tags
        cwe_tag = next((tag for tag in combined_tags if tag.lower().startswith("cwe-")), None)
        owasp_tag = next((tag for tag in combined_tags if tag.lower().startswith("owasp")), None)

        # Add rule to SARIF tool rules section
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_info["title"] or rule_id,
                "shortDescription": {"text": rule_info["title"] or rule_id},
                "fullDescription": {"text": rule_info["sections"].get("why", "")},
                "helpUri": f"https://rules.sonarsource.com/java/RSPEC-{rule_id.split(':')[-1]}",
                "properties": {
                    "tags": rule_info["tags"],
                    "details": rule_info["sections"]
                }
            }

        # Add result (issue) to SARIF
        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "level": severity.lower(),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": line}
                }
            }],
            "properties": {
                "tags": combined_tags,
                "ruleDetails": rule_info["sections"],
                "securityCategory": issue.get("securityCategory"),
                "type": issue.get("type"),
                "effort": issue.get("effort"),
                "author": issue.get("author"),
                "creationDate": issue.get("creationDate"),
                "updateDate": issue.get("updateDate"),
                "component": issue.get("component"),
                "status": issue.get("status"),
                "resolution": issue.get("resolution"),
                "ruleUrl": f"https://rules.sonarsource.com/java/RSPEC-{rule_id.split(':')[-1]}",
                "cweId": rule_info.get("cweId"),
                "owaspCategory": rule_info.get("owaspCategory")
            }
        })

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())

    tmp_path = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    with open(tmp_path.name, 'w') as f:
        json.dump(sarif, f, indent=2)

    return send_file(tmp_path.name, as_attachment=True, download_name="sonarqube-security-report.json", mimetype="application/json")

@app.route('/trigger-semgrep', methods=['POST'])
def trigger_semgrep():
    repo_url = request.json.get("repo_url")
    headers = {
        "Authorization": f"Bearer {get_semgrep_token()}",
        "Accept": "application/json"
    }

    org_slug = "aprajita_bhowal_cogniasec_com"
    scans_url = f"https://semgrep.dev/api/v1/orgs/{org_slug}/scans"

    scans_resp = requests.get(scans_url, headers=headers)
    if scans_resp.status_code != 200:
        return jsonify({"error": "Failed to fetch scans", "detail": scans_resp.text}), 500

    scans = scans_resp.json().get("scans", [])
    matching_scans = [s for s in scans if s.get("repo", {}).get("url") == repo_url]
    if not matching_scans:
        return jsonify({"error": "No scans found for this repo"}), 404

    scan_id = matching_scans[0]["id"]
    findings_url = f"https://semgrep.dev/api/v1/scans/{scan_id}/sarif"

    findings_resp = requests.get(findings_url, headers=headers)
    if findings_resp.status_code != 200:
        return jsonify({"error": "Failed to fetch findings", "detail": findings_resp.text}), 500

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    with open(tmp_file.name, 'wb') as f:
        f.write(findings_resp.content)

    return send_file(tmp_file.name, as_attachment=True, download_name="semgrep-report.json", mimetype="application/json")


@app.route('/trigger-dependabot', methods=['POST'])
def trigger_dependabot():
    repo_url = request.json.get("repo_url")
    owner, repo = "aprajita-bhowal", "shopizer"

    headers = {
        "Authorization": f"Bearer {get_github_token()}",
        "Accept": "application/vnd.github+json"
    }

    alerts = []
    page = 1
    while True:
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts",
            headers=headers,
            params={"per_page": 100, "page": page}
        )
        if resp.status_code != 200:
            return jsonify({"error": "Failed to fetch dependabot alerts", "detail": resp.text}), 500
        data = resp.json()
        if not data:
            break
        alerts.extend(data)
        page += 1

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    with open(tmp_file.name, 'w') as f:
        json.dump(alerts, f, indent=2)

    return send_file(tmp_file.name, as_attachment=True, download_name="dependabot-report.json", mimetype="application/json")

if __name__ == '__main__':
    app.run(debug=True)
