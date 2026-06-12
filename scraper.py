import os
import requests
import json
import time
import csv
from datetime import datetime, timezone, timedelta
import google.generativeai as genai
from collections import OrderedDict
from fpdf import FPDF

# ==========================================
# CONFIGURATION AND API KEYS
# ==========================================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
NVD_API_KEY    = os.getenv("NVD_API_KEY")

genai.configure(api_key=GEMINI_API_KEY)

MODEL_NAME = "gemini-2.0-flash"
model = genai.GenerativeModel(MODEL_NAME)

CSV_PATH = os.path.join("dashboards", "historico.csv")

# ─── 1. CSV Migration ────────────────────────────────────────────────────────
def migrate_csv():
    os.makedirs("dashboards", exist_ok=True)
    if not os.path.exists(CSV_PATH):
        return

    needs_migration = False
    rows = []
    
    with open(CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return
            
        if len(header) < 19:
            needs_migration = True
        
        for row in reader:
            rows.append(row)
            
    if needs_migration:
        print(f"Update: Migrating {CSV_PATH} to 19 columns...")
        new_header = [
            "data", "hora", "cve_id", "score", "severidade", 
            "priority_score", "priority_rating", "in_cisa_kev", "epss",
            "cwe_id", "attack_vector", "attack_complexity",
            "ransomware_known", "ioc_count",
            "setor", "software", "tem_patch", "exploitabilidade", "resumo"
        ]
        
        with open(CSV_PATH, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(new_header)
            for row in rows:
                row = row + [""] * (19 - len(row))
                writer.writerow(row)

# ─── 2. NVD API Fetch ────────────────────────────────────────────────────────
def get_cves():
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=8)
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_time.strftime("%Y-%m-%dT%H:%M:%S.000%z").replace("+0000", "Z"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000%z").replace("+0000", "Z")
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    print(f"Fetching CVEs from {params['pubStartDate']}...")
    try:
        response = requests.get(url, params=params, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"NVD API Error: {e}")
        return []

# ─── 3. Filtering and Detail Extraction ──────────────────────────────────────
def filter_critical(vulnerabilities):
    critical_cves = []
    
    for item in vulnerabilities:
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        
        desc = "N/A"
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value")
                break
                
        score = 0
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0]["cvssData"]
                score = cvss_data.get("baseScore", 0)
                severity = cvss_data.get("baseSeverity", entries[0].get("baseSeverity", "UNKNOWN"))
                break

        cwe_id = "N/A"
        weaknesses = cve.get("weaknesses", [])
        if weaknesses:
            for w in weaknesses:
                for d in w.get("description", []):
                    if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                        cwe_id = d["value"]
                        break
                if cwe_id != "N/A":
                    break

        attack_vector = "UNKNOWN"
        attack_complexity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0]["cvssData"]
                attack_vector = cvss_data.get("attackVector", "UNKNOWN")
                attack_complexity = cvss_data.get("attackComplexity", "UNKNOWN")
                break
                
        if score >= 7.0:
            refs = [r["url"] for r in cve.get("references", [])]
            critical_cves.append({
                "id": cve["id"],
                "description": desc,
                "score": score,
                "severity": severity,
                "cwe_id": cwe_id,
                "attack_vector": attack_vector,
                "attack_complexity": attack_complexity,
                "references": refs
            })
            
    return critical_cves

# ─── 4. CISA KEV and EPSS Integration ────────────────────────────────────────
def get_cisa_kev_cves():
    print("Downloading CISA KEV catalog...")
    try:
        resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=15)
        resp.raise_for_status()
        data = resp.json()
        kev_data = {}
        for vuln in data.get("vulnerabilities", []):
            kev_data[vuln["cveID"]] = {
                "ransomware_known": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                "required_action": vuln.get("requiredAction", "N/A"),
                "due_date": vuln.get("dueDate", "N/A"),
            }
        return kev_data
    except Exception as e:
        print(f"CISA KEV Error: {e}")
        return {}

def get_epss_scores(cve_ids):
    if not cve_ids:
        return {}
    results = {}
    chunk_size = 100
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i:i+chunk_size]
        cves_param = ",".join(chunk)
        try:
            resp = requests.get(f"https://api.first.org/data/v1/epss?cve={cves_param}", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", []):
                    results[item["cve"]] = {
                        "epss": float(item["epss"]),
                        "percentile": float(item["percentile"])
                    }
        except Exception as e:
            pass
    return results

def get_threatfox_iocs(cve_ids):
    results = {}
    for cve_id in cve_ids:
        try:
            resp = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": cve_id},
                timeout=8
            )
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("data"):
                iocs = data["data"]
                results[cve_id] = {
                    "count": len(iocs),
                    "ioc_types": list(set(i.get("ioc_type", "") for i in iocs[:10])),
                    "malware_families": list(set(i.get("malware_printable", "") for i in iocs[:10] if i.get("malware_printable")))
                }
            else:
                results[cve_id] = {"count": 0, "ioc_types": [], "malware_families": []}
        except Exception:
            results[cve_id] = {"count": 0, "ioc_types": [], "malware_families": []}
    return results

def get_github_advisories(cve_ids):
    results = {}
    for cve_id in cve_ids:
        try:
            resp = requests.get(
                "https://api.github.com/advisories",
                params={"cve_id": cve_id},
                headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
                timeout=8
            )
            if resp.status_code == 200:
                data = resp.json()
                if data:
                    adv = data[0]
                    results[cve_id] = {
                        "ghsa_id": adv.get("ghsa_id", ""),
                        "severity": adv.get("severity", ""),
                        "summary": adv.get("summary", "")[:200],
                        "url": adv.get("html_url", "")
                    }
                else:
                    results[cve_id] = None
            else:
                results[cve_id] = None
        except Exception:
            results[cve_id] = None
        time.sleep(0.5)
    return results

# ─── 5. Hybrid Priority Scoring ─────────────────────────────────────────────
def calculate_priority_score(cvss_score, in_cisa_kev, epss_data, ransomware_known, ioc_count, attack_vector, attack_complexity):
    cvss = float(cvss_score)
    cvss_points = cvss * 0.4
    kev_points = 2.5 if in_cisa_kev else 0.0
    epss_prob = epss_data.get("epss", 0.0) if epss_data else 0.0
    epss_points = epss_prob * 1.0
    ransomware_points = 1.0 if ransomware_known else 0.0
    ioc_points = 0.5 if ioc_count > 0 else 0.0
    
    net_points = 0.0
    if attack_vector == "NETWORK": net_points += 0.5
    if attack_complexity == "LOW": net_points += 0.5
    
    priority_score = min(10.0, cvss_points + kev_points + epss_points + ransomware_points + ioc_points + net_points)
    
    if priority_score >= 8.5:
        priority_rating = "IMMEDIATE"
    elif priority_score >= 7.0:
        priority_rating = "CRITICAL"
    elif priority_score >= 5.0:
        priority_rating = "HIGH"
    else:
        priority_rating = "MEDIUM"
    
    return priority_score, priority_rating

# ─── 6. AI Analysis via Gemini ──────────────────────────────────────────────
def parse_json_response(text):
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.endswith("```"):
        text = text[:-3]
    return json.loads(text.strip())

def analyze_batch_with_gemini(cves, start_idx, end_idx):
    cves_input = []
    for c in cves[start_idx:end_idx]:
        cves_input.append({
            "id": c["id"],
            "description": c["description"],
            "score": c["score"],
            "severity": c["severity"],
            "cwe_id": c.get("cwe_id", "N/A"),
            "attack_vector": c.get("attack_vector", "UNKNOWN"),
            "priority_rating": c["priority_rating"],
            "in_cisa_kev": "Yes" if c["in_cisa_kev"] else "No",
        })

    prompt = f"""
    You are a SecOps specialist. Analyze these {len(cves_input)} vulnerabilities.
    
    Input JSON:
    {json.dumps(cves_input)}
    
    For each CVE, return a JSON array containing objects with:
    [
      {{
        "id": "CVE-XXXX-XXXX",
        "setor": "Windows/Linux/Web/Database/Network/Mobile/Cloud/Other",
        "software": "Affected software name (e.g. Microsoft Exchange, Apache)",
        "tem_patch": "sim or não (deduce if patch is available)",
        "exploitabilidade": "Alta, Média or Baixa",
        "resumo_o_que_e": "1 concise sentence explaining the flaw.",
        "resumo_quem_afeta": "1 concise sentence listing who is vulnerable.",
        "resumo_o_que_fazer": "1 concise sentence with the immediate recommended action."
      }}
    ]
    Return valid JSON only. Keep the summaries very professional and direct.
    """
    try:
        response = model.generate_content(prompt)
        return parse_json_response(response.text)
    except Exception as e:
        try:
            time.sleep(15)
            response = model.generate_content(prompt)
            return parse_json_response(response.text)
        except Exception:
            return None

# ─── 7. PDF Report Generation (fpdf2) ───────────────────────────────────────
class PDF(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 14)
        self.cell(0, 10, "Sentinel SecOps - Threat Intelligence Report", border=False, ln=True, align="C")
        self.line(10, 20, 200, 20)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

def generate_pdf_report(cves_analyzed, date_str, hour_str, status_text):
    os.makedirs("pdf_reports", exist_ok=True)
    filename = f"pdf_reports/Report_{date_str}_{hour_str.replace(':', '-')}.pdf"
    
    pdf = PDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Metadata
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(0, 6, f"Generation Date: {date_str} {hour_str} (BRT)", ln=True)
    pdf.cell(0, 6, f"Threat Status: {status_text}", ln=True)
    pdf.cell(0, 6, f"Total Critical/High CVEs: {len(cves_analyzed)}", ln=True)
    pdf.ln(10)
    
    if not cves_analyzed:
        pdf.set_font("helvetica", "I", 12)
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 10, "No CRITICAL or HIGH vulnerabilities detected in the last cycle.", ln=True)
    else:
        for item in cves_analyzed:
            cve = item["cve"]
            an = item["analysis_raw"]
            
            # Header block for the CVE
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 8, f"{cve['id']} - {an.get('software', 'N/A')}", ln=True, align="L")
            
            # Severity metrics
            pdf.set_font("helvetica", "", 10)
            pdf.set_text_color(50, 50, 50)
            
            metrics_line = (
                f"CVSS: {cve['score']} ({cve['severity']}) | "
                f"Priority: {cve['priority_rating']} ({cve['priority_score']:.1f}) | "
                f"EPSS: {cve['epss_data'].get('epss', 0.0)*100:.2f}%"
            )
            pdf.cell(0, 6, metrics_line, ln=True)
            
            threat_line = (
                f"CISA KEV: {'Yes' if cve['in_cisa_kev'] else 'No'} | "
                f"Ransomware: {'Known' if cve.get('ransomware_known') else 'Unknown'} | "
                f"IOCs: {cve.get('ioc_count', 0)}"
            )
            pdf.cell(0, 6, threat_line, ln=True)
            
            tech_line = (
                f"Vector: {cve.get('attack_vector', 'UNKNOWN')} | "
                f"Complexity: {cve.get('attack_complexity', 'UNKNOWN')} | "
                f"CWE: {cve.get('cwe_id', 'N/A')} | "
                f"Patch: {'Available' if an.get('tem_patch') == 'sim' else 'Pending'}"
            )
            pdf.cell(0, 6, tech_line, ln=True)
            
            # Textual analysis
            pdf.ln(3)
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(25, 5, "Summary:")
            pdf.set_font("helvetica", "", 10)
            pdf.multi_cell(0, 5, an.get("resumo_o_que_e", "N/A"))
            
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(25, 5, "Impact:")
            pdf.set_font("helvetica", "", 10)
            pdf.multi_cell(0, 5, an.get("resumo_quem_afeta", "N/A"))
            
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(35, 5, "Recommendation:")
            pdf.set_font("helvetica", "", 10)
            pdf.multi_cell(0, 5, an.get("resumo_o_que_fazer", "N/A"))
            
            pdf.ln(5)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)

    pdf.output(filename)
    return filename

# ─── 8. Minimal Dashboard Generator (Single Index) ──────────────────────────
def _build_cve_card(item):
    cve = item["cve"]
    an = item["analysis_raw"]
    
    return f'''
    <div class="card" style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; background: #fff;">
        <h3 style="margin-top: 0; color: #0f172a;">{cve['id']} - {an.get('software', 'N/A')}</h3>
        <p style="font-size: 0.9em; color: #475569; margin: 4px 0;">
            <strong>CVSS:</strong> {cve['score']} ({cve['severity']}) |
            <strong>Priority:</strong> {cve['priority_rating']} |
            <strong>EPSS:</strong> {cve['epss_data'].get('epss', 0.0)*100:.2f}%
        </p>
        <p style="font-size: 0.9em; color: #475569; margin: 4px 0;">
            <strong>CISA KEV:</strong> {'Yes' if cve['in_cisa_kev'] else 'No'} |
            <strong>Ransomware:</strong> {'Known' if cve.get('ransomware_known') else 'Unknown'}
        </p>
        <p style="margin-bottom: 4px;"><strong>Summary:</strong> {an.get('resumo_o_que_e', '')}</p>
        <p style="margin-top: 0;"><strong>Action:</strong> {an.get('resumo_o_que_fazer', '')}</p>
    </div>
    '''

def generate_html_dashboard(cves_analyzed, date_str, hour_str, status_text):
    os.makedirs("dashboards", exist_ok=True)
    filepath = "index.html"
    
    cards_html = ""
    if not cves_analyzed:
        cards_html = "<p>No CRITICAL or HIGH vulnerabilities detected in the last cycle.</p>"
    else:
        cards_html = "\n".join(_build_cve_card(item) for item in cves_analyzed)
        
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel SecOps - Latest Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #334155; max-width: 900px; margin: 0 auto; padding: 2rem; }}
        header {{ margin-bottom: 2rem; border-bottom: 1px solid #cbd5e1; padding-bottom: 1rem; }}
    </style>
</head>
<body>
    <header>
        <h1 style="color: #0f172a;">Sentinel SecOps Threat Dashboard</h1>
        <p><strong>Date:</strong> {date_str} {hour_str}</p>
        <p><strong>Status:</strong> {status_text}</p>
        <p><strong>Total Tracked:</strong> {len(cves_analyzed)}</p>
    </header>
    <main>
        {cards_html}
    </main>
</body>
</html>"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    return filepath

# ─── 9. CSV Update ──────────────────────────────────────────────────────────
def update_csv(cves_analyzed, date_str, hour_str):
    file_exists = os.path.exists(CSV_PATH)
    with open(CSV_PATH, mode="a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "data", "hora", "cve_id", "score", "severidade",
                "priority_score", "priority_rating", "in_cisa_kev", "epss",
                "cwe_id", "attack_vector", "attack_complexity",
                "ransomware_known", "ioc_count",
                "setor", "software", "tem_patch", "exploitabilidade", "resumo"
            ])
            
        for item in cves_analyzed:
            cve = item["cve"]
            an = item["analysis_raw"]
            writer.writerow([
                date_str, hour_str, cve["id"], cve["score"], cve["severity"],
                f"{cve['priority_score']:.1f}", cve["priority_rating"],
                cve["in_cisa_kev"], cve["epss_data"].get("epss", 0.0),
                cve.get("cwe_id", "N/A"), cve.get("attack_vector", "UNKNOWN"),
                cve.get("attack_complexity", "UNKNOWN"),
                "sim" if cve.get("ransomware_known") else "não",
                cve.get("ioc_count", 0), an.get("setor", "Other"),
                an.get("software", "N/A"), an.get("tem_patch", "não"),
                an.get("exploitabilidade", "Média"), an.get("resumo_o_que_e", "")
            ])

# ─── 10. Update README ──────────────────────────────────────────────────────
def update_readme(date_str, hour_str, count_cves, pdf_file, status_text):
    print("Updating README.md...")
    try:
        with open("README.md", "r", encoding="utf-8") as f:
            content = f.read()

        new_status = (
            f"**Last Update:** {date_str} {hour_str} (BRT)\n\n"
            f"**Network Status:** {status_text}\n\n"
            f"**Critical CVEs Today:** {count_cves}\n\n"
            f"**[Download Latest PDF Report]({pdf_file})**\n\n"
            f"**[View Minimal HTML Dashboard](index.html)**\n\n"
        )

        start_idx = content.find("<!-- STATUS_START -->")
        end_idx = content.find("<!-- STATUS_END -->")
        
        if start_idx != -1 and end_idx != -1:
            start_idx += len("<!-- STATUS_START -->\n")
            content = content[:start_idx] + new_status + content[end_idx:]

        with open("README.md", "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        print(f"Error updating README: {e}")

# ─── 11. MAIN FLOW ──────────────────────────────────────────────────────────
def main():
    print("Starting Sentinel SecOps Pipeline")
    migrate_csv()
    
    now_br = datetime.now(timezone.utc) - timedelta(hours=3)
    date_str = now_br.strftime("%Y-%m-%d")
    hour_str = now_br.strftime("%H:%M")
    
    raw_vulnerabilities = get_cves()
    
    if not raw_vulnerabilities:
        pdf_file = generate_pdf_report([], date_str, hour_str, "SECURE")
        generate_html_dashboard([], date_str, hour_str, "SECURE")
        update_readme(date_str, hour_str, 0, pdf_file, "SECURE - No Critical Alerts")
        return

    critical_cves = filter_critical(raw_vulnerabilities)
    
    if not critical_cves:
        pdf_file = generate_pdf_report([], date_str, hour_str, "SECURE")
        generate_html_dashboard([], date_str, hour_str, "SECURE")
        update_readme(date_str, hour_str, 0, pdf_file, "SECURE - Only Low Severity Alerts")
        return

    cve_ids = [c["id"] for c in critical_cves]
    kev_data = get_cisa_kev_cves()
    epss_scores = get_epss_scores(cve_ids)
    threatfox_data = get_threatfox_iocs(cve_ids)
    ghsa_data = get_github_advisories(cve_ids)

    for cve in critical_cves:
        cve_id = cve["id"]
        cve["in_cisa_kev"] = cve_id in kev_data
        cve["ransomware_known"] = kev_data.get(cve_id, {}).get("ransomware_known", "Unknown") == "Known"
        cve["epss_data"] = epss_scores.get(cve_id, {"epss": 0.0, "percentile": 0.0})
        cve["ioc_count"] = threatfox_data.get(cve_id, {"count": 0}).get("count", 0)
        
        priority_score, priority_rating = calculate_priority_score(
            cve["score"], cve["in_cisa_kev"], cve["epss_data"],
            cve["ransomware_known"], cve["ioc_count"],
            cve.get("attack_vector", "UNKNOWN"),
            cve.get("attack_complexity", "UNKNOWN")
        )
        cve["priority_score"] = priority_score
        cve["priority_rating"] = priority_rating

    cves_analyzed = []
    batch_size = 10
    for i in range(0, len(critical_cves), batch_size):
        end_idx = min(i + batch_size, len(critical_cves))
        gemini_results = analyze_batch_with_gemini(critical_cves, i, end_idx)
        
        if gemini_results:
            lookup = {r["id"]: r for r in gemini_results if "id" in r}
            for cve in critical_cves[i:end_idx]:
                if cve["id"] in lookup:
                    cves_analyzed.append({
                        "cve": cve,
                        "analysis_raw": lookup[cve["id"]]
                    })
        time.sleep(3)

    update_csv(cves_analyzed, date_str, hour_str)
    
    status_text = "ATTENTION"
    if any(item["cve"]["priority_rating"] == "IMMEDIATE" for item in cves_analyzed):
        status_text = "CRITICAL - Immediate Action Required"
    elif any(item["cve"]["severity"] == "CRITICAL" for item in cves_analyzed):
        status_text = "HIGH ALERT"

    pdf_file = generate_pdf_report(cves_analyzed, date_str, hour_str, status_text)
    generate_html_dashboard(cves_analyzed, date_str, hour_str, status_text)
    update_readme(date_str, hour_str, len(cves_analyzed), pdf_file, status_text)

if __name__ == "__main__":
    main()
