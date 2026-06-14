import os
import requests
import json
import time
import csv
from datetime import datetime, timezone, timedelta
import google.generativeai as genai
from collections import OrderedDict
from fpdf import FPDF

# Import v2.0 custom modules
from scripts.feeds.osv import check_osv_cve
from scripts.feeds.exploitdb import check_exploitdb_cve
from scripts.enrichment.mitre_mapper import get_mitre_technique
from scripts.output.audio_generator import generate_audio_briefing
from scripts.output.stix_exporter import export_to_stix
from scripts.output.rss_generator import generate_rss_feed

# ==========================================
# CONFIGURATION AND API KEYS
# ==========================================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
NVD_API_KEY    = os.getenv("NVD_API_KEY")

genai.configure(api_key=GEMINI_API_KEY)

# Using gemini-3.5-flash as principal model
MODEL_NAME = "gemini-3.1-flash"
model = genai.GenerativeModel(MODEL_NAME)

CSV_PATH = os.path.join("dashboards", "historico.csv")

# ─── 1. CSV Migration & Initial Setup ────────────────────────────────────────
def migrate_csv():
    os.makedirs("dashboards", exist_ok=True)
    
    # 33 columns including new v2.0 fields
    new_header = [
        "data", "hora", "cve_id", "score", "severidade",
        "priority_score", "priority_rating", "in_cisa_kev", "epss",
        "cwe_id", "attack_vector", "attack_complexity",
        "ransomware_known", "ioc_count",
        "setor", "software", "tem_patch", "exploitabilidade", "resumo",
        "score_previous", "score_current", "score_updated_at", "score_trend",
        "sla_deadline", "sla_label", "sla_status",
        "mitre_technique_id", "mitre_technique_name", "mitre_tactic",
        "exploitdb_has_exploit", "exploitdb_exploit_count",
        "osv_confirmed", "osv_ecosystems"
    ]
    
    if not os.path.exists(CSV_PATH):
        with open(CSV_PATH, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(new_header)
        return

    # Check if header matches size
    rows = []
    with open(CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return
            
        if len(header) < len(new_header):
            for row in reader:
                rows.append(row)
                
            print(f"Migrating {CSV_PATH} to v2.0 header...")
            with open(CSV_PATH, mode="w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(new_header)
                for row in rows:
                    # Pad the row to new header length
                    padded_row = row + [""] * (len(new_header) - len(row))
                    writer.writerow(padded_row)

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
                
        score = 0.0
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0]["cvssData"]
                score = float(cvss_data.get("baseScore", 0.0))
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
        time.sleep(0.1)
    return results

# ─── 5. Hybrid Priority Scoring ─────────────────────────────────────────────
def calculate_priority_score(cvss_score, in_cisa_kev, epss_data, ransomware_known, ioc_count, attack_vector, attack_complexity, exploitdb_has_exploit):
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
    
    # Exploit-DB Match Bonus of +1.5 points
    exploit_points = 1.5 if exploitdb_has_exploit else 0.0
    
    priority_score = min(10.0, cvss_points + kev_points + epss_points + ransomware_points + ioc_points + net_points + exploit_points)
    
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

def analyze_batch_with_gemini(cves, start_idx, end_idx, assets_config):
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
            "exploitdb_has_exploit": "Yes" if c.get("exploitdb_has_exploit") else "No",
        })

    # System instruction adhering to Parte 8
    system_instruction = """Você é um analista sênior de segurança cibernética (SOC Tier 3) da empresa brasileira de threat intelligence Sentinel SecOps.
Você recebe dados brutos e técnicos sobre vulnerabilidades (CVEs) coletados de múltiplas fontes globais e precisa transformar esses dados em inteligência acionável.

REGRAS DE RESPOSTA:
- Responda EXCLUSIVAMENTE em JSON válido, contendo um array de objetos JSON para cada uma das CVEs analisadas. O array deve conter objetos correspondentes.
- Use português brasileiro em todos os campos de texto.
- Seja direto e objetivo — o público é técnico mas o relatório será lido por executivos.
- Nunca use jargão sem explicação, nunca use "é importante notar que", nunca use rodeios.
- Se uma informação não estiver disponível, use null, não invente dados.
- Mantenha a mesma chave 'cve_id' em cada objeto para identificar a qual CVE se refere.

ESTRUTURA DE CADA OBJETO JSON:
{
  "cve_id": "CVE-ID analisada (Ex: CVE-2023-1234)",
  "software_affected": "Nome do software/produto afetado e versões vulneráveis",
  "vulnerability_type": "Tipo técnico da falha (ex: Buffer Overflow, SQL Injection, RCE)",
  "exploitability": "TRIVIAL | MODERATE | COMPLEX",
  "attack_vector": "NETWORK | ADJACENT | LOCAL | PHYSICAL",
  "executive_summary": "2 a 3 frases em português explicando o que é a falha, quem ela afeta, e qual o risco real para a organização. Sem jargão técnico.",
  "technical_summary": "2 a 3 frases técnicas sobre o mecanismo da falha, vetor de ataque, e impacto técnico.",
  "affected_components": ["lista", "de", "componentes", "específicos"],
  "mitre_technique_id": "T1190 (ou a técnica mais relevante)",
  "mitre_technique_name": "Nome da técnica MITRE ATT&CK",
  "mitre_tactic": "Tática pai (ex: Initial Access, Execution, Privilege Escalation)",
  "immediate_action": "Plano de ação imediato em até 3 passos numerados. Seja específico: comandos, patches, links de vendor advisory.",
  "affects_our_stack": true ou false baseado no tech stack da organização fornecido,
  "affected_assets": ["lista de ativos do tech stack que são afetados, ou array vazio"],
  "business_impact": "CRITICAL | HIGH | MEDIUM | LOW",
  "patch_available": true ou false,
  "patch_reference": "URL ou referência do patch/advisory do fabricante, ou null",
  "cvss_interpretation": "Explicação em 1 frase do que o score CVSS significa na prática para essa CVE específica"
}"""

    prompt = f"""
    Organização Monitorada Assets Profile:
    {json.dumps(assets_config)}
    
    Analise estas {len(cves_input)} vulnerabilidades e retorne o array de objetos JSON descritos:
    {json.dumps(cves_input)}
    """
    try:
        local_model = genai.GenerativeModel(MODEL_NAME, system_instruction=system_instruction)
        response = local_model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        return parse_json_response(response.text)
    except Exception as e:
        print(f"Gemini API Error: {e}")
        try:
            time.sleep(10)
            local_model = genai.GenerativeModel(MODEL_NAME, system_instruction=system_instruction)
            response = local_model.generate_content(
                prompt,
                generation_config={"response_mime_type": "application/json"}
            )
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
            pdf.cell(0, 8, f"{cve['id']} - {an.get('software_affected', 'N/A')}", ln=True, align="L")
            
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
                f"IOCs: {cve.get('ioc_count', 0)} | "
                f"Exploit DB: {'Yes' if cve.get('exploitdb_has_exploit') else 'No'}"
            )
            pdf.cell(0, 6, threat_line, ln=True)
            
            tech_line = (
                f"Vector: {cve.get('attack_vector', 'UNKNOWN')} | "
                f"Complexity: {cve.get('attack_complexity', 'UNKNOWN')} | "
                f"CWE: {cve.get('cwe_id', 'N/A')} | "
                f"Patch: {'Available' if an.get('patch_available') else 'Pending'}"
            )
            pdf.cell(0, 6, tech_line, ln=True)
            
            # ATT&CK mapping information
            mitre_line = (
                f"MITRE ATT&CK: {cve.get('mitre_technique_id', 'N/A')} - {cve.get('mitre_technique_name', 'N/A')} "
                f"({cve.get('mitre_tactic', 'N/A')})"
            )
            pdf.cell(0, 6, mitre_line, ln=True)
            
            # Textual analysis
            pdf.ln(3)
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(25, 5, "Summary:")
            pdf.set_font("helvetica", "", 10)
            pdf.multi_cell(0, 5, an.get("executive_summary", "N/A"))
            
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(25, 5, "Technical:")
            pdf.set_font("helvetica", "", 10)
            pdf.multi_cell(0, 5, an.get("technical_summary", "N/A"))
            
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(35, 5, "Recommendation:")
            pdf.set_font("helvetica", "", 10)
            pdf.multi_cell(0, 5, an.get("immediate_action", "N/A"))
            
            pdf.ln(5)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)

    pdf.output(filename)
    return filename

# ─── 8. Enhanced Dashboard HTML Builder ───────────────────────────────────────
def generate_html_dashboard(cves_analyzed, date_str, hour_str, status_text, assets_config):
    os.makedirs("dashboards", exist_ok=True)
    filepath = "index.html"
    
    # 7.1 Counters
    critical_today = sum(1 for item in cves_analyzed if float(item["cve"]["priority_score"]) >= 9.0)
    ransomware_linked = sum(1 for item in cves_analyzed if item["cve"].get("ransomware_known"))
    has_exploit = sum(1 for item in cves_analyzed if item["cve"].get("exploitdb_has_exploit"))
    sla_24h = sum(1 for item in cves_analyzed if item["cve"].get("sla_label") == "CRITICAL")
    
    # 7.3 Threat of the week
    threat_of_week_html = ""
    if cves_analyzed:
        top_vuln = max(cves_analyzed, key=lambda x: float(x["cve"]["priority_score"]))
        top_cve = top_vuln["cve"]
        top_an = top_vuln["analysis_raw"]
        
        threat_of_week_html = f"""
        <div class="threat-of-week-card">
            <div class="tow-header">
                <span class="tow-badge">CRITICAL THREAT OF THE WEEK</span>
                <h2>{top_cve['id']} - {top_an.get('software_affected', 'N/A')}</h2>
            </div>
            <div class="tow-body">
                <div class="tow-metric">
                    <span class="tow-label">Priority Score: {top_cve['priority_score']:.1f}/10</span>
                    <div class="progress-bar-container">
                        <div class="progress-bar" style="width: {top_cve['priority_score']*10}%"></div>
                    </div>
                </div>
                <p><strong>Resumo Executivo:</strong> {top_an.get('executive_summary', '')}</p>
                <p><strong>Técnica MITRE:</strong> {top_cve.get('mitre_technique_id', 'N/A')} - {top_cve.get('mitre_technique_name', 'N/A')} ({top_cve.get('mitre_tactic', 'N/A')})</p>
                <div class="tow-action">
                    <strong>Plano de Ação Recomendado:</strong>
                    <p>{top_an.get('immediate_action', '')}</p>
                </div>
            </div>
        </div>
        """
    
    # Main Table rows
    table_rows = ""
    if not cves_analyzed:
        table_rows = """<tr><td colspan="9" style="text-align: center; padding: 20px; color: #94a3b8;">No CRITICAL or HIGH vulnerabilities detected in the last cycle.</td></tr>"""
    else:
        for item in cves_analyzed:
            cve = item["cve"]
            an = item["analysis_raw"]
            
            # Badge styles
            sla_class = f"badge-{cve.get('sla_label', 'low').lower()}"
            trend_val = cve.get("score_trend", "STABLE")
            trend_symbol = "—"
            trend_class = "trend-stable"
            if trend_val == "UP":
                trend_symbol = "▲"
                trend_class = "trend-up"
            elif trend_val == "DOWN":
                trend_symbol = "▼"
                trend_class = "trend-down"
                
            exploit_icon = "✓" if cve.get("exploitdb_has_exploit") else "✗"
            exploit_class = "yes" if cve.get("exploitdb_has_exploit") else "no"
            
            stack_icon = '<span class="badge badge-stack" style="background: rgba(234, 179, 8, 0.15); color: var(--yellow-warning); font-size: 0.7rem; margin-left: 0.4rem; padding: 0.1rem 0.3rem; border-radius: 4px;">STACK</span>' if cve.get("affects_our_stack") or an.get("affects_our_stack") else ""
            
            table_rows += f"""
            <tr id="cve-{cve['id']}">
                <td class="font-semibold">{cve['id']} {stack_icon}</td>
                <td>{an.get('software_affected', 'N/A')}</td>
                <td><span class="score-pill score-{int(cve['priority_score'])}">{cve['priority_score']:.1f}</span></td>
                <td>{cve.get('mitre_tactic', 'N/A')}</td>
                <td><span class="badge {sla_class}">{cve.get('sla_label', 'LOW')}</span></td>
                <td class="exploit-col {exploit_class}">{exploit_icon}</td>
                <td class="{trend_class}">{trend_symbol}</td>
                <td>{'Yes' if cve.get('ransomware_known') else 'No'}</td>
                <td><button class="btn-detail" onclick="showDetail('{cve['id']}')">View Details</button></td>
            </tr>
            <tr id="detail-{cve['id']}" class="detail-row hidden">
                <td colspan="9">
                    <div class="detail-content">
                        <p><strong>Descrição Completa:</strong> {cve['description']}</p>
                        <p><strong>Resumo Técnico:</strong> {an.get('technical_summary', 'N/A')}</p>
                        <p><strong>Interpretação CVSS:</strong> {an.get('cvss_interpretation', 'N/A')}</p>
                        <p><strong>CWE ID:</strong> {cve.get('cwe_id', 'N/A')}</p>
                        <p><strong>OSV Confirmado:</strong> {'Sim' if cve.get('osv_confirmed') else 'Não'} (Ecosystems: {cve.get('osv_ecosystems', 'N/A')})</p>
                        <p><strong>Vetor de Ataque:</strong> {cve.get('attack_vector', 'UNKNOWN')} | Complexidade: {cve.get('attack_complexity', 'UNKNOWN')}</p>
                        <div class="action-block">
                            <strong>Ação Imediata Recomendada:</strong>
                            <p>{an.get('immediate_action', 'N/A')}</p>
                        </div>
                    </div>
                </td>
            </tr>
            """
            
    # System Prompt dynamic inject for SOC assistant chat
    chat_system_context = f"""Você é o SOC Assistant do Sentinel-SecOps, um analista virtual de segurança cibernética integrado ao dashboard de Threat Intelligence.
CONTEÚDO DO PAINEL ATUAL (gerado em {date_str} {hour_str}):
- Total de CVEs monitoradas hoje: {len(cves_analyzed)}
- CVEs críticas (score >= 9.0): {critical_today}
- CVEs com ransomware associado: {ransomware_linked}
- CVEs com exploit público: {has_exploit}
- Top 3 ameaças do ciclo: {', '.join([c['cve']['id'] for c in cves_analyzed[:3]]) if cves_analyzed else 'Nenhuma'}
- Stack tecnológico monitorado: {', '.join(assets_config.get('tech_stack', []))}

REGRAS DE COMPORTAMENTO:
- Responda sempre em português brasileiro.
- Seja direto e técnico, mas acessível.
- Respostas curtas e objetivas — máximo 4 parágrafos.
- Quando perguntado sobre uma CVE específica, use o contexto do painel ou seu conhecimento sobre ela.
- Nunca invente dados sobre CVEs que não estejam no contexto fornecido; se não souber, diga que a informação não está disponível no ciclo atual.
- Se o usuário perguntar algo fora de segurança, redirecione educadamente para o escopo do painel.
"""

    # Read config assets details
    tech_stack_str = ", ".join(assets_config.get("tech_stack", []))

    # Read api key and encode in Base64 to obfuscate it from simple automated code scanners
    import base64
    raw_key = os.environ.get("GEMINI_API_KEY", "")
    api_key_b64 = base64.b64encode(raw_key.encode("utf-8")).decode("utf-8")

    html_template = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel SecOps — Pedroxious Lab</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>
    <style>
        /* ═══════════════════════════════════════════════════════
           DESIGN TOKENS — Pedroxious Lab palette
        ═══════════════════════════════════════════════════════ */
        :root {{
            --bg:           #07080c;
            --bg-sidebar:   #0a0b10;
            --bg-card:      #0d0f17;
            --bg-input:     #0f111a;
            --bg-hover:     rgba(255,255,255,0.03);
            --border:       #1a1e2f;
            --border-soft:  rgba(255,255,255,0.05);

            --green:        #10b981;
            --green-dim:    rgba(16,185,129,0.12);
            --green-glow:   rgba(16,185,129,0.08);
            --purple:       #8b5cf6;
            --cyan:         #06b6d4;
            --blue:         #3b82f6;

            --text:         #f1f5f9;
            --text-muted:   #64748b;
            --text-sub:     #94a3b8;

            --red:          #ef4444;
            --yellow:       #eab308;
            --ok:           #22c55e;

            --radius-sm:    6px;
            --radius-md:    10px;
            --radius-lg:    16px;
            --radius-xl:    24px;
            --sidebar-w:    260px;
        }}

        *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

        html, body {{ height: 100%; }}

        body {{
            background: var(--bg);
            color: var(--text);
            font-family: 'Outfit', sans-serif;
            display: flex;
            overflow: hidden;
        }}

        /* ═══════════════════════════════════════════════════════
           SIDEBAR
        ═══════════════════════════════════════════════════════ */
        .sidebar {{
            width: var(--sidebar-w);
            min-width: var(--sidebar-w);
            height: 100vh;
            background: var(--bg-sidebar);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            padding: 0;
            position: relative;
            z-index: 10;
            transition: transform 0.28s cubic-bezier(.4,0,.2,1);
        }}

        .sidebar-logo {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 20px 18px 16px;
            border-bottom: 1px solid var(--border);
        }}

        .sidebar-logo-icon {{
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: var(--green-dim);
            border: 1px solid rgba(16,185,129,0.25);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--green);
            flex-shrink: 0;
        }}

        .sidebar-logo-icon svg {{ width: 16px; height: 16px; }}

        .sidebar-logo-text {{
            font-size: 0.88rem;
            font-weight: 700;
            letter-spacing: 0.3px;
            background: linear-gradient(90deg, var(--green), var(--cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            line-height: 1.1;
        }}

        .sidebar-logo-sub {{
            font-size: 0.65rem;
            color: var(--text-muted);
            font-weight: 400;
            -webkit-text-fill-color: var(--text-muted);
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }}

        .sidebar-section {{
            padding: 12px 10px 4px;
        }}

        .sidebar-section-label {{
            font-size: 0.65rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            padding: 0 8px 8px;
        }}

        .sidebar-btn {{
            display: flex;
            align-items: center;
            gap: 10px;
            width: 100%;
            padding: 9px 10px;
            border-radius: var(--radius-sm);
            background: transparent;
            border: none;
            color: var(--text-sub);
            font-family: 'Outfit', sans-serif;
            font-size: 0.85rem;
            cursor: pointer;
            text-align: left;
            transition: background 0.15s, color 0.15s;
            text-decoration: none;
        }}

        .sidebar-btn:hover {{ background: var(--bg-hover); color: var(--text); }}
        .sidebar-btn.active {{ background: var(--green-dim); color: var(--green); }}

        .sidebar-btn svg {{ width: 15px; height: 15px; flex-shrink: 0; }}

        .sidebar-btn-new {{
            display: flex;
            align-items: center;
            gap: 10px;
            width: calc(100% - 20px);
            margin: 14px 10px;
            padding: 9px 14px;
            border-radius: var(--radius-md);
            background: var(--green-dim);
            border: 1px solid rgba(16,185,129,0.2);
            color: var(--green);
            font-family: 'Outfit', sans-serif;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .sidebar-btn-new:hover {{
            background: rgba(16,185,129,0.2);
            border-color: rgba(16,185,129,0.4);
        }}

        .sidebar-btn-new svg {{ width: 14px; height: 14px; }}

        .sidebar-history {{
            flex: 1;
            overflow-y: auto;
            padding: 0 10px 10px;
        }}

        .sidebar-history::-webkit-scrollbar {{ width: 3px; }}
        .sidebar-history::-webkit-scrollbar-track {{ background: transparent; }}
        .sidebar-history::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}

        .history-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 10px;
            border-radius: var(--radius-sm);
            cursor: pointer;
            color: var(--text-muted);
            font-size: 0.8rem;
            transition: background 0.12s, color 0.12s;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .history-item:hover {{ background: var(--bg-hover); color: var(--text-sub); }}
        .history-item svg {{ width: 12px; height: 12px; flex-shrink: 0; opacity: 0.5; }}

        .sidebar-footer {{
            padding: 12px 10px;
            border-top: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .sidebar-user {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 10px;
            border-radius: var(--radius-sm);
            cursor: pointer;
            transition: background 0.15s;
        }}

        .sidebar-user:hover {{ background: var(--bg-hover); }}

        .sidebar-avatar {{
            width: 28px;
            height: 28px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--purple), var(--cyan));
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.7rem;
            font-weight: 700;
            color: white;
            flex-shrink: 0;
        }}

        .sidebar-user-info {{ display: flex; flex-direction: column; }}
        .sidebar-user-name {{ font-size: 0.82rem; font-weight: 600; color: var(--text); }}
        .sidebar-user-role {{ font-size: 0.68rem; color: var(--text-muted); }}

        /* ═══════════════════════════════════════════════════════
           MAIN AREA
        ═══════════════════════════════════════════════════════ */
        .main {{
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100vh;
            overflow: hidden;
            position: relative;
        }}

        /* ─── Top bar ─────────────────────────────────────── */
        .topbar {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 24px;
            height: 56px;
            border-bottom: 1px solid var(--border);
            flex-shrink: 0;
            background: var(--bg);
        }}

        .topbar-left {{ display: flex; align-items: center; gap: 12px; }}

        .btn-hamburger {{
            display: none;
            align-items: center;
            justify-content: center;
            width: 32px; height: 32px;
            border-radius: var(--radius-sm);
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
        }}

        .btn-hamburger:hover {{ background: var(--bg-hover); color: var(--text); }}
        .btn-hamburger svg {{ width: 18px; height: 18px; }}

        .topbar-title {{
            font-size: 0.88rem;
            font-weight: 600;
            color: var(--text-sub);
        }}

        .topbar-right {{ display: flex; align-items: center; gap: 8px; }}

        .topbar-badge {{
            font-size: 0.72rem;
            font-weight: 600;
            padding: 3px 10px;
            border-radius: 20px;
            border: 1px solid var(--border);
            color: var(--text-muted);
            background: rgba(255,255,255,0.02);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .status-dot {{
            width: 7px; height: 7px;
            border-radius: 50%;
            background: var(--green);
            box-shadow: 0 0 6px var(--green);
            animation: pulse-dot 2s infinite;
        }}

        @keyframes pulse-dot {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.4; }}
        }}

        /* ─── Scrollable content area ─────────────────────── */
        .content-scroll {{
            flex: 1;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
        }}

        .content-scroll::-webkit-scrollbar {{ width: 4px; }}
        .content-scroll::-webkit-scrollbar-track {{ background: transparent; }}
        .content-scroll::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}

        /* ═══════════════════════════════════════════════════════
           CHAT SECTION — fills 100vh first
        ═══════════════════════════════════════════════════════ */
        .chat-section {{
            min-height: calc(100vh - 56px);
            display: flex;
            flex-direction: column;
            position: relative;
        }}

        /* Welcome screen */
        .chat-welcome {{
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px 24px 20px;
            text-align: center;
        }}

        .chat-welcome.hidden {{ display: none; }}

        .aeris-orb {{
            width: 56px; height: 56px;
            border-radius: 50%;
            background: radial-gradient(circle at 35% 35%, rgba(16,185,129,0.3), rgba(6,182,212,0.1));
            border: 1px solid rgba(16,185,129,0.25);
            display: flex; align-items: center; justify-content: center;
            margin-bottom: 20px;
            position: relative;
        }}

        .aeris-orb::after {{
            content: '';
            position: absolute;
            inset: -4px;
            border-radius: 50%;
            border: 1px solid rgba(16,185,129,0.08);
        }}

        .aeris-orb svg {{ width: 24px; height: 24px; color: var(--green); }}

        .chat-welcome h1 {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--text);
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }}

        .chat-welcome p {{
            font-size: 0.92rem;
            color: var(--text-sub);
            max-width: 420px;
            line-height: 1.55;
        }}

        /* Suggestion chips */
        .suggestion-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
            width: 100%;
            max-width: 560px;
            margin-top: 28px;
        }}

        .chip {{
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 12px 14px;
            border-radius: var(--radius-md);
            background: var(--bg-card);
            border: 1px solid var(--border);
            cursor: pointer;
            font-family: 'Outfit', sans-serif;
            font-size: 0.82rem;
            color: var(--text-sub);
            text-align: left;
            transition: all 0.15s;
            line-height: 1.4;
        }}

        .chip:hover {{
            background: var(--bg-hover);
            border-color: rgba(16,185,129,0.2);
            color: var(--text);
        }}

        .chip svg {{ width: 14px; height: 14px; color: var(--green); flex-shrink: 0; margin-top: 1px; }}

        /* Messages area */
        .chat-messages {{
            flex: 1;
            display: none;
            flex-direction: column;
            gap: 0;
            padding: 24px 0 16px;
            overflow-y: auto;
        }}

        .chat-messages.visible {{ display: flex; }}
        .chat-messages::-webkit-scrollbar {{ width: 4px; }}
        .chat-messages::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}

        /* Message rows */
        .msg-row {{
            display: flex;
            padding: 8px 24px;
            animation: msg-in 0.18s ease;
        }}

        @keyframes msg-in {{
            from {{ opacity: 0; transform: translateY(6px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}

        .msg-row.user {{ justify-content: flex-end; }}
        .msg-row.bot  {{ justify-content: flex-start; }}

        .msg-row.bot .msg-inner {{
            display: flex;
            align-items: flex-start;
            gap: 12px;
            max-width: 78%;
        }}

        .msg-row.user .msg-inner {{
            max-width: 72%;
        }}

        .bot-av {{
            width: 28px; height: 28px;
            border-radius: 50%;
            background: var(--green-dim);
            border: 1px solid rgba(16,185,129,0.2);
            display: flex; align-items: center; justify-content: center;
            flex-shrink: 0;
            margin-top: 2px;
            color: var(--green);
        }}

        .bot-av svg {{ width: 13px; height: 13px; }}

        .bubble {{
            padding: 11px 15px;
            border-radius: var(--radius-lg);
            font-size: 0.9rem;
            line-height: 1.6;
            word-wrap: break-word;
        }}

        .bubble.user-bubble {{
            background: var(--green);
            color: #07080c;
            font-weight: 500;
            border-bottom-right-radius: 4px;
        }}

        .bubble.bot-bubble {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text);
            border-bottom-left-radius: 4px;
        }}

        .msg-meta {{
            font-size: 0.68rem;
            color: var(--text-muted);
            margin-top: 4px;
            padding: 0 4px;
        }}

        /* Typing indicator */
        .typing-row {{ display: flex; align-items: flex-start; gap: 12px; padding: 8px 24px; }}

        .typing-dots {{
            display: flex; gap: 4px; align-items: center;
            padding: 14px 16px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            border-bottom-left-radius: 4px;
        }}

        .typing-dots span {{
            width: 5px; height: 5px;
            border-radius: 50%;
            background: var(--text-muted);
            animation: bounce 1.3s infinite ease-in-out both;
        }}

        .typing-dots span:nth-child(1) {{ animation-delay: -0.3s; }}
        .typing-dots span:nth-child(2) {{ animation-delay: -0.15s; }}

        @keyframes bounce {{
            0%, 80%, 100% {{ transform: scale(0.6); opacity: 0.4; }}
            40%            {{ transform: scale(1); opacity: 1; }}
        }}

        /* ─── Input bar ───────────────────────────────────── */
        .chat-input-area {{
            padding: 12px 20px 20px;
            background: var(--bg);
            border-top: 1px solid var(--border-soft);
            flex-shrink: 0;
        }}

        .chat-error {{
            display: flex; align-items: center; gap: 6px;
            font-size: 0.8rem; color: var(--red);
            margin-bottom: 8px; padding: 0 4px;
        }}

        .chat-error svg {{ width: 13px; height: 13px; }}

        .input-pill {{
            display: flex;
            align-items: flex-end;
            gap: 10px;
            padding: 10px 10px 10px 18px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: var(--radius-xl);
            transition: border-color 0.2s;
        }}

        .input-pill:focus-within {{
            border-color: rgba(16,185,129,0.35);
            box-shadow: 0 0 0 3px rgba(16,185,129,0.05);
        }}

        .input-pill textarea {{
            flex: 1;
            background: transparent;
            border: none;
            outline: none;
            color: var(--text);
            font-family: 'Outfit', sans-serif;
            font-size: 0.9rem;
            line-height: 1.5;
            resize: none;
            height: 22px;
            max-height: 140px;
            overflow-y: auto;
        }}

        .input-pill textarea::placeholder {{ color: var(--text-muted); }}
        .input-pill textarea::-webkit-scrollbar {{ width: 3px; }}
        .input-pill textarea::-webkit-scrollbar-thumb {{ background: var(--border); }}

        .input-pill-meta {{
            display: flex; align-items: center; gap: 8px; flex-shrink: 0;
        }}

        .input-workspace-tag {{
            font-size: 0.7rem;
            font-weight: 600;
            padding: 3px 10px;
            border-radius: 20px;
            background: rgba(255,255,255,0.04);
            border: 1px solid var(--border);
            color: var(--text-muted);
            white-space: nowrap;
        }}

        .btn-send {{
            width: 34px; height: 34px;
            border-radius: 50%;
            background: var(--green);
            border: none;
            color: #07080c;
            cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            transition: all 0.15s;
            flex-shrink: 0;
        }}

        .btn-send:hover {{ opacity: 0.88; transform: scale(1.05); }}
        .btn-send:active {{ transform: scale(0.95); }}
        .btn-send:disabled {{ background: var(--border); color: var(--text-muted); cursor: not-allowed; transform: none; }}
        .btn-send svg {{ width: 14px; height: 14px; }}

        .btn-spinner {{
            width: 14px; height: 14px;
            border: 2px solid rgba(7,8,12,0.2);
            border-top: 2px solid #07080c;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }}

        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}

        .input-footer {{
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 8px;
            gap: 6px;
        }}

        .quota-text {{
            font-size: 0.72rem;
            color: var(--text-muted);
            text-align: center;
        }}

        .quota-warn {{
            display: flex; align-items: center; gap: 4px;
            color: var(--yellow); font-size: 0.72rem;
        }}

        .quota-warn svg {{ width: 12px; height: 12px; }}

        /* ═══════════════════════════════════════════════════════
           SCROLL CUE
        ═══════════════════════════════════════════════════════ */
        .scroll-cue {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            padding: 6px 0 0;
            color: var(--text-muted);
            font-size: 0.72rem;
            cursor: pointer;
            transition: color 0.15s;
            flex-shrink: 0;
            border-top: 1px solid var(--border-soft);
        }}

        .scroll-cue:hover {{ color: var(--text-sub); }}
        .scroll-cue svg {{ width: 12px; height: 12px; animation: bob 2s ease-in-out infinite; }}

        @keyframes bob {{
            0%, 100% {{ transform: translateY(0); }}
            50%       {{ transform: translateY(3px); }}
        }}

        /* ═══════════════════════════════════════════════════════
           DASHBOARD SECTION
        ═══════════════════════════════════════════════════════ */
        .dashboard-section {{
            padding: 40px 24px 60px;
            display: flex;
            flex-direction: column;
            gap: 28px;
            border-top: 1px solid var(--border);
        }}

        .dash-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
        }}

        .dash-header-left {{ display: flex; align-items: center; gap: 12px; }}

        .dash-title {{
            font-size: 1.05rem;
            font-weight: 700;
            color: var(--text);
        }}

        .dash-subtitle {{ font-size: 0.8rem; color: var(--text-muted); margin-top: 2px; }}

        .dash-live-badge {{
            display: flex; align-items: center; gap: 6px;
            font-size: 0.68rem; font-weight: 600;
            padding: 3px 10px; border-radius: 20px;
            border: 1px solid rgba(16,185,129,0.25);
            background: var(--green-dim);
            color: var(--green);
            text-transform: uppercase; letter-spacing: 0.5px;
        }}

        .dash-pdf-link {{
            display: flex; align-items: center; gap: 6px;
            padding: 6px 12px; border-radius: var(--radius-sm);
            border: 1px solid var(--border);
            background: rgba(255,255,255,0.02);
            color: var(--text-sub);
            font-size: 0.78rem; font-weight: 500;
            text-decoration: none;
            transition: all 0.15s;
        }}

        .dash-pdf-link:hover {{ border-color: rgba(16,185,129,0.2); color: var(--green); }}
        .dash-pdf-link svg {{ width: 13px; height: 13px; }}

        /* ─── Metric cards grid ───────────────────────────── */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
        }}

        .metric-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 18px;
            position: relative;
            overflow: hidden;
            transition: transform 0.15s, border-color 0.15s;
        }}

        .metric-card:hover {{ transform: translateY(-1px); }}

        .metric-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
        }}

        .metric-card.red::before   {{ background: var(--red); }}
        .metric-card.purple::before {{ background: var(--purple); }}
        .metric-card.yellow::before {{ background: var(--yellow); }}
        .metric-card.cyan::before   {{ background: var(--cyan); }}

        .metric-label {{
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 10px;
            font-weight: 600;
        }}

        .metric-value {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--text);
            line-height: 1;
            font-family: 'JetBrains Mono', monospace;
        }}

        .metric-icon {{
            position: absolute;
            bottom: 14px; right: 14px;
            opacity: 0.08;
            color: var(--text);
            transition: opacity 0.2s;
        }}

        .metric-icon svg {{ width: 24px; height: 24px; }}
        .metric-card:hover .metric-icon {{ opacity: 0.2; }}

        /* ─── Threat of the Week ──────────────────────────── */
        .threat-card {{
            background: var(--bg-card);
            border: 1px solid rgba(239,68,68,0.2);
            border-radius: var(--radius-lg);
            padding: 22px 24px;
            position: relative;
            overflow: hidden;
        }}

        .threat-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 1px;
            background: linear-gradient(90deg, var(--red), transparent);
        }}

        .threat-header {{
            display: flex; align-items: center; justify-content: space-between;
            flex-wrap: wrap; gap: 10px; margin-bottom: 14px;
        }}

        .threat-badge {{
            font-size: 0.65rem; font-weight: 700;
            padding: 3px 10px; border-radius: 20px;
            background: rgba(239,68,68,0.1);
            border: 1px solid rgba(239,68,68,0.25);
            color: var(--red);
            text-transform: uppercase; letter-spacing: 0.8px;
        }}

        .threat-id {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem; font-weight: 700;
            color: var(--text);
        }}

        .threat-summary {{ font-size: 0.85rem; color: var(--text-sub); line-height: 1.55; margin-bottom: 14px; }}

        .threat-score-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }}

        .progress-track {{
            flex: 1; height: 5px;
            background: rgba(255,255,255,0.06);
            border-radius: 3px; overflow: hidden;
        }}

        .progress-fill {{
            height: 100%; border-radius: 3px;
            background: linear-gradient(90deg, var(--cyan), var(--red));
        }}

        .progress-label {{ font-size: 0.78rem; font-weight: 600; font-family: 'JetBrains Mono', monospace; color: var(--red); white-space: nowrap; }}

        .threat-action {{
            background: rgba(16,185,129,0.04);
            border-left: 2px solid var(--green);
            border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
            padding: 12px 14px;
        }}

        .threat-action strong {{ font-size: 0.78rem; color: var(--green); display: block; margin-bottom: 4px; font-weight: 600; }}
        .threat-action p {{ font-size: 0.82rem; color: var(--text-sub); line-height: 1.5; }}

        /* ─── Table ───────────────────────────────────────── */
        .table-wrapper {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            overflow-x: auto;
        }}

        .dash-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.83rem;
        }}

        .dash-table th {{
            padding: 12px 16px;
            background: rgba(0,0,0,0.2);
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }}

        .dash-table td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-soft);
            color: var(--text);
            vertical-align: middle;
        }}

        .dash-table tbody tr:last-child td {{ border-bottom: none; }}

        .dash-table tbody tr:hover td {{ background: var(--bg-hover); }}

        .cve-id-cell {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            font-weight: 500;
            color: var(--text);
        }}

        /* Score pill */
        .score-pill {{
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 0.78rem;
            padding: 3px 8px;
            border-radius: 5px;
            display: inline-block;
        }}

        .score-critical {{ background: rgba(239,68,68,0.12); color: var(--red); }}
        .score-high     {{ background: rgba(234,179,8,0.12);  color: var(--yellow); }}
        .score-medium   {{ background: rgba(59,130,246,0.12); color: var(--blue); }}
        .score-low      {{ background: rgba(100,116,139,0.12); color: var(--text-muted); }}

        /* SLA badge */
        .sla-badge {{
            font-size: 0.68rem; font-weight: 700;
            padding: 2px 7px; border-radius: 4px;
            text-transform: uppercase; letter-spacing: 0.4px;
        }}

        .sla-critical {{ background: rgba(239,68,68,0.12); color: var(--red); border: 1px solid rgba(239,68,68,0.2); }}
        .sla-high     {{ background: rgba(234,179,8,0.12);  color: var(--yellow); border: 1px solid rgba(234,179,8,0.2); }}
        .sla-medium   {{ background: rgba(59,130,246,0.12); color: var(--blue); border: 1px solid rgba(59,130,246,0.2); }}
        .sla-low      {{ background: rgba(100,116,139,0.1); color: var(--text-muted); border: 1px solid var(--border); }}

        /* Exploit / trend icons */
        .exploit-yes {{ color: var(--red); }}
        .exploit-no  {{ color: var(--text-muted); }}
        .trend-up    {{ color: var(--red); }}
        .trend-down  {{ color: var(--ok); }}
        .trend-stable {{ color: var(--text-muted); }}

        .icon-cell svg {{ width: 14px; height: 14px; vertical-align: middle; }}

        /* Stack badge */
        .stack-tag {{
            font-size: 0.6rem; font-weight: 700; padding: 1px 5px;
            border-radius: 3px; background: rgba(234,179,8,0.1);
            color: var(--yellow); border: 1px solid rgba(234,179,8,0.2);
            text-transform: uppercase; margin-left: 5px;
        }}

        /* Detail button */
        .btn-detail {{
            padding: 4px 10px; border-radius: 5px;
            background: var(--green-dim);
            border: 1px solid rgba(16,185,129,0.2);
            color: var(--green);
            font-size: 0.72rem; font-weight: 600;
            cursor: pointer; font-family: 'Outfit', sans-serif;
            transition: all 0.15s; white-space: nowrap;
        }}

        .btn-detail:hover {{ background: rgba(16,185,129,0.2); }}

        /* Expandable row */
        .detail-row {{ display: none; }}
        .detail-row.open {{ display: table-row; }}

        .detail-box {{
            padding: 16px 20px;
            background: rgba(0,0,0,0.15);
            border-left: 2px solid var(--green);
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}

        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 10px;
        }}

        .detail-field {{ font-size: 0.82rem; color: var(--text-sub); line-height: 1.5; }}
        .detail-field strong {{ color: var(--text); font-weight: 600; }}

        .detail-action {{
            background: rgba(16,185,129,0.04);
            border: 1px solid rgba(16,185,129,0.12);
            border-radius: var(--radius-sm);
            padding: 12px 14px;
        }}

        .detail-action strong {{ color: var(--green); display: block; margin-bottom: 4px; font-size: 0.8rem; }}
        .detail-action p {{ font-size: 0.82rem; color: var(--text-sub); line-height: 1.5; }}

        .table-empty {{
            text-align: center;
            padding: 40px 20px;
            color: var(--text-muted);
            font-size: 0.85rem;
        }}

        /* ─── Audio player ────────────────────────────────── */
        .audio-bar {{
            position: fixed; bottom: 0; left: 0; right: 0;
            background: rgba(10,11,16,0.95);
            backdrop-filter: blur(12px);
            border-top: 1px solid var(--border);
            padding: 10px 20px;
            display: flex; align-items: center; gap: 14px;
            transform: translateY(100%);
            transition: transform 0.3s cubic-bezier(.4,0,.2,1);
            z-index: 200;
        }}

        .audio-bar.visible {{ transform: translateY(0); }}

        .audio-label {{
            font-size: 0.78rem; font-weight: 600;
            color: var(--green); white-space: nowrap;
        }}

        .audio-bar audio {{ flex: 1; max-width: 480px; height: 28px; }}

        .btn-close-audio {{
            background: transparent; border: none;
            color: var(--text-muted); cursor: pointer; font-size: 1rem;
            padding: 4px; transition: color 0.15s;
        }}

        .btn-close-audio:hover {{ color: var(--text); }}

        /* ─── Utility ─────────────────────────────────────── */
        .hidden {{ display: none !important; }}

        /* ═══════════════════════════════════════════════════════
           RESPONSIVE
        ═══════════════════════════════════════════════════════ */
        @media (max-width: 900px) {{
            .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}

        @media (max-width: 680px) {{
            .sidebar {{
                position: fixed; top: 0; left: 0; bottom: 0;
                transform: translateX(-100%);
                z-index: 50;
            }}
            .sidebar.open {{ transform: translateX(0); }}
            .btn-hamburger {{ display: flex; }}
            .suggestion-grid {{ grid-template-columns: 1fr; }}
            .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .chat-welcome h1 {{ font-size: 1.55rem; }}
            .msg-row.bot .msg-inner, .msg-row.user .msg-inner {{ max-width: 92%; }}
        }}

        @media (max-width: 480px) {{
            .metrics-grid {{ grid-template-columns: 1fr 1fr; }}
            .dash-table th:nth-child(n+5):not(:last-child) {{ display: none; }}
            .dash-table td:nth-child(n+5):not(:last-child) {{ display: none; }}
        }}

        /* ─── Scrollbar geral ─────────────────────────────── */
        ::-webkit-scrollbar {{ width: 4px; }}
        ::-webkit-scrollbar-track {{ background: transparent; }}
        ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}

        /* ─── Focus visible ───────────────────────────────── */
        :focus-visible {{ outline: 2px solid rgba(16,185,129,0.5); outline-offset: 2px; }}
    </style>
</head>
<body>

    <!-- ══════════════════════════════════════════════════════
         SIDEBAR
    ══════════════════════════════════════════════════════ -->
    <aside class="sidebar" id="sidebar">
        <!-- Logo -->
        <div class="sidebar-logo">
            <div class="sidebar-logo-icon">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <div>
                <div class="sidebar-logo-text">Sentinel SecOps</div>
                <div class="sidebar-logo-sub">Pedroxious Lab</div>
            </div>
        </div>

        <!-- New chat -->
        <button class="sidebar-btn-new" onclick="resetChat()">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Nova Consulta
        </button>

        <!-- Nav -->
        <div class="sidebar-section">
            <div class="sidebar-section-label">Plataforma</div>
            <button class="sidebar-btn active" onclick="scrollToChat()">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                Aeris SOC Assistant
            </button>
            <button class="sidebar-btn" onclick="scrollToDashboard()">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                Threat Dashboard
            </button>
        </div>

        <div class="sidebar-section">
            <div class="sidebar-section-label">Outputs</div>
            <a class="sidebar-btn" href="pdf_reports/" target="_blank">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                Relatórios PDF
            </a>
            <a class="sidebar-btn" href="feed.xml" target="_blank">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>
                RSS Feed
            </a>
            <a class="sidebar-btn" href="output/" target="_blank">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                STIX Export
            </a>
        </div>

        <!-- Histórico de sessões decorativo -->
        <div class="sidebar-section" style="flex:1; overflow:hidden; display:flex; flex-direction:column;">
            <div class="sidebar-section-label">Histórico recente</div>
            <div class="sidebar-history" id="session-history">
                <div class="history-item">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                    Hoje
                </div>
                <!-- histórico dinâmico injetado por JS -->
            </div>
        </div>

        <!-- Footer usuário -->
        <div class="sidebar-footer">
            <div class="sidebar-user">
                <div class="sidebar-avatar">PL</div>
                <div class="sidebar-user-info">
                    <span class="sidebar-user-name">Pedroxious Lab</span>
                    <span class="sidebar-user-role">Analyst · Workspace</span>
                </div>
            </div>
        </div>
    </aside>

    <!-- ══════════════════════════════════════════════════════
         MAIN
    ══════════════════════════════════════════════════════ -->
    <div class="main" id="main">

        <!-- Top bar -->
        <header class="topbar">
            <div class="topbar-left">
                <button class="btn-hamburger" id="btn-hamburger" onclick="toggleSidebar()" aria-label="Abrir menu">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
                </button>
                <span class="topbar-title">Aeris — SOC Intelligence Assistant</span>
            </div>
            <div class="topbar-right">
                <div class="status-dot"></div>
                <span class="topbar-badge">Online</span>
            </div>
        </header>

        <!-- Scrollable content -->
        <div class="content-scroll" id="content-scroll">

            <!-- ══ CHAT SECTION ══════════════════════════════ -->
            <section class="chat-section" id="chat-section">

                <!-- Welcome screen (hidden when chat starts) -->
                <div class="chat-welcome" id="chat-welcome">
                    <div class="aeris-orb">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
                    <h1>Como posso ajudar?</h1>
                    <p>Analise ameaças cibernéticas, CVEs e exploits com suporte da Aeris — a IA da Pedroxious Lab.</p>

                    <div class="suggestion-grid">
                        <button class="chip" onclick="applySuggestion('Qual a ameaça mais crítica monitorada hoje?')">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 7 13.5 15.5 8.5 10.5 1 17"/><polyline points="17 7 23 7 23 13"/></svg>
                            Ameaça mais crítica hoje
                        </button>
                        <button class="chip" onclick="applySuggestion('Quais CVEs afetam meu tech stack atual?')">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                            CVEs no meu tech stack
                        </button>
                        <button class="chip" onclick="applySuggestion('Explique o que é uma CVE com exploit público e qual o risco.')">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
                            O que é exploit público?
                        </button>
                        <button class="chip" onclick="applySuggestion('O que significa a tática MITRE T1190?')">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
                            Explicar MITRE T1190
                        </button>
                    </div>
                </div>

                <!-- Messages -->
                <div class="chat-messages" id="chat-messages"></div>

                <!-- Input area -->
                <div class="chat-input-area">
                    <div id="chat-error" class="chat-error hidden">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                        <span id="chat-error-msg"></span>
                    </div>

                    <form id="chat-form" onsubmit="handleSubmit(event)">
                        <div class="input-pill">
                            <textarea
                                id="chat-input"
                                placeholder="Pergunte sobre CVEs, exploits, MITRE ATT&CK..."
                                rows="1"
                                aria-label="Mensagem para Aeris"
                            ></textarea>
                            <div class="input-pill-meta">
                                <span class="input-workspace-tag">Pedroxious Lab</span>
                                <button type="submit" id="btn-send" class="btn-send" aria-label="Enviar">
                                    <svg id="send-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                                    <div class="btn-spinner hidden" id="btn-spinner"></div>
                                </button>
                            </div>
                        </div>
                    </form>

                    <div class="input-footer">
                        <span class="quota-text" id="quota-label">Carregando cota...</span>
                    </div>
                </div>

                <!-- Scroll cue -->
                <div class="scroll-cue" onclick="scrollToDashboard()" title="Ver painel de ameaças">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
                    Threat Dashboard
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
                </div>

            </section><!-- /chat-section -->

            <!-- ══ DASHBOARD SECTION ═════════════════════════ -->
            <section class="dashboard-section" id="dashboard-section">

                <div class="dash-header">
                    <div class="dash-header-left">
                        <div>
                            <div class="dash-title">Painel de Threat Intelligence</div>
                            <div class="dash-subtitle" id="dash-subtitle">Atualizado em: {date_str} às {hour_str}</div>
                        </div>
                        <div class="dash-live-badge">
                            <div class="status-dot"></div>
                            Ao vivo
                        </div>
                    </div>
                    <a class="dash-pdf-link" href="pdf_reports/" target="_blank">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                        Relatório PDF
                    </a>
                </div>

                <!-- Metrics -->
                <div class="metrics-grid">
                    <div class="metric-card red">
                        <div class="metric-label">CVEs Críticas Hoje</div>
                        <div class="metric-value" id="m-critical">{critical_today}</div>
                        <div class="metric-icon">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                        </div>
                    </div>
                    <div class="metric-card purple">
                        <div class="metric-label">Ransomware Linked</div>
                        <div class="metric-value" id="m-ransomware">{ransomware_linked}</div>
                        <div class="metric-icon">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                        </div>
                    </div>
                    <div class="metric-card yellow">
                        <div class="metric-label">Com Exploit Público</div>
                        <div class="metric-value" id="m-exploit">{has_exploit}</div>
                        <div class="metric-icon">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
                        </div>
                    </div>
                    <div class="metric-card cyan">
                        <div class="metric-label">SLA Vencendo 24h</div>
                        <div class="metric-value" id="m-sla">{sla_24h}</div>
                        <div class="metric-icon">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                        </div>
                    </div>
                </div>

                <!-- Threat of the week (injected by Python or hidden) -->
                {threat_of_week_html}

                <!-- CVE Table -->
                <div class="table-wrapper">
                    <table class="dash-table" id="cve-table">
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Software Afetado</th>
                                <th>Score</th>
                                <th>Tática MITRE</th>
                                <th>SLA</th>
                                <th>Exploit DB</th>
                                <th>Tendência</th>
                                <th>Ransomware</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody id="cve-tbody">
                            {table_rows}
                        </tbody>
                    </table>
                </div>

            </section><!-- /dashboard-section -->

        </div><!-- /content-scroll -->
    </div><!-- /main -->

    <!-- Audio bar -->
    <div class="audio-bar" id="audio-bar">
        <span class="audio-label">⚡ Cyber Briefing</span>
        <audio controls id="briefing-audio">
            <source src="reports/audio/latest.mp3" type="audio/mpeg">
        </audio>
        <button class="btn-close-audio" onclick="closeAudio()">✕</button>
    </div>

    <!-- Sidebar overlay (mobile) -->
    <div id="sidebar-overlay" onclick="closeSidebar()"
         style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:40;"></div>

    <script>
    /* ═══════════════════════════════════════════════════════════
       CONFIGURATION
    ═══════════════════════════════════════════════════════════ */
    let API_KEY = atob("{api_key_b64}");          // Base64-encoded Gemini API key injected by scraper.py
    if (!API_KEY) {{
        API_KEY = localStorage.getItem("GEMINI_API_KEY") || "";
    }}
    const MAX_QUOTA = 20;
    const GEMINI_MODEL = "gemini-3.1-flash";

    const AERIS_SYSTEM_PROMPT = `{chat_system_context}`;

    const AERIS_PRESET_MESSAGE = `Olá, sou **Aeris**, assistente de IA da Pedroxious Lab para a plataforma Sentinel SecOps. Estou aqui para ajudar você a analisar ameaças cibernéticas, CVEs e exploits.

Como posso auxiliar na segurança hoje?`;

    /* ═══════════════════════════════════════════════════════════
       STATE
    ═══════════════════════════════════════════════════════════ */
    let conversationHistory = [];
    let chatStarted = false;
    let sessionMessages = [];    // for sidebar history

    /* ═══════════════════════════════════════════════════════════
       INIT
    ═══════════════════════════════════════════════════════════ */
    document.addEventListener("DOMContentLoaded", () => {{
        checkQuota();
        injectPresetMessage();
        setupTextarea();
    }});

    function injectPresetMessage() {{
        // Inject the visual preset bot message (not part of API history)
        const messagesEl = document.getElementById("chat-messages");
        const row = buildBotRow(AERIS_PRESET_MESSAGE, true);
        messagesEl.appendChild(row);
        // Add preset to history so Aeris has context of her own greeting
        conversationHistory.push({{
            role: "model",
            parts: [{{ text: "Olá, sou Aeris, assistente de IA da Pedroxious Lab para a plataforma Sentinel SecOps. Estou aqui para ajudar você a analisar ameaças cibernéticas, CVEs e exploits. Como posso auxiliar na segurança hoje?" }}]
        }});
    }}

    /* ═══════════════════════════════════════════════════════════
       SIDEBAR / NAVIGATION
    ═══════════════════════════════════════════════════════════ */
    function toggleSidebar() {{
        const sb = document.getElementById("sidebar");
        const ov = document.getElementById("sidebar-overlay");
        const open = sb.classList.contains("open");
        sb.classList.toggle("open", !open);
        ov.style.display = open ? "none" : "block";
    }}

    function closeSidebar() {{
        document.getElementById("sidebar").classList.remove("open");
        document.getElementById("sidebar-overlay").style.display = "none";
    }}

    function scrollToChat() {{
        document.getElementById("content-scroll").scrollTo({{ top: 0, behavior: "smooth" }});
        closeSidebar();
    }}

    function scrollToDashboard() {{
        document.getElementById("dashboard-section").scrollIntoView({{ behavior: "smooth" }});
        closeSidebar();
    }}

    /* ═══════════════════════════════════════════════════════════
       QUOTA
    ═══════════════════════════════════════════════════════════ */
    function checkQuota() {{
        const today = new Date().toISOString().slice(0, 10);
        let usage = JSON.parse(localStorage.getItem("sentinel_quota") || "null");
        if (!usage || usage.date !== today) usage = {{ date: today, count: 0 }};
        localStorage.setItem("sentinel_quota", JSON.stringify(usage));

        const label = document.getElementById("quota-label");
        const remaining = MAX_QUOTA - usage.count;

        if (usage.count >= MAX_QUOTA) {{
            document.getElementById("chat-input").disabled = true;
            document.getElementById("chat-input").placeholder = "Consultas esgotadas por hoje.";
            document.getElementById("btn-send").disabled = true;
            label.innerHTML = `<span class="quota-warn"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>Limite diário atingido — renova à meia-noite</span>`;
            return false;
        }}

        label.textContent = `${{remaining}} de ${{MAX_QUOTA}} consultas disponíveis hoje`;
        return true;
    }}

    function incrementQuota() {{
        const today = new Date().toISOString().slice(0, 10);
        let usage = JSON.parse(localStorage.getItem("sentinel_quota") || "null");
        if (!usage || usage.date !== today) usage = {{ date: today, count: 0 }};
        usage.count += 1;
        localStorage.setItem("sentinel_quota", JSON.stringify(usage));
        checkQuota();
    }}

    /* ═══════════════════════════════════════════════════════════
       CHAT SUBMIT
    ═══════════════════════════════════════════════════════════ */
    async function handleSubmit(e) {{
        e.preventDefault();
        const input = document.getElementById("chat-input");
        const message = input.value.trim();
        if (!message) return;

        if (!API_KEY) {{
            const userKey = prompt("Por favor, insira sua chave de API do Gemini para continuar:");
            if (!userKey || !userKey.trim()) {{
                showError("Chave de API do Gemini é necessária para usar o chat.");
                return;
            }}
            API_KEY = userKey.trim();
            localStorage.setItem("GEMINI_API_KEY", API_KEY);
        }}

        if (!checkQuota()) return;

        // First real message: hide welcome, show messages
        if (!chatStarted) {{
            document.getElementById("chat-welcome").classList.add("hidden");
            document.getElementById("chat-messages").classList.add("visible");
            chatStarted = true;
        }}

        appendUserBubble(message);
        input.value = "";
        input.style.height = "auto";

        // Audio keyword check
        checkAudioKeywords(message);

        // Add to sidebar history
        addToSidebarHistory(message);

        showError(null);
        setLoading(true);

        conversationHistory.push({{ role: "user", parts: [{{ text: message }}] }});

        try {{
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${{GEMINI_MODEL}}:generateContent?key=${{API_KEY}}`;
            const res = await fetch(url, {{
                method: "POST",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify({{
                    contents: conversationHistory,
                    systemInstruction: {{ parts: [{{ text: AERIS_SYSTEM_PROMPT }}] }},
                    generationConfig: {{ temperature: 0.7, maxOutputTokens: 1024 }}
                }})
            }});

            if (!res.ok) throw new Error(`API error: ${{res.status}} ${{res.statusText}}`);

            const data = await res.json();
            const reply = data?.candidates?.[0]?.content?.parts?.[0]?.text;
            if (!reply) throw new Error("Resposta vazia da API.");

            appendBotBubble(reply);
            conversationHistory.push({{ role: "model", parts: [{{ text: reply }}] }});
            incrementQuota();

        }} catch (err) {{
            console.error("Aeris API Error:", err);
            showError("Aeris não conseguiu responder no momento. Verifique a chave de API ou tente novamente.");
        }} finally {{
            setLoading(false);
        }}
    }}

    /* ═══════════════════════════════════════════════════════════
       BUBBLE BUILDERS
    ═══════════════════════════════════════════════════════════ */
    function timeNow() {{
        return new Date().toLocaleTimeString("pt-BR", {{ hour: "2-digit", minute: "2-digit" }});
    }}

    function appendUserBubble(text) {{
        const messages = document.getElementById("chat-messages");
        const row = document.createElement("div");
        row.className = "msg-row user";
        row.innerHTML = `
            <div class="msg-inner">
                <div>
                    <div class="bubble user-bubble">${{escHtml(text)}}</div>
                    <div class="msg-meta" style="text-align:right;">${{timeNow()}} · Você</div>
                </div>
            </div>`;
        messages.appendChild(row);
        scrollMessages();
    }}

    function appendBotBubble(text) {{
        const messages = document.getElementById("chat-messages");
        const row = buildBotRow(text, false);
        messages.appendChild(row);
        scrollMessages();
    }}

    function buildBotRow(text, isPreset) {{
        const row = document.createElement("div");
        row.className = "msg-row bot";
        const formatted = formatMarkdown(text);
        row.innerHTML = `
            <div class="msg-inner">
                <div class="bot-av" aria-hidden="true">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div>
                    <div class="bubble bot-bubble">${{formatted}}</div>
                    <div class="msg-meta">
                        ${{isPreset ? "Aeris · Pedroxious Lab" : timeNow() + " · Aeris"}}
                    </div>
                </div>
            </div>`;
        return row;
    }}

    function formatMarkdown(text) {{
        return text
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
            .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
            .replace(/\*(.*?)\*/g, "<em>$1</em>")
            .replace(/`([^`]+)`/g, "<code style='font-family:JetBrains Mono,monospace;font-size:0.82em;background:rgba(255,255,255,0.07);padding:1px 5px;border-radius:3px;'>$1</code>")
            .replace(/\n/g, "<br>");
    }}

    function escHtml(t) {{
        return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    }}

    function scrollMessages() {{
        const msgs = document.getElementById("chat-messages");
        msgs.scrollTop = msgs.scrollHeight;
    }}

    /* ═══════════════════════════════════════════════════════════
       LOADING STATE
    ═══════════════════════════════════════════════════════════ */
    function setLoading(on) {{
        const btn = document.getElementById("btn-send");
        const icon = document.getElementById("send-icon");
        const spinner = document.getElementById("btn-spinner");
        const messages = document.getElementById("chat-messages");

        btn.disabled = on;

        if (on) {{
            icon.classList.add("hidden");
            spinner.classList.remove("hidden");

            const typing = document.createElement("div");
            typing.id = "typing-indicator";
            typing.className = "typing-row";
            typing.innerHTML = `
                <div class="bot-av" aria-hidden="true">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div class="typing-dots">
                    <span></span><span></span><span></span>
                </div>`;
            messages.appendChild(typing);
            scrollMessages();
        }} else {{
            icon.classList.remove("hidden");
            spinner.classList.add("hidden");
            const t = document.getElementById("typing-indicator");
            if (t) t.remove();
        }}
    }}

    /* ═══════════════════════════════════════════════════════════
       ERROR
    ═══════════════════════════════════════════════════════════ */
    function showError(msg) {{
        const el = document.getElementById("chat-error");
        const txt = document.getElementById("chat-error-msg");
        if (msg) {{ txt.textContent = msg; el.classList.remove("hidden"); }}
        else      {{ el.classList.add("hidden"); }}
    }}

    /* ═══════════════════════════════════════════════════════════
       SUGGESTIONS & RESET
    ═══════════════════════════════════════════════════════════ */
    function applySuggestion(text) {{
        document.getElementById("chat-input").value = text;
        document.getElementById("chat-form").requestSubmit();
    }}

    function resetChat() {{
        conversationHistory = [];
        chatStarted = false;
        document.getElementById("chat-messages").innerHTML = "";
        document.getElementById("chat-messages").classList.remove("visible");
        document.getElementById("chat-welcome").classList.remove("hidden");
        showError(null);
        injectPresetMessage();
        scrollToChat();
        closeSidebar();
    }}

    /* ═══════════════════════════════════════════════════════════
       TEXTAREA AUTO-RESIZE
    ═══════════════════════════════════════════════════════════ */
    function setupTextarea() {{
        const ta = document.getElementById("chat-input");
        ta.addEventListener("input", function() {{
            this.style.height = "auto";
            this.style.height = Math.min(this.scrollHeight, 140) + "px";
        }});
        ta.addEventListener("keydown", function(e) {{
            if (e.key === "Enter" && !e.shiftKey) {{
                e.preventDefault();
                document.getElementById("chat-form").requestSubmit();
            }}
        }});
    }}

    /* ═══════════════════════════════════════════════════════════
       AUDIO
    ═══════════════════════════════════════════════════════════ */
    const AUDIO_KEYWORDS = ["audio","áudio","briefing","ouvir","tocar","narrar","podcast","reproduzir","som","escutar"];

    function checkAudioKeywords(msg) {{
        if (AUDIO_KEYWORDS.some(kw => msg.toLowerCase().includes(kw))) {{
            const bar = document.getElementById("audio-bar");
            bar.classList.add("visible");
            const player = document.getElementById("briefing-audio");
            player.load();
            player.play().catch(() => {{}});
        }}
    }}

    function closeAudio() {{
        document.getElementById("briefing-audio").pause();
        document.getElementById("audio-bar").classList.remove("visible");
    }}

    /* ═══════════════════════════════════════════════════════════
       DASHBOARD: detail row toggle
    ═══════════════════════════════════════════════════════════ */
    function toggleDetail(id) {{
        const row = document.getElementById("detail-" + id);
        if (!row) return;
        row.classList.toggle("open");
    }}

    /* ═══════════════════════════════════════════════════════════
       SIDEBAR SESSION HISTORY
    ═══════════════════════════════════════════════════════════ */
    function addToSidebarHistory(msg) {{
        const hist = document.getElementById("session-history");
        const existing = hist.querySelector(".history-item:not([data-placeholder])");
        // max 6 items
        const items = hist.querySelectorAll(".history-item[data-msg]");
        if (items.length >= 6) items[0].remove();

        const item = document.createElement("div");
        item.className = "history-item";
        item.setAttribute("data-msg", "1");
        item.title = msg;
        item.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
            ${{escHtml(msg.length > 28 ? msg.slice(0, 28) + "…" : msg)}}`;
        item.onclick = () => applySuggestion(msg);
        hist.appendChild(item);
    }}
    </script>

</body>
</html>
"""


    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_template)
    return filepath

# ─── 9. CSV Update with Trend and SLA Tracking ──────────────────────────────
def update_csv_v2(cves_analyzed, date_str, hour_str):
    existing_cves = {}
    if os.path.exists(CSV_PATH):
        try:
            with open(CSV_PATH, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cve_id = row.get("cve_id")
                    if cve_id:
                        existing_cves[cve_id] = row
        except Exception as e:
            print(f"Error reading existing CSV for evolution mapping: {e}")

    # Write headers and append rows
    # Read headers
    with open(CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        headers = next(reader)
        
    # Open CSV to append
    with open(CSV_PATH, mode="a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        
        for item in cves_analyzed:
            cve = item["cve"]
            an = item["analysis_raw"]
            cve_id = cve["id"]
            
            # Historical Trend Map
            score_prev = ""
            score_curr = f"{cve['priority_score']:.1f}"
            score_trend = "STABLE"
            score_updated_at = ""
            
            if cve_id in existing_cves:
                old_row = existing_cves[cve_id]
                old_score_str = old_row.get("priority_score", "0.0")
                try:
                    old_score = float(old_score_str)
                except ValueError:
                    old_score = 0.0
                    
                new_score = cve["priority_score"]
                score_prev = f"{old_score:.1f}"
                score_updated_at = f"{date_str} {hour_str}"
                
                if new_score > old_score:
                    score_trend = "UP"
                elif new_score < old_score:
                    score_trend = "DOWN"
                else:
                    score_trend = "STABLE"
                    
            cve["score_trend"] = score_trend
            
            # SLA Tracker calculation
            # labels: CRITICAL, HIGH, MEDIUM, LOW
            priority_val = cve["priority_score"]
            if priority_val >= 9.0:
                sla_label = "CRITICAL"
                sla_hours = 24
            elif priority_val >= 7.0:
                sla_label = "HIGH"
                sla_hours = 72
            elif priority_val >= 5.0:
                sla_label = "MEDIUM"
                sla_hours = 7 * 24
            else:
                sla_label = "LOW"
                sla_hours = 30 * 24
                
            now_dt = datetime.now(timezone.utc) - timedelta(hours=3) # BRT time
            sla_deadline_dt = now_dt + timedelta(hours=sla_hours)
            sla_deadline = sla_deadline_dt.strftime("%Y-%m-%d %H:%M")
            sla_status = "OPEN"
            
            cve["sla_label"] = sla_label
            cve["sla_deadline"] = sla_deadline
            cve["sla_status"] = sla_status
            
            # OSV parameters map
            osv_conf = "sim" if cve.get("osv_confirmed") else "não"
            osv_eco = ", ".join(cve.get("osv_ecosystems", []))
            
            # Convert values to match CSV headers order
            row_data = [
                date_str, hour_str, cve_id, cve["score"], cve["severity"],
                score_curr, cve["priority_rating"], "sim" if cve["in_cisa_kev"] else "não",
                cve["epss_data"].get("epss", 0.0),
                cve.get("cwe_id", "N/A"), cve.get("attack_vector", "UNKNOWN"),
                cve.get("attack_complexity", "UNKNOWN"),
                "sim" if cve.get("ransomware_known") else "não",
                cve.get("ioc_count", 0), an.get("vulnerability_type", "Other"),
                an.get("software_affected", "N/A"), "sim" if an.get("patch_available") else "não",
                an.get("exploitability", "Média"), an.get("executive_summary", ""),
                
                score_prev, score_curr, score_updated_at, score_trend,
                sla_deadline, sla_label, sla_status,
                cve.get("mitre_technique_id", "N/A"), cve.get("mitre_technique_name", "N/A"),
                cve.get("mitre_tactic", "N/A"),
                "sim" if cve.get("exploitdb_has_exploit") else "não",
                cve.get("exploitdb_exploit_count", 0),
                osv_conf, osv_eco
            ]
            writer.writerow(row_data)

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
    print("Starting Sentinel SecOps v2.0 Pipeline")
    migrate_csv()
    
    # Load assets.json
    assets_config = {}
    assets_path = os.path.join("config", "assets.json")
    if os.path.exists(assets_path):
        try:
            with open(assets_path, "r", encoding="utf-8") as f:
                assets_config = json.load(f)
        except Exception as e:
            print(f"Failed to load organization assets.json: {e}")
            
    now_br = datetime.now(timezone.utc) - timedelta(hours=3)
    date_str = now_br.strftime("%Y-%m-%d")
    hour_str = now_br.strftime("%H:%M")
    
    raw_vulnerabilities = get_cves()
    
    if not raw_vulnerabilities:
        print("No new raw vulnerabilities found in this cycle.")
        pdf_file = generate_pdf_report([], date_str, hour_str, "SECURE")
        generate_html_dashboard([], date_str, hour_str, "SECURE", assets_config)
        update_readme(date_str, hour_str, 0, pdf_file, "SECURE - No Critical Alerts")
        return

    critical_cves = filter_critical(raw_vulnerabilities)
    
    if not critical_cves:
        print("No raw vulnerabilities met the Critical/High threshold.")
        pdf_file = generate_pdf_report([], date_str, hour_str, "SECURE")
        generate_html_dashboard([], date_str, hour_str, "SECURE", assets_config)
        update_readme(date_str, hour_str, 0, pdf_file, "SECURE - Only Low Severity Alerts")
        return

    cve_ids = [c["id"] for c in critical_cves]
    kev_data = get_cisa_kev_cves()
    epss_scores = get_epss_scores(cve_ids)
    threatfox_data = get_threatfox_iocs(cve_ids)
    ghsa_data = get_github_advisories(cve_ids)

    # Fetch OSV, Exploit-DB, and map MITRE ATT&CK for each CVE
    for cve in critical_cves:
        cve_id = cve["id"]
        cve["in_cisa_kev"] = cve_id in kev_data
        cve["ransomware_known"] = kev_data.get(cve_id, {}).get("ransomware_known", "Unknown") == "Known"
        cve["epss_data"] = epss_scores.get(cve_id, {"epss": 0.0, "percentile": 0.0})
        cve["ioc_count"] = threatfox_data.get(cve_id, {"count": 0}).get("count", 0)
        
        # 2.1 OSV Lookup
        osv_conf, osv_ecosystems = check_osv_cve(cve_id)
        cve["osv_confirmed"] = osv_conf
        cve["osv_ecosystems"] = osv_ecosystems
        
        # 2.3 Exploit-DB Lookup
        has_exp, exp_count = check_exploitdb_cve(cve_id)
        cve["exploitdb_has_exploit"] = has_exp
        cve["exploitdb_exploit_count"] = exp_count
        
        # Calculate Priority Score (incorporating Exploit-DB)
        priority_score, priority_rating = calculate_priority_score(
            cve["score"], cve["in_cisa_kev"], cve["epss_data"],
            cve["ransomware_known"], cve["ioc_count"],
            cve.get("attack_vector", "UNKNOWN"),
            cve.get("attack_complexity", "UNKNOWN"),
            cve["exploitdb_has_exploit"]
        )
        cve["priority_score"] = priority_score
        cve["priority_rating"] = priority_rating

    # AI batch analysis with Gemini
    cves_analyzed = []
    batch_size = 10
    for i in range(0, len(critical_cves), batch_size):
        end_idx = min(i + batch_size, len(critical_cves))
        gemini_results = analyze_batch_with_gemini(critical_cves, i, end_idx, assets_config)
        
        if gemini_results:
            lookup = {r["cve_id"]: r for r in gemini_results if "cve_id" in r}
            for cve in critical_cves[i:end_idx]:
                if cve["id"] in lookup:
                    analysis = lookup[cve["id"]]
                    # 2.2 MITRE attack mapping from Gemini technique identification
                    mitre_tech_id = analysis.get("mitre_technique_id", "N/A")
                    mitre_details = get_mitre_technique(mitre_tech_id)
                    
                    cve["mitre_technique_id"] = mitre_details.get("id", "N/A")
                    cve["mitre_technique_name"] = mitre_details.get("name", "N/A")
                    cve["mitre_tactic"] = mitre_details.get("tactic", "N/A")
                    cve["affects_our_stack"] = analysis.get("affects_our_stack", False)
                    
                    cves_analyzed.append({
                        "cve": cve,
                        "analysis_raw": analysis
                    })
        time.sleep(3)

    # 3. CSV manager update with history tracking
    update_csv_v2(cves_analyzed, date_str, hour_str)
    
    status_text = "ATTENTION"
    if any(item["cve"]["priority_rating"] == "IMMEDIATE" for item in cves_analyzed):
        status_text = "CRITICAL - Immediate Action Required"
    elif any(item["cve"]["severity"] == "CRITICAL" for item in cves_analyzed):
        status_text = "HIGH ALERT"

    # Reports outputs
    pdf_file = generate_pdf_report(cves_analyzed, date_str, hour_str, status_text)
    
    # STIX 2.1 Export
    export_to_stix(cves_analyzed)
    
    # RSS Feed Export
    generate_rss_feed(cves_analyzed)
    
    # 4. Generate audio podcast cyber briefing
    audio_script = build_audio_script(cves_analyzed, date_str)
    generate_audio_briefing(audio_script, date_str, hour_str)
    
    generate_html_dashboard(cves_analyzed, date_str, hour_str, status_text, assets_config)
    update_readme(date_str, hour_str, len(cves_analyzed), pdf_file, status_text)

def build_audio_script(cves_analyzed, date_str):
    total = len(cves_analyzed)
    criticals = sum(1 for item in cves_analyzed if item["cve"].get("priority_rating") in ["IMMEDIATE", "CRITICAL"])
    
    script = f"Bom dia. Este é o Sentinel SecOps Briefing de {date_str}.\n"
    script += f"Hoje monitoramos {total} novas vulnerabilidades.\n"
    script += f"{criticals} são classificadas como críticas ou de alta prioridade e exigem ação imediata.\n\n"
    
    # Sort by priority score descending
    sorted_items = sorted(cves_analyzed, key=lambda x: x["cve"].get("priority_score", 0.0), reverse=True)
    top_3 = sorted_items[:3]
    
    for idx, item in enumerate(top_3):
        cve = item["cve"]
        an = item["analysis_raw"]
        cve_id = cve["id"]
        software = an.get("software_affected", "N/A")
        exec_summary = an.get("executive_summary", "")
        score = cve["priority_score"]
        
        script += f"A ameaça número {idx+1} é {cve_id}, afetando {software}.\n"
        script += f"{exec_summary} Score de prioridade: {score:.1f} de 10.\n"
        
        if cve.get("ransomware_known"):
            script += "Esta vulnerabilidade está sendo usada ativamente por gangues de ransomware.\n"
        if cve.get("exploitdb_has_exploit"):
            script += "Existe exploit público disponível para esta falha.\n"
        script += "\n"
        
    script += "Para o relatório completo e análise detalhada, acesse o painel de segurança.\n"
    script += "Sentinel SecOps. Inteligência que protege."
    return script

if __name__ == "__main__":
    main()
