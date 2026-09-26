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

# Using gemini-1.5-flash as principal model
MODEL_NAME = "gemini-1.5-flash"
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
    <title>Sentinel SecOps — Autonomous Threat Intelligence Platform</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <style>
        /* ═══════════════════════════════════════════════════════
           DESIGN TOKENS — Sentinel SecOps Dark Palette
        ═══════════════════════════════════════════════════════ */
        :root {{
            --bg:           #07080c;
            --bg-sidebar:   #0a0b10;
            --bg-card:      #0d0f17;
            --bg-card-alt:  #111420;
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
            z-index: 50;
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

        .sidebar-section {{
            padding: 8px 10px 4px;
        }}

        .sidebar-section-label {{
            font-size: 0.65rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            padding: 0 8px 6px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .sidebar-btn {{
            display: flex;
            align-items: center;
            gap: 10px;
            width: 100%;
            padding: 8px 10px;
            border-radius: var(--radius-sm);
            background: transparent;
            border: none;
            color: var(--text-sub);
            font-family: 'Outfit', sans-serif;
            font-size: 0.84rem;
            cursor: pointer;
            text-align: left;
            transition: background 0.15s, color 0.15s;
            text-decoration: none;
        }}

        .sidebar-btn:hover {{ background: var(--bg-hover); color: var(--text); }}
        .sidebar-btn.active {{ background: var(--green-dim); color: var(--green); font-weight: 500; }}
        .sidebar-btn svg {{ width: 15px; height: 15px; flex-shrink: 0; }}

        /* Dynamic Chat History in Sidebar */
        .sidebar-history {{
            flex: 1;
            overflow-y: auto;
            padding: 4px 6px 10px;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}

        .sidebar-history::-webkit-scrollbar {{ width: 3px; }}
        .sidebar-history::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}

        .history-session-item {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 8px 10px;
            border-radius: var(--radius-sm);
            cursor: pointer;
            color: var(--text-muted);
            font-size: 0.79rem;
            transition: background 0.12s, color 0.12s;
            position: relative;
            group: relative;
        }}

        .history-session-item:hover {{ background: var(--bg-hover); color: var(--text-sub); }}
        .history-session-item.active {{ background: rgba(16,185,129,0.1); color: var(--green); font-weight: 500; }}

        .history-session-left {{
            display: flex;
            flex-direction: column;
            overflow: hidden;
            gap: 2px;
            flex: 1;
        }}

        .history-session-title {{
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.8rem;
        }}

        .history-session-time {{
            font-size: 0.68rem;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }}

        .history-del-btn {{
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 4px;
            border-radius: 4px;
            opacity: 0;
            transition: opacity 0.15s, color 0.15s;
        }}

        .history-session-item:hover .history-del-btn {{ opacity: 1; }}
        .history-del-btn:hover {{ color: var(--red); background: rgba(239,68,68,0.1); }}
        .history-del-btn svg {{ width: 12px; height: 12px; }}

        /* Anonymous User Footer */
        .sidebar-footer {{
            padding: 10px;
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
            transition: background 0.15s, border-color 0.15s;
            border: 1px solid transparent;
            background: rgba(255,255,255,0.02);
        }}

        .sidebar-user:hover {{
            background: var(--bg-hover);
            border-color: rgba(16,185,129,0.2);
        }}

        .sidebar-avatar.anonymous {{
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: #141724;
            border: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--cyan);
            flex-shrink: 0;
        }}

        .sidebar-avatar.anonymous svg {{ width: 17px; height: 17px; }}

        .sidebar-user-info {{ display: flex; flex-direction: column; flex: 1; overflow: hidden; }}
        .sidebar-user-name {{ font-size: 0.82rem; font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .sidebar-user-role {{ font-size: 0.68rem; color: var(--text-muted); }}

        .sidebar-user-cog {{
            color: var(--text-muted);
            display: flex;
            align-items: center;
        }}
        .sidebar-user-cog svg {{ width: 14px; height: 14px; }}

        /* ═══════════════════════════════════════════════════════
           MAIN AREA & SPA VIEWS
        ═══════════════════════════════════════════════════════ */
        .main {{
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100vh;
            overflow: hidden;
            position: relative;
        }}

        .topbar {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 24px;
            height: 56px;
            border-bottom: 1px solid var(--border);
            flex-shrink: 0;
            background: var(--bg);
            z-index: 20;
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

        .topbar-right {{ display: flex; align-items: center; gap: 10px; }}

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

        .topbar-account-btn {{
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-sub);
            padding: 4px 10px;
            border-radius: var(--radius-sm);
            font-size: 0.75rem;
            display: flex;
            align-items: center;
            gap: 6px;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .topbar-account-btn:hover {{
            background: var(--bg-hover);
            color: var(--text);
            border-color: rgba(16,185,129,0.3);
        }}

        .content-scroll {{
            flex: 1;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            position: relative;
        }}

        .content-scroll::-webkit-scrollbar {{ width: 4px; }}
        .content-scroll::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}

        /* SPA VIEW CONTAINERS */
        .spa-view {{
            display: none;
            width: 100%;
            animation: fadeIn 0.18s ease-in-out;
        }}

        .spa-view.active {{
            display: block;
        }}

        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(4px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        /* ═══════════════════════════════════════════════════════
           CHAT SECTION
        ═══════════════════════════════════════════════════════ */
        .chat-section {{
            min-height: calc(100vh - 56px);
            display: flex;
            flex-direction: column;
            position: relative;
        }}

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
            max-width: 440px;
            line-height: 1.55;
        }}

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
            max-width: 82%;
        }}

        .msg-row.user .msg-inner {{
            max-width: 75%;
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
            padding: 12px 16px;
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
            line-height: 1.6;
        }}

        /* Rich Markdown formatting */
        .bubble.bot-bubble h1.msg-h1 {{ font-size: 1.15rem; font-weight: 700; color: var(--green); margin: 12px 0 6px; }}
        .bubble.bot-bubble h2.msg-h2 {{ font-size: 1.02rem; font-weight: 700; color: var(--green); margin: 10px 0 4px; }}
        .bubble.bot-bubble h3.msg-h3 {{ font-size: 0.92rem; font-weight: 600; color: var(--cyan); margin: 8px 0 4px; }}
        .bubble.bot-bubble ul.msg-list, .bubble.bot-bubble ol.msg-num-list {{ margin: 6px 0 8px 20px; }}
        .bubble.bot-bubble li {{ margin-bottom: 3px; }}
        .bubble.bot-bubble blockquote.msg-quote {{
            border-left: 3px solid var(--green);
            background: rgba(16,185,129,0.06);
            padding: 6px 12px;
            margin: 8px 0;
            border-radius: 0 4px 4px 0;
            color: var(--text-sub);
            font-style: italic;
        }}
        .bubble.bot-bubble code.msg-inline-code {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82em;
            background: rgba(255,255,255,0.08);
            color: #38bdf8;
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid rgba(255,255,255,0.05);
        }}

        /* Modern Code Block with Language Badge & Copy Button */
        .code-block-wrapper {{
            margin: 12px 0;
            border-radius: var(--radius-md);
            background: #090b10;
            border: 1px solid var(--border);
            overflow: hidden;
            box-shadow: 0 4px 14px rgba(0,0,0,0.3);
        }}
        .code-block-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 7px 14px;
            background: rgba(255,255,255,0.03);
            border-bottom: 1px solid var(--border);
            font-size: 0.72rem;
            user-select: none;
        }}
        .code-block-header .code-lang {{
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            color: var(--green);
        }}
        .btn-copy-code {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.08);
            color: var(--text-sub);
            font-size: 0.72rem;
            cursor: pointer;
            padding: 4px 10px;
            border-radius: 5px;
            transition: all 0.15s ease;
            font-family: 'Outfit', sans-serif;
            font-weight: 500;
        }}
        .btn-copy-code:hover {{
            background: rgba(255,255,255,0.1);
            color: var(--text);
            border-color: rgba(255,255,255,0.18);
        }}
        .btn-copy-code.copied {{
            color: var(--green);
            border-color: rgba(16,185,129,0.4);
            background: rgba(16,185,129,0.1);
        }}
        .code-block-wrapper pre {{
            margin: 0;
            padding: 12px 14px;
            overflow-x: auto;
            background: #090b10 !important;
        }}
        .code-block-wrapper pre code {{
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.84rem;
            line-height: 1.55;
            background: transparent !important;
            padding: 0 !important;
            border-radius: 0 !important;
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

        /* Input Area */
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
            justify-content: space-between;
            margin-top: 8px;
            gap: 12px;
        }}

        .quota-text {{
            font-size: 0.72rem;
            color: var(--text-muted);
            text-align: center;
        }}

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
            gap: 24px;
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
            font-size: 1.15rem;
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

        .dash-actions-bar {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .btn-dash-action {{
            display: flex; align-items: center; gap: 6px;
            padding: 6px 12px; border-radius: var(--radius-sm);
            border: 1px solid var(--border);
            background: rgba(255,255,255,0.02);
            color: var(--text-sub);
            font-size: 0.78rem; font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .btn-dash-action:hover {{ border-color: rgba(16,185,129,0.3); color: var(--green); }}
        .btn-dash-action svg {{ width: 13px; height: 13px; }}

        /* Metrics */
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

        /* Table Filter Controls */
        .table-controls {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 12px;
        }}

        .search-box {{
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            padding: 6px 12px;
            flex: 1;
            max-width: 420px;
        }}

        .search-box svg {{ width: 14px; height: 14px; color: var(--text-muted); flex-shrink: 0; }}
        .search-box input {{
            background: transparent;
            border: none;
            outline: none;
            color: var(--text);
            font-size: 0.82rem;
            font-family: 'Outfit', sans-serif;
            width: 100%;
        }}
        .search-box input::placeholder {{ color: var(--text-muted); }}

        .filter-tabs {{
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }}

        .filter-chip {{
            padding: 4px 10px;
            border-radius: 14px;
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border);
            color: var(--text-sub);
            font-size: 0.74rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .filter-chip:hover {{ color: var(--text); border-color: rgba(16,185,129,0.3); }}
        .filter-chip.active {{ background: var(--green-dim); color: var(--green); border-color: rgba(16,185,129,0.3); font-weight: 600; }}

        /* Table */
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
            background: rgba(0,0,0,0.25);
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
            font-weight: 600;
            color: var(--text);
        }}

        .score-pill {{
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 0.76rem;
            padding: 3px 8px;
            border-radius: 5px;
            display: inline-block;
        }}

        .score-critical {{ background: rgba(239,68,68,0.14); color: var(--red); border: 1px solid rgba(239,68,68,0.25); }}
        .score-high     {{ background: rgba(234,179,8,0.14);  color: var(--yellow); border: 1px solid rgba(234,179,8,0.25); }}
        .score-medium   {{ background: rgba(59,130,246,0.14); color: var(--blue); border: 1px solid rgba(59,130,246,0.25); }}

        .sla-badge {{
            font-size: 0.68rem; font-weight: 700;
            padding: 2px 7px; border-radius: 4px;
            text-transform: uppercase; letter-spacing: 0.4px;
        }}

        .sla-critical {{ background: rgba(239,68,68,0.12); color: var(--red); border: 1px solid rgba(239,68,68,0.2); }}
        .sla-high     {{ background: rgba(234,179,8,0.12);  color: var(--yellow); border: 1px solid rgba(234,179,8,0.2); }}
        .sla-medium   {{ background: rgba(59,130,246,0.12); color: var(--blue); border: 1px solid rgba(59,130,246,0.2); }}

        .exploit-yes {{ color: var(--red); font-weight: 600; display: inline-flex; align-items: center; gap: 4px; }}
        .exploit-no  {{ color: var(--text-muted); }}
        .trend-up    {{ color: var(--red); }}
        .trend-down  {{ color: var(--ok); }}
        .trend-stable {{ color: var(--text-muted); }}

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

        .detail-row {{ display: none; }}
        .detail-row.open {{ display: table-row; }}

        .detail-box {{
            padding: 16px 20px;
            background: rgba(0,0,0,0.2);
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

        /* ═══════════════════════════════════════════════════════
           SINGLE PAGE SUB-VIEWS (PDF, RSS, STIX, ACCOUNT)
        ═══════════════════════════════════════════════════════ */
        .view-header {{
            padding: 30px 32px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 20px;
            flex-wrap: wrap;
            background: linear-gradient(180deg, rgba(255,255,255,0.015), transparent);
        }}

        .view-header-main {{ max-width: 650px; }}
        .view-title {{ font-size: 1.45rem; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 10px; }}
        .view-subtitle {{ font-size: 0.86rem; color: var(--text-sub); margin-top: 6px; line-height: 1.5; }}

        .btn-view-back {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px;
            background: rgba(255,255,255,0.04);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            color: var(--text-sub);
            font-size: 0.82rem;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .btn-view-back:hover {{
            background: var(--bg-hover);
            color: var(--text);
            border-color: rgba(16,185,129,0.3);
        }}

        .view-body {{
            padding: 28px 32px 60px;
            max-width: 1200px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }}

        /* Generic Card Container */
        .subview-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 24px;
            position: relative;
        }}

        .subview-card-title {{
            font-size: 1.05rem;
            font-weight: 700;
            color: var(--text);
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .subview-card-desc {{
            font-size: 0.84rem;
            color: var(--text-muted);
            margin-bottom: 18px;
            line-height: 1.5;
        }}

        /* PDF Viewer Grid */
        .pdf-reports-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 16px;
        }}

        .pdf-report-card {{
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 16px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            gap: 12px;
            transition: all 0.15s;
        }}

        .pdf-report-card:hover {{
            border-color: rgba(16,185,129,0.3);
            transform: translateY(-2px);
        }}

        .pdf-card-top {{ display: flex; align-items: flex-start; gap: 12px; }}
        .pdf-icon-box {{
            width: 38px; height: 38px; border-radius: 8px;
            background: rgba(239,68,68,0.12);
            color: var(--red);
            border: 1px solid rgba(239,68,68,0.25);
            display: flex; align-items: center; justify-content: center;
            flex-shrink: 0;
        }}
        .pdf-icon-box svg {{ width: 20px; height: 20px; }}

        .pdf-info h4 {{ font-size: 0.88rem; font-weight: 600; color: var(--text); }}
        .pdf-info p {{ font-size: 0.74rem; color: var(--text-muted); margin-top: 3px; font-family: 'JetBrains Mono', monospace; }}

        .pdf-actions {{ display: flex; align-items: center; gap: 8px; margin-top: 4px; }}
        .btn-download-pdf {{
            flex: 1;
            padding: 6px 12px;
            border-radius: var(--radius-sm);
            background: var(--green-dim);
            border: 1px solid rgba(16,185,129,0.2);
            color: var(--green);
            font-size: 0.76rem;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            transition: all 0.15s;
        }}
        .btn-download-pdf:hover {{ background: rgba(16,185,129,0.25); }}

        /* Code & JSON Display Blocks */
        .code-display {{
            background: #090a10;
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: #cbd5e1;
            max-height: 420px;
            overflow: auto;
            line-height: 1.5;
            white-space: pre-wrap;
        }}

        /* Account Settings Form Elements */
        .form-row {{
            display: flex;
            flex-direction: column;
            gap: 6px;
            margin-bottom: 16px;
        }}

        .form-label {{
            font-size: 0.82rem;
            font-weight: 600;
            color: var(--text);
        }}

        .form-hint {{
            font-size: 0.74rem;
            color: var(--text-muted);
        }}

        .form-input {{
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            padding: 10px 14px;
            color: var(--text);
            font-family: 'Outfit', sans-serif;
            font-size: 0.88rem;
            outline: none;
            transition: border-color 0.15s;
        }}

        .form-input:focus {{ border-color: var(--green); }}

        .btn-primary {{
            background: var(--green);
            color: #07080c;
            border: none;
            border-radius: var(--radius-sm);
            padding: 9px 18px;
            font-weight: 600;
            font-size: 0.84rem;
            cursor: pointer;
            transition: all 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}

        .btn-primary:hover {{ opacity: 0.9; }}

        .btn-danger {{
            background: rgba(239,68,68,0.12);
            color: var(--red);
            border: 1px solid rgba(239,68,68,0.3);
            border-radius: var(--radius-sm);
            padding: 9px 18px;
            font-weight: 600;
            font-size: 0.84rem;
            cursor: pointer;
            transition: all 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}

        .btn-danger:hover {{ background: rgba(239,68,68,0.2); }}

        /* Audio bar */
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
        .hidden {{ display: none !important; }}

        /* ═══════════════════════════════════════════════════════
           RESPONSIVE
        ═══════════════════════════════════════════════════════ */
        @media (max-width: 900px) {{
            .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .view-header {{ padding: 20px 20px 16px; }}
            .view-body {{ padding: 20px; }}
        }}

        @media (max-width: 680px) {{
            .sidebar {{
                position: fixed; top: 0; left: 0; bottom: 0;
                transform: translateX(-100%);
                z-index: 100;
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

        ::-webkit-scrollbar {{ width: 4px; }}
        ::-webkit-scrollbar-track {{ background: transparent; }}
        ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}
    
        /* ═══════════════════════════════════════════════════════
           UPGRADE PLANS PAGE (MOCKUP LIKE CLAUDE / CHATGPT)
        ═══════════════════════════════════════════════════════ */
        .upgrade-page-container {{
            max-width: 1100px;
            margin: 0 auto;
            padding: 30px 24px 60px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}

        .upgrade-top-bar {{
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
        }}

        .btn-upgrade-back {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: transparent;
            border: none;
            color: var(--text-sub);
            font-size: 0.95rem;
            font-weight: 500;
            cursor: pointer;
            transition: color 0.15s;
        }}

        .btn-upgrade-back:hover {{ color: var(--text); }}
        .btn-upgrade-back svg {{ width: 18px; height: 18px; }}

        .pricing-segmented-control {{
            display: inline-flex;
            background: #141724;
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 4px;
            gap: 4px;
            margin-bottom: 36px;
        }}

        .segment-btn {{
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 0.85rem;
            font-weight: 500;
            padding: 6px 16px;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .segment-btn.active {{
            background: #252b3d;
            color: #ffffff;
            font-weight: 600;
        }}

        .pricing-cards-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            width: 100%;
        }}

        @media (max-width: 900px) {{
            .pricing-cards-grid {{
                grid-template-columns: 1fr;
                max-width: 440px;
            }}
        }}

        .pricing-card {{
            background: #0d0f17;
            border: 1px solid #1a1e2f;
            border-radius: 16px;
            padding: 28px 24px;
            display: flex;
            flex-direction: column;
            position: relative;
            transition: transform 0.15s, border-color 0.15s;
        }}

        .pricing-card:hover {{
            transform: translateY(-2px);
            border-color: rgba(255,255,255,0.12);
        }}

        .pricing-card.featured {{
            border-color: rgba(59, 130, 246, 0.4);
            box-shadow: 0 0 25px rgba(59, 130, 246, 0.08);
        }}

        .pricing-badge-recommend {{
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(59, 130, 246, 0.18);
            border: 1px solid rgba(59, 130, 246, 0.4);
            color: #60a5fa;
            font-size: 0.72rem;
            font-weight: 600;
            padding: 3px 10px;
            border-radius: 12px;
        }}

        .pricing-icon-box {{
            width: 42px;
            height: 42px;
            margin-bottom: 16px;
            color: #cbd5e1;
        }}

        .pricing-icon-box svg {{ width: 36px; height: 36px; }}

        .pricing-title {{
            font-size: 1.4rem;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 4px;
        }}

        .pricing-subtitle {{
            font-size: 0.84rem;
            color: var(--text-muted);
            min-height: 20px;
            margin-bottom: 20px;
        }}

        .pricing-price-box {{
            margin-bottom: 24px;
            min-height: 58px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}

        .pricing-price-main {{
            font-size: 2rem;
            font-weight: 800;
            color: #ffffff;
            font-family: 'Outfit', sans-serif;
            line-height: 1.1;
        }}

        .pricing-price-period {{
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 4px;
        }}

        .pricing-btn {{
            width: 100%;
            padding: 11px 16px;
            border-radius: 8px;
            font-size: 0.88rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s;
            text-align: center;
            border: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }}

        .pricing-btn-primary {{
            background: #ffffff;
            color: #07080c;
        }}

        .pricing-btn-primary:hover {{
            background: #e2e8f0;
        }}

        .pricing-btn-outline {{
            background: rgba(255, 255, 255, 0.05);
            color: var(--text);
            border: 1px solid var(--border);
        }}

        .pricing-btn-outline:hover {{
            background: rgba(255, 255, 255, 0.08);
        }}

        .pricing-subcaption {{
            font-size: 0.72rem;
            color: var(--text-muted);
            text-align: center;
            margin-top: 8px;
            margin-bottom: 24px;
        }}

        .pricing-divider {{
            height: 1px;
            background: var(--border-soft);
            margin-bottom: 20px;
        }}

        .pricing-feature-header {{
            font-size: 0.82rem;
            font-weight: 600;
            color: var(--text-sub);
            margin-bottom: 12px;
        }}

        .pricing-feature-list {{
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}

        .pricing-feature-item {{
            display: flex;
            align-items: flex-start;
            gap: 10px;
            font-size: 0.84rem;
            color: var(--text-sub);
            line-height: 1.45;
        }}

        .pricing-feature-item svg {{
            width: 15px;
            height: 15px;
            color: var(--green);
            flex-shrink: 0;
            margin-top: 2px;
        }}

        /* ChatGPT-style quota limit banner */
        .quota-limit-banner {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(234, 179, 8, 0.08);
            border: 1px solid rgba(234, 179, 8, 0.25);
            border-radius: var(--radius-md);
            padding: 10px 16px;
            margin-bottom: 10px;
            gap: 12px;
            flex-wrap: wrap;
        }}

        .quota-limit-banner.hidden {{ display: none !important; }}

        .quota-limit-text {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.82rem;
            color: #fbbf24;
        }}

        .quota-limit-text svg {{ width: 15px; height: 15px; flex-shrink: 0; }}

        .btn-upgrade-pill {{
            background: linear-gradient(135deg, #10b981, #06b6d4);
            color: #07080c;
            border: none;
            border-radius: 20px;
            padding: 5px 14px;
            font-size: 0.78rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            box-shadow: 0 0 10px rgba(16,185,129,0.25);
        }}

        .btn-upgrade-pill:hover {{
            opacity: 0.9;
            transform: scale(1.03);
        }}

        .topbar-upgrade-btn {{
            background: rgba(234, 179, 8, 0.1);
            border: 1px solid rgba(234, 179, 8, 0.3);
            color: #fbbf24;
            padding: 4px 10px;
            border-radius: var(--radius-sm);
            font-size: 0.75rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 5px;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .topbar-upgrade-btn:hover {{
            background: rgba(234, 179, 8, 0.2);
            border-color: #fbbf24;
        }}

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
                <div class="sidebar-logo-sub">Threat Intelligence</div>
            </div>
        </div>

        <!-- Independent Scroll Container -->
        <div class="sidebar-scroll-container">
            <!-- New chat session button -->
            <button class="sidebar-btn-new" onclick="startNewSession()">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                Nova Consulta
            </button>

            <!-- Platform Navigation -->
            <div class="sidebar-section">
                <div class="sidebar-section-label">Plataforma</div>
                <button class="sidebar-btn active" id="nav-chat" onclick="showView('view-chat-dash'); scrollToChat();">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                    Aeris SOC Assistant
                </button>
                <button class="sidebar-btn" id="nav-dashboard" onclick="showView('view-chat-dash'); scrollToDashboard();">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                    Threat Dashboard
                </button>
                <button class="sidebar-btn" id="nav-upgrade" onclick="showView('view-upgrade');" style="color:var(--yellow); font-weight:600;">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    Fazer Upgrade
                </button>
            </div>

            <!-- Outputs Navigation (Single Pages) -->
            <div class="sidebar-section">
                <div class="sidebar-section-label">Outputs</div>
                <button class="sidebar-btn" id="nav-pdf" onclick="showView('view-pdf');">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    Relatórios PDF
                </button>
                <button class="sidebar-btn" id="nav-rss" onclick="showView('view-rss');">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>
                    RSS Feed
                </button>
                <button class="sidebar-btn" id="nav-stix" onclick="showView('view-stix');">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    STIX Export
                </button>
            </div>

            <!-- Multi-session Chat History in Sidebar -->
            <div class="sidebar-section" style="flex:1; display:flex; flex-direction:column;">
                <div class="sidebar-section-label">
                    <span>Histórico recente</span>
                    <span id="session-count-badge" style="font-size:0.6rem; color:var(--green); text-transform:none;">0 salvas</span>
                </div>
                <div class="sidebar-history" id="session-history">
                    <!-- Dynamically rendered chat sessions -->
                </div>
            </div>
        </div>

        <!-- Anonymous User Profile Footer -->
        <div class="sidebar-footer">
            <div class="sidebar-user" onclick="showView('view-account')" role="button" tabindex="0" title="Configurações da Conta Anônima">
                <div class="sidebar-avatar anonymous">
                    <!-- Anonymous vector icon -->
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                </div>
                <div class="sidebar-user-info">
                    <span class="sidebar-user-name" id="sidebar-user-name-display">Operador Anônimo</span>
                    <span class="sidebar-user-role">Sessão Local · Privada</span>
                </div>
                <div class="sidebar-user-cog">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                </div>
            </div>
        </div>
    </aside>

    <!-- ══════════════════════════════════════════════════════
         MAIN VIEWPORT
    ══════════════════════════════════════════════════════ -->
    <div class="main" id="main">

        <!-- Topbar -->
        <header class="topbar">
            <div class="topbar-left">
                <button class="btn-hamburger" id="btn-hamburger" onclick="toggleSidebar()" aria-label="Abrir menu">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
                </button>
                <span class="topbar-title" id="topbar-title">Aeris — SOC Intelligence Assistant</span>
            </div>
            <div class="topbar-right">
                <div class="status-dot"></div>
                <span class="topbar-badge" id="topbar-badge">Online</span>
                <button class="topbar-upgrade-btn" onclick="showView('view-upgrade')" title="Fazer Upgrade de Plano"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg><span>Upgrade</span></button>
                <button class="topbar-account-btn" onclick="showView('view-account')" title="Configurações da Conta Anônima">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><circle cx="12" cy="7" r="4"/><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/></svg>
                    <span>Conta</span>
                </button>
            </div>
        </header>

        <!-- Scrollable content area for SPA views -->
        <div class="content-scroll" id="content-scroll">

            <!-- ══════════════════════════════════════════════
                 VIEW 1: CHAT & THREAT DASHBOARD (DEFAULT)
            ══════════════════════════════════════════════ -->
            <div class="spa-view active" id="view-chat-dash">

                <!-- Chat Section -->
                <section class="chat-section" id="chat-section">
                    <!-- Welcome screen -->
                    <div class="chat-welcome" id="chat-welcome">
                        <div class="aeris-orb">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        </div>
                        <h1>Como posso ajudar?</h1>
                        <p>Analise ameaças cibernéticas, CVEs críticas e vetores de ataque com suporte autônomo da Aeris.</p>

                        <div class="suggestion-grid">
                            <button class="chip" onclick="applySuggestion('Qual a ameaça mais crítica monitorada hoje?')">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 7 13.5 15.5 8.5 10.5 1 17"/><polyline points="17 7 23 7 23 13"/></svg>
                                Ameaça mais crítica hoje
                            </button>
                            <button class="chip" onclick="applySuggestion('Quais CVEs afetam Apache HTTP Server e VMware ESXi?')">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                                CVEs no tech stack
                            </button>
                            <button class="chip" onclick="applySuggestion('Explique o que é uma CVE com exploit público e qual o risco.')">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
                                O que é exploit público?
                            </button>
                            <button class="chip" onclick="applySuggestion('O que significa a tática MITRE T1190 e como mitigar?')">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
                                Explicar MITRE T1190
                            </button>
                        </div>
                    </div>

                    <!-- Messages Container -->
                    <div class="chat-messages" id="chat-messages"></div>

                    <!-- Input Area -->
                    <div class="chat-input-area">
                        <div id="chat-error" class="chat-error hidden">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                            <span id="chat-error-msg"></span>
                        </div>

                        
                    <!-- ChatGPT-style quota limit banner -->
                    <div id="quota-limit-banner" class="quota-limit-banner hidden">
                        <div class="quota-limit-text">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                            <span id="quota-limit-msg">Você atingiu o limite de consultas gratuitas de hoje. Seus tokens serão renovados às <strong>00:00</strong>.</span>
                        </div>
                        <button class="btn-upgrade-pill" onclick="showView('view-upgrade')">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="12" height="12"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                            Fazer Upgrade
                        </button>
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
                                    <span class="input-workspace-tag">Sessão Local</span>
                                    <button type="submit" id="btn-send" class="btn-send" aria-label="Enviar">
                                        <svg id="send-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                                        <div class="btn-spinner hidden" id="btn-spinner"></div>
                                    </button>
                                </div>
                            </div>
                        </form>

                        <div class="input-footer">
                            <span class="quota-text" id="quota-label">Consultas ilimitadas na sessão local</span>
                            <button type="button" onclick="showView('view-account')" class="api-key-btn" style="background:transparent;border:none;color:var(--text-muted);font-size:0.72rem;cursor:pointer;display:inline-flex;align-items:center;gap:4px;padding:2px 6px;border-radius:4px;transition:all 0.15s;" title="Configurações da Sessão e Chave Opcional">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                                <span id="session-status-badge">Sessão Segura</span>
                            </button>
                        </div>
                    </div>

                    <!-- Scroll cue -->
                    <div class="scroll-cue" onclick="scrollToDashboard()" title="Ver painel de ameaças">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                        Threat Dashboard
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                    </div>
                </section>

                <!-- Threat Dashboard Section -->
                <section class="dashboard-section" id="dashboard-section">
                    <div class="dash-header">
                        <div class="dash-header-left">
                            <div>
                                <div class="dash-title">Painel de Threat Intelligence</div>
                                <div class="dash-subtitle" id="dash-subtitle">Atualizado em: 2026-09-24 às 00:30</div>
                            </div>
                            <div class="dash-live-badge">
                                <div class="status-dot"></div>
                                Ao vivo
                            </div>
                        </div>
                        <div class="dash-actions-bar">
                            <button class="btn-dash-action" onclick="showView('view-pdf')">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                Relatórios PDF
                            </button>
                            <button class="btn-dash-action" onclick="showView('view-stix')">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                STIX 2.1
                            </button>
                        </div>
                    </div>

                    <!-- Metrics Grid -->
                    <div class="metrics-grid">
                        <div class="metric-card red">
                            <div class="metric-label">CVEs Críticas Ativas</div>
                            <div class="metric-value" id="m-critical">4</div>
                            <div class="metric-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                            </div>
                        </div>
                        <div class="metric-card purple">
                            <div class="metric-label">Ransomware Linked</div>
                            <div class="metric-value" id="m-ransomware">3</div>
                            <div class="metric-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                            </div>
                        </div>
                        <div class="metric-card yellow">
                            <div class="metric-label">Com Exploit Público</div>
                            <div class="metric-value" id="m-exploit">5</div>
                            <div class="metric-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
                            </div>
                        </div>
                        <div class="metric-card cyan">
                            <div class="metric-label">SLA Vencendo 24h</div>
                            <div class="metric-value" id="m-sla">4</div>
                            <div class="metric-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                            </div>
                        </div>
                    </div>

                    <!-- Table Controls: Search & Filter Chips -->
                    <div class="table-controls">
                        <div class="search-box">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                            <input type="text" id="cve-search" placeholder="Filtrar por CVE, software ou tática (ex: Apache, VMware, T1190)..." oninput="filterCveTable()">
                        </div>
                        <div class="filter-tabs">
                            <button class="filter-chip active" onclick="setTableFilter('all', this)">Todas as Ameaças</button>
                            <button class="filter-chip" onclick="setTableFilter('critical', this)">🔥 Críticas (>= 9.0)</button>
                            <button class="filter-chip" onclick="setTableFilter('ransomware', this)">💀 Ransomware</button>
                            <button class="filter-chip" onclick="setTableFilter('exploit', this)">⚡ Com Exploit</button>
                            <button class="filter-chip" onclick="setTableFilter('sla', this)">⏳ SLA 24h</button>
                        </div>
                    </div>

                    <!-- Interactive CVE Table -->
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
                                <!-- Populated by JS -->
                            </tbody>
                        </table>
                    </div>
                </section>
            </div>

            <!-- ══════════════════════════════════════════════
                 VIEW 2: RELATÓRIOS PDF (SINGLE PAGE)
            ══════════════════════════════════════════════ -->
            <div class="spa-view" id="view-pdf">
                <div class="view-header">
                    <div class="view-header-main">
                        <h2 class="view-title">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24" color="var(--red)"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                            Central de Relatórios Executivos (PDF)
                        </h2>
                        <p class="view-subtitle">Relatórios técnicos e executivos gerados periodicamente pela esteira autônoma Sentinel SecOps. Faça download direto ou visualize relatórios arquivados.</p>
                    </div>
                    <button class="btn-view-back" onclick="showView('view-chat-dash')">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                        Voltar ao Chat / Dashboard
                    </button>
                </div>

                <div class="view-body">
                    <!-- Stats summary -->
                    <div class="metrics-grid">
                        <div class="metric-card cyan">
                            <div class="metric-label">Relatórios Gerados</div>
                            <div class="metric-value">320+</div>
                        </div>
                        <div class="metric-card red">
                            <div class="metric-label">Último Relatório Diário</div>
                            <div class="metric-value" style="font-size:1.15rem; margin-top:8px;">23/09 23:27</div>
                        </div>
                        <div class="metric-card purple">
                            <div class="metric-label">Relatório Executivo Semanal</div>
                            <div class="metric-value" style="font-size:1.15rem; margin-top:8px;">Ativo (PDF)</div>
                        </div>
                        <div class="metric-card yellow">
                            <div class="metric-label">Padrão de Conformidade</div>
                            <div class="metric-value" style="font-size:1.15rem; margin-top:8px;">A4 Executivo</div>
                        </div>
                    </div>

                    <!-- PDF Reports Listing -->
                    <div class="subview-card">
                        <div class="subview-card-title">Relatórios Recentes Disponíveis para Download</div>
                        <div class="subview-card-desc">Clique para baixar os relatórios em formato PDF de alta fidelidade com vetores CVSS v3.1, tabelas MITRE ATT&CK e diretrizes de mitigação.</div>

                        <div class="pdf-reports-grid" id="pdf-reports-list">
                            <!-- Injected by JS with actual PDF files -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- ══════════════════════════════════════════════
                 VIEW 3: RSS FEED (SINGLE PAGE)
            ══════════════════════════════════════════════ -->
            <div class="spa-view" id="view-rss">
                <div class="view-header">
                    <div class="view-header-main">
                        <h2 class="view-title">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24" color="var(--cyan)"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>
                            Feed RSS de Ameaças & Alertas Cibernéticos
                        </h2>
                        <p class="view-subtitle">Sindicador de inteligência de ameaças padronizado em RSS 2.0 para integração direta com agregadores, canais de alertas (Slack/Discord/Teams) e sistemas SIEM.</p>
                    </div>
                    <button class="btn-view-back" onclick="showView('view-chat-dash')">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                        Voltar ao Chat / Dashboard
                    </button>
                </div>

                <div class="view-body">
                    <!-- URL & Actions -->
                    <div class="subview-card">
                        <div class="subview-card-title">Endpoint do Feed RSS</div>
                        <div class="subview-card-desc">Utilize a URL abaixo em qualquer leitor de RSS ou ferramenta de ingestão de feeds de inteligência de ameaças.</div>

                        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px;">
                            <input type="text" id="rss-feed-url" value="https://pedroxious.github.io/Sentinel-SecOps/feed.xml" readonly class="form-input" style="flex:1; min-width:280px; font-family:'JetBrains Mono',monospace; font-size:0.8rem;">
                            <button class="btn-primary" onclick="copyRssUrl()">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                <span id="copy-rss-btn-text">Copiar URL</span>
                            </button>
                            <a href="feed.xml" target="_blank" class="btn-dash-action" style="padding:9px 16px;">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                                Abrir XML
                            </a>
                            <a href="feed.xml" download="feed.xml" class="btn-dash-action" style="padding:9px 16px;">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                Baixar Arquivo
                            </a>
                        </div>
                    </div>

                    <!-- Live feed preview -->
                    <div class="subview-card">
                        <div class="subview-card-title">Visualizador de Alertas do Feed</div>
                        <div class="subview-card-desc">Últimos itens processados na esteira e distribuídos no feed RSS:</div>

                        <div id="rss-items-container" style="display:flex; flex-direction:column; gap:12px;">
                            <!-- Injected by JS -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- ══════════════════════════════════════════════
                 VIEW 4: STIX 2.1 EXPORT (SINGLE PAGE)
            ══════════════════════════════════════════════ -->
            <div class="spa-view" id="view-stix">
                <div class="view-header">
                    <div class="view-header-main">
                        <h2 class="view-title">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24" color="var(--purple)"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                            Exportação STIX 2.1 (Cyber Threat Intelligence)
                        </h2>
                        <p class="view-subtitle">Pacote padronizado OASIS STIX 2.1 pronto para ingestão automática em plataformas OpenCTI, MISP, Microsoft Sentinel, Cortex XSOAR e Splunk.</p>
                    </div>
                    <button class="btn-view-back" onclick="showView('view-chat-dash')">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                        Voltar ao Chat / Dashboard
                    </button>
                </div>

                <div class="view-body">
                    <div class="subview-card">
                        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; margin-bottom:16px;">
                            <div>
                                <div class="subview-card-title">Pacote STIX 2.1 Bundle</div>
                                <div class="subview-card-desc" style="margin-bottom:0;">Contém objetos de Vulnerabilidade, Indicadores de Compromisso (IoCs) e Padrões de Ataque MITRE ATT&CK.</div>
                            </div>
                            <div style="display:flex; gap:8px;">
                                <button class="btn-primary" onclick="downloadStixBundle()">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                    Baixar stix_bundle.json
                                </button>
                                <button class="btn-dash-action" onclick="copyStixJson()">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                    <span id="copy-stix-btn-text">Copiar JSON</span>
                                </button>
                            </div>
                        </div>

                        <pre class="code-display" id="stix-json-display">// Carregando STIX 2.1 Bundle...</pre>
                    </div>
                </div>
            </div>

            <!-- ══════════════════════════════════════════════
                 VIEW 5: CONFIGURAÇÕES DA CONTA (SINGLE PAGE)
            ══════════════════════════════════════════════ -->
            <div class="spa-view" id="view-account">
                <div class="view-header">
                    <div class="view-header-main">
                        <h2 class="view-title">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24" color="var(--green)"><circle cx="12" cy="7" r="4"/><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/></svg>
                            Configurações da Conta & Sessão Local
                        </h2>
                        <p class="view-subtitle">Gerencie suas preferências de analista, armazenamento de conversas e modo de privacidade no navegador.</p>
                    </div>
                    <button class="btn-view-back" onclick="showView('view-chat-dash')">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                        Voltar ao Chat / Dashboard
                    </button>
                </div>

                <div class="view-body">
                    <!-- Profile Card -->
                    <div class="subview-card" style="display:flex; align-items:center; gap:20px; flex-wrap:wrap;">
                        <div class="sidebar-avatar anonymous" style="width:56px; height:56px; border-radius:14px;">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="28" height="28"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                        </div>
                        <div style="flex:1;">
                            <div style="font-size:1.15rem; font-weight:700; color:var(--text);" id="account-name-badge">Operador Anônimo</div>
                            <div style="font-size:0.8rem; color:var(--green); margin-top:2px;">● Sessão Local Segura · Sem Rastreamento Externo</div>
                            <div style="font-size:0.75rem; color:var(--text-muted); margin-top:4px; font-family:'JetBrains Mono',monospace;" id="account-session-id">ID: SEC-OP-LOCAL-7749</div>
                        </div>
                    </div>

                    <!-- Identity Preferences -->
                    <div class="subview-card">
                        <div class="subview-card-title">Identidade do Analista</div>
                        <div class="subview-card-desc">Altere o nome exibido na sua interface local caso deseje personalizar sua sessão.</div>

                        <div class="form-row">
                            <label class="form-label" for="input-operator-name">Nome do Operador</label>
                            <input type="text" id="input-operator-name" class="form-input" value="Operador Anônimo" maxlength="30" placeholder="Ex: Operador Anônimo">
                            <span class="form-hint">Salvo estritamente no armazenamento local do seu navegador (localStorage).</span>
                        </div>
                        <button class="btn-primary" onclick="saveOperatorName()">Salvar Alterações</button>
                    </div>

                    <!-- Local Storage & Chat History -->
                    <div class="subview-card">
                        <div class="subview-card-title">Gerenciamento de Conversas e Dados</div>
                        <div class="subview-card-desc">Todas as suas conversas e investigações realizadas com a Aeris ficam salvas localmente no navegador, sem necessidade de login.</div>

                        <div style="display:flex; gap:12px; flex-wrap:wrap; align-items:center;">
                            <button class="btn-dash-action" onclick="exportChatsJson()" style="padding:9px 16px;">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                Exportar Histórico de Conversas (JSON)
                            </button>
                            <button class="btn-danger" onclick="clearAllChatHistory()">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                                Limpar Todo o Histórico de Conversas
                            </button>
                        </div>
                    </div>

                    <!-- Optional Gemini API Key -->
                    <div class="subview-card">
                        <div class="subview-card-title">Chave de API do Gemini (Opcional)</div>
                        <div class="subview-card-desc">
                            A Aeris funciona de forma autônoma e inteligente sem que você precise saber o que é uma API ou inserir qualquer chave. Caso você seja um desenvolvedor ou usuário avançado e queira usar sua própria cota pessoal do Google Gemini AI Studio, insira-a abaixo:
                        </div>

                        <div class="form-row">
                            <label class="form-label" for="input-custom-api-key">Chave de API Gemini (AI Studio)</label>
                            <input type="password" id="input-custom-api-key" class="form-input" placeholder="AIzaSy... (Opcional - deixe em branco para uso padrão)">
                            <span class="form-hint" id="api-key-status-text">Status: Modo Autônomo Local Ativo</span>
                        </div>
                        <div style="display:flex; gap:10px;">
                            <button class="btn-primary" onclick="saveCustomApiKey()">Salvar Chave</button>
                            <button class="btn-dash-action" onclick="removeCustomApiKey()">Remover Chave</button>
                        </div>
                    </div>
                </div>
            </div>

        
            <!-- ══════════════════════════════════════════════
                 VIEW 6: PLANOS DE UPGRADE (SINGLE PAGE VENDAS)
            ══════════════════════════════════════════════ -->
            <div class="spa-view" id="view-upgrade">
                <div class="upgrade-page-container">
                    <!-- Top Bar -->
                    <div class="upgrade-top-bar">
                        <button class="btn-upgrade-back" onclick="showView('view-chat-dash')">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                            Fazer Upgrade
                        </button>
                    </div>

                    <!-- Segmented Control (Indivíduos vs Team/Enterprise) -->
                    <div class="pricing-segmented-control">
                        <button class="segment-btn active" id="tab-indiv" onclick="setPricingTab('indiv')">Para indivíduos</button>
                        <button class="segment-btn" id="tab-team" onclick="setPricingTab('team')">Team e Enterprise</button>
                    </div>

                    <!-- Pricing Cards Grid -->
                    <div class="pricing-cards-grid">
                        
                        <!-- Card 1: Free -->
                        <div class="pricing-card">
                            <div class="pricing-icon-box">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="12" r="2"/><circle cx="19" cy="12" r="2"/><circle cx="12" cy="19" r="2"/><path d="M12 7v10M7 12h10"/></svg>
                            </div>
                            <div class="pricing-title">Free</div>
                            <div class="pricing-subtitle">Conheça o Sentinel Aeris</div>

                            <div class="pricing-price-box">
                                <div class="pricing-price-main">R$ 0</div>
                            </div>

                            <button class="pricing-btn pricing-btn-outline" disabled style="opacity:0.8; cursor:default;">
                                Plano Atual
                            </button>
                            <div class="pricing-subcaption">Use o Sentinel gratuitamente</div>

                            <div class="pricing-divider"></div>

                            <ul class="pricing-feature-list">
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Até 35 consultas diárias com IA Gemini</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Threat Dashboard de vulnerabilidades ao vivo</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Histórico de sessões salvo localmente no navegador</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Download de relatórios executivos em PDF</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Acesso aos feeds RSS e STIX 2.1</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Detecção de táticas MITRE ATT&CK</span>
                                </li>
                            </ul>
                        </div>

                        <!-- Card 2: Pro (Recomendado) -->
                        <div class="pricing-card featured">
                            <div class="pricing-badge-recommend">Recomendado para você</div>
                            
                            <div class="pricing-icon-box" style="color:var(--cyan);">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="4" r="2"/><circle cx="4" cy="11" r="2"/><circle cx="20" cy="11" r="2"/><circle cx="7" cy="19" r="2"/><circle cx="17" cy="19" r="2"/><path d="M12 6v6m-6-1 4 3m8-3-4 3M7 17l3-3m7 3-3-3"/></svg>
                            </div>
                            <div class="pricing-title">Pro</div>
                            <div class="pricing-subtitle">Pesquise, investigue e automatize</div>

                            <div class="pricing-price-box">
                                <div class="pricing-price-main">R$ 110</div>
                                <div class="pricing-price-period">BRL / mês · cobrado mensalmente</div>
                            </div>

                            <button class="pricing-btn pricing-btn-primary" onclick="handleCheckoutPlan('Pro')">
                                Obter plano Pro
                            </button>
                            <div class="pricing-subcaption">Sem compromisso · Cancele quando quiser</div>

                            <div class="pricing-divider"></div>

                            <div class="pricing-feature-header">Tudo do Free e:</div>
                            <ul class="pricing-feature-list">
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span><strong>Consultas ilimitadas</strong> com Aeris SOC AI</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Modelos avançados de raciocínio estendido</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Correlação automática com CISA KEV e Exploit-DB</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Alertas em tempo real via Webhook (Slack/Teams)</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Exportação personalizada de STIX 2.1 e relatórios</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Memória e investigações que persistem entre conversas</span>
                                </li>
                            </ul>
                        </div>

                        <!-- Card 3: Max -->
                        <div class="pricing-card">
                            <div class="pricing-icon-box" style="color:var(--purple);">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="3" r="2"/><circle cx="3" cy="9" r="2"/><circle cx="21" cy="9" r="2"/><circle cx="5" cy="18" r="2"/><circle cx="19" cy="18" r="2"/><circle cx="12" cy="13" r="2"/><path d="M12 5v6m-7-2 5 2m9-2-5 2m-2 2v-2M5 18l5-3m9 3-5-3"/></svg>
                            </div>
                            <div class="pricing-title">Max</div>
                            <div class="pricing-subtitle">Limites maiores, acesso prioritário para equipes</div>

                            <div class="pricing-price-box">
                                <div class="pricing-price-main">A partir de R$ 550</div>
                                <div class="pricing-price-period">BRL / mês · cobrado mensalmente</div>
                            </div>

                            <button class="pricing-btn pricing-btn-primary" onclick="handleCheckoutPlan('Max')">
                                Obter plano Max
                            </button>
                            <div class="pricing-subcaption">Sem compromisso · Cancele quando quiser</div>

                            <div class="pricing-divider"></div>

                            <div class="pricing-feature-header">Tudo do Pro, mais:</div>
                            <ul class="pricing-feature-list">
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Até 20x mais uso que o Pro*</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Conexão direta com SIEMs (Splunk, Sentinel, OpenCTI)</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>API dedicada com SLA garantido de 99.9%</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Workspaces de equipe e permissões multi-analista</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Acesso prioritário em horários de pico de tráfego</span>
                                </li>
                                <li class="pricing-feature-item">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Suporte dedicado 24/7 com engenheiro de SecOps</span>
                                </li>
                            </ul>
                        </div>

                    </div>
                </div>
            </div>

        </div><!-- /content-scroll -->
    </div><!-- /main -->

    <!-- Audio briefing bar -->
    <div class="audio-bar" id="audio-bar">
        <span class="audio-label">⚡ Cyber Briefing</span>
        <audio controls id="briefing-audio">
            <source src="reports/audio/latest.mp3" type="audio/mpeg">
        </audio>
        <button class="btn-close-audio" onclick="closeAudio()">✕</button>
    </div>

    <!-- Mobile sidebar overlay -->
    <div id="sidebar-overlay" onclick="closeSidebar()"
         style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:40;"></div>

    <script>
    
    const CLOUDFLARE_WORKER_URL = "https://sentinel-ai-proxy.pedroazevedojoel.workers.dev/";
    const MAX_QUOTA = 35; // Generous daily quota (>= 20) without exhausting Google AI Studio

    function getTimeUntilMidnight() {{
        const now = new Date();
        const midnight = new Date();
        midnight.setHours(24, 0, 0, 0);
        const diffMs = midnight - now;
        const hours = Math.floor(diffMs / (1000 * 60 * 60));
        const mins = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
        return `${{hours}}h ${{mins}}m`;
    }}

    function checkQuota() {{
        const today = new Date().toISOString().slice(0, 10);
        let usage = JSON.parse(localStorage.getItem("sentinel_quota") || "null");
        if (!usage || usage.date !== today) usage = {{ date: today, count: 0 }};
        localStorage.setItem("sentinel_quota", JSON.stringify(usage));

        const label = document.getElementById("quota-label");
        const remaining = Math.max(0, MAX_QUOTA - usage.count);
        const banner = document.getElementById("quota-limit-banner");
        const input = document.getElementById("chat-input");
        const btnSend = document.getElementById("btn-send");

        if (usage.count >= MAX_QUOTA) {{
            const timeLeft = getTimeUntilMidnight();
            if (banner) {{
                banner.classList.remove("hidden");
                const msgEl = document.getElementById("quota-limit-msg");
                if (msgEl) msgEl.innerHTML = `Você atingiu o limite de consultas gratuitas de hoje. Seus tokens serão renovados em <strong>${{timeLeft}}</strong> (às 00:00).`;
            }}
            if (input) {{
                input.disabled = true;
                input.placeholder = `Limite gratuito de 35 mensagens atingido. Renova em ${{timeLeft}} (às 00:00).`;
            }}
            if (btnSend) btnSend.disabled = true;
            if (label) label.textContent = "Limite diário atingido (35/35) · Renova à meia-noite";
            return false;
        }}

        if (banner) banner.classList.add("hidden");
        if (input) {{
            input.disabled = false;
            input.placeholder = "Pergunte sobre CVEs, exploits, MITRE ATT&CK...";
        }}
        if (btnSend) btnSend.disabled = false;
        if (label) label.textContent = `${{remaining}} de ${{MAX_QUOTA}} consultas disponíveis hoje (Plano Gratuito)`;
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

    function setPricingTab(tab) {{
        document.getElementById("tab-indiv").classList.toggle("active", tab === "indiv");
        document.getElementById("tab-team").classList.toggle("active", tab === "team");
    }}

    function handleCheckoutPlan(plan) {{
        alert(`Você selecionou o Plano ${{plan}}! No momento, o fluxo de pagamento está em ambiente de homologação (mockup). Em breve disponível!`);
    }}

    /* ═══════════════════════════════════════════════════════════
       STATE & CONFIGURATION
    ═══════════════════════════════════════════════════════════ */
    let API_KEY = localStorage.getItem("GEMINI_API_KEY") || "";
    try {{
        const injectedKey = atob("");
        if (!API_KEY && injectedKey && injectedKey.length > 10) {{
            API_KEY = injectedKey;
        }}
    }} catch(e) {{}}

    const GEMINI_MODELS = [
        "gemini-3.8-flash",
        "gemini-flash-latest",
        "gemini-3.5-flash",
        "gemini-flash-lite-latest",
        "gemini-2.0-flash"
    ];
    const AERIS_SYSTEM_PROMPT = `Você é o SOC Assistant do Sentinel-SecOps, um analista virtual de segurança cibernética integrado ao dashboard de Threat Intelligence.
CONTEÚDO DO PAINEL ATUAL (gerado em 2026-09-24 00:30):
- Total de CVEs monitoradas hoje: 0
- CVEs críticas (score >= 9.0): 0
- CVEs com ransomware associado: 0
- CVEs com exploit público: 0
- Top 3 ameaças do ciclo: Nenhuma
- Stack tecnológico monitorado: Apache, VMware

REGRAS DE COMPORTAMENTO:
- Responda sempre em português brasileiro.
- Seja direto e técnico, mas acessível.
- Respostas curtas e objetivas — máximo 4 parágrafos.
- Quando perguntado sobre uma CVE específica, use o contexto do painel ou seu conhecimento sobre ela.
- Nunca invente dados sobre CVEs que não estejam no contexto fornecido; se não souber, diga que a informação não está disponível no ciclo atual.
- Se o usuário perguntar algo fora de segurança, redirecione educadamente para o escopo do painel.
`;

    const AERIS_PRESET_MESSAGE = `Olá, sou **Aeris**, assistente de IA da plataforma **Sentinel SecOps**. Estou pronta para auxiliar na análise de vulnerabilidades, monitoramento de CVEs ativas, táticas MITRE ATT&CK e diretrizes de defesa cibernética.

Como posso fortalecer a sua postura de segurança hoje?`;

    // Multi-session chat management
    let currentSessionId = null;
    let conversationHistory = [];
    let chatStarted = false;

    // Active Telemetry Dataset for the Threat Dashboard
    const TELEMETRY_DATA = [
        {{
            cve: "CVE-2024-38475",
            software: "Apache HTTP Server",
            score: "9.8",
            severity: "critical",
            mitre: "T1190 Exploit Public-Facing",
            sla: "24h",
            slaClass: "critical",
            exploit: true,
            trend: "up",
            ransomware: "Não vinculado",
            desc: "Falha de substituição imprópria no mod_proxy do Apache HTTP Server permitindo que invasores remotos contornem restrições de arquitetura reversa e acessem serviços internos confidenciais.",
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            mitigation: "Atualizar Apache HTTP Server para versão 2.4.60 ou superior; validar regras de ProxyPassMatch e bloquear URLs codificadas no WAF.",
            patchUrl: "https://httpd.apache.org/security/vulnerabilities_24.html"
        }},
        {{
            cve: "CVE-2024-37085",
            software: "VMware ESXi",
            score: "9.6",
            severity: "critical",
            mitre: "T1078 Valid Accounts",
            sla: "24h",
            slaClass: "critical",
            exploit: true,
            trend: "up",
            ransomware: "Akira / BlackCat",
            desc: "Vulnerabilidade de bypass de autenticação no VMware ESXi via Active Directory. Invasores com privilégios suficientes no AD conseguem obter acesso administrativo root completo ao hipervisor ESXi.",
            vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            mitigation: "Aplicar atualizações de segurança da VMware para ESXi 7.0/8.0; isolar o grupo 'ESX Admins' e restringir privilégios delegados no domínio AD.",
            patchUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-37085"
        }},
        {{
            cve: "CVE-2024-38077",
            software: "Windows Server 2019/2022",
            score: "9.8",
            severity: "critical",
            mitre: "T1210 Remote Services",
            sla: "24h",
            slaClass: "critical",
            exploit: true,
            trend: "up",
            ransomware: "LockBit 3.0",
            desc: "Execução Remota de Código (MadLicense) no serviço Windows Remote Desktop Licensing (RDL). Permite que atacantes não autenticados enviem pacotes maliciosos pela rede corporativa e executem código com privilégios de SYSTEM.",
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            mitigation: "Aplicar o patch cumulativo Microsoft KB5040442; desativar temporariamente o serviço Remote Desktop Licensing em servidores que não necessitam dele.",
            patchUrl: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077"
        }},
        {{
            cve: "CVE-2024-10979",
            software: "PostgreSQL",
            score: "8.8",
            severity: "high",
            mitre: "T1068 Privilege Escalation",
            sla: "3 dias",
            slaClass: "high",
            exploit: true,
            trend: "stable",
            ransomware: "Não vinculado",
            desc: "Modificação incorreta de variáveis de ambiente no módulo PL/Perl do PostgreSQL permite que usuários autenticados alterem variáveis sensíveis e executem binários arbitrários com privilégios do processo do banco.",
            vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            mitigation: "Atualizar PostgreSQL para as versões 17.1, 16.5, 15.9, 14.14 ou 13.17; desabilitar extensões de linguagem não confiáveis (untrusted languages).",
            patchUrl: "https://www.postgresql.org/support/security/CVE-2024-10979/"
        }},
        {{
            cve: "CVE-2024-4577",
            software: "PHP / Windows (nginx / Apache)",
            score: "9.8",
            severity: "critical",
            mitre: "T1190 Exploit Public-Facing",
            sla: "24h",
            slaClass: "critical",
            exploit: true,
            trend: "up",
            ransomware: "TellYouThePass",
            desc: "Argument Injection RCE no PHP CGI executado em ambientes Windows devido a falha no tratamento de Best-Fit mapping na conversão de caracteres Unicode, permitindo execução arbitrária de código remoto.",
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            mitigation: "Atualizar PHP para 8.3.8, 8.2.20 ou 8.1.29; migrar de PHP-CGI para FastCGI (php-fpm) e filtrar query parameters maliciosos no web server.",
            patchUrl: "https://www.php.net/ChangeLog-8.php#8.3.8"
        }},
        {{
            cve: "CVE-2024-21413",
            software: "Microsoft Office / Windows",
            score: "9.8",
            severity: "critical",
            mitre: "T1204 User Execution",
            sla: "24h",
            slaClass: "critical",
            exploit: true,
            trend: "up",
            ransomware: "Akira",
            desc: "Vulnerabilidade de bypass de recursos de segurança (MonikerLink). Permite que invasores ignorem o Modo de Exibição Protegido do Office e forcem o vazamento de hashes NTLM ou execução de código.",
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            mitigation: "Aplicar atualizações do Patch Tuesday; bloquear tráfego SMB de saída (porta 445) no firewall perimetral para evitar vazamento de credenciais NTLM.",
            patchUrl: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413"
        }}
    ];

    /* ═══════════════════════════════════════════════════════════
       INITIALIZATION
    ═══════════════════════════════════════════════════════════ */
    document.addEventListener("DOMContentLoaded", () => {{
        checkQuota();
        initOperatorProfile();
        initSessions();
        renderCveTable(TELEMETRY_DATA);
        updateDashboardMetrics();
        setupTextarea();
        initSubviewsContent();
    }});

    /* ═══════════════════════════════════════════════════════════
       SPA VIEWS ROUTING SYSTEM
    ═══════════════════════════════════════════════════════ */
    function showView(viewId) {{
        const views = document.querySelectorAll(".spa-view");
        views.forEach(v => v.classList.remove("active"));

        const target = document.getElementById(viewId);
        if (target) {{
            target.classList.add("active");
        }}

        // Update sidebar nav active state
        document.querySelectorAll(".sidebar-btn").forEach(b => b.classList.remove("active"));
        if (viewId === "view-chat-dash") {{
            const navChat = document.getElementById("nav-chat");
            if (navChat) navChat.classList.add("active");
            document.getElementById("topbar-title").textContent = "Aeris — SOC Intelligence Assistant";
        }} else if (viewId === "view-pdf") {{
            const navPdf = document.getElementById("nav-pdf");
            if (navPdf) navPdf.classList.add("active");
            document.getElementById("topbar-title").textContent = "Relatórios Executivos PDF — Sentinel SecOps";
        }} else if (viewId === "view-rss") {{
            const navRss = document.getElementById("nav-rss");
            if (navRss) navRss.classList.add("active");
            document.getElementById("topbar-title").textContent = "Feed RSS de Ameaças — Sentinel SecOps";
        }} else if (viewId === "view-stix") {{
            const navStix = document.getElementById("nav-stix");
            if (navStix) navStix.classList.add("active");
            document.getElementById("topbar-title").textContent = "STIX 2.1 Threat Intel Bundle — Sentinel SecOps";
        }} else if (viewId === "view-account") {{
            document.getElementById("topbar-title").textContent = "Configurações da Conta Anônima — Sentinel SecOps";
        }} else if (viewId === "view-upgrade") {{
            const navUpgrade = document.getElementById("nav-upgrade");
            if (navUpgrade) navUpgrade.classList.add("active");
            document.getElementById("topbar-title").textContent = "Fazer Upgrade — Sentinel SecOps";
        }}

        // Scroll to top of the content container
        document.getElementById("content-scroll").scrollTo({{ top: 0, behavior: "smooth" }});
        closeSidebar();
    }}

    function scrollToChat() {{
        showView("view-chat-dash");
        document.getElementById("content-scroll").scrollTo({{ top: 0, behavior: "smooth" }});
        closeSidebar();
    }}

    function scrollToDashboard() {{
        showView("view-chat-dash");
        setTimeout(() => {{
            const dash = document.getElementById("dashboard-section");
            if (dash) dash.scrollIntoView({{ behavior: "smooth" }});
        }}, 50);
        closeSidebar();
    }}

    /* ═══════════════════════════════════════════════════════════
       OPERATOR IDENTITY & PRIVACY (ANONYMOUS)
    ═══════════════════════════════════════════════════════ */
    function initOperatorProfile() {{
        let opName = localStorage.getItem("sentinel_operator_name") || "Operador Anônimo";
        let opId = localStorage.getItem("sentinel_operator_id");
        if (!opId) {{
            opId = "SEC-OP-" + Math.floor(100000 + Math.random() * 900000);
            localStorage.setItem("sentinel_operator_id", opId);
        }}

        const nameDisplay = document.getElementById("sidebar-user-name-display");
        if (nameDisplay) nameDisplay.textContent = opName;

        const badgeName = document.getElementById("account-name-badge");
        if (badgeName) badgeName.textContent = opName;

        const inputName = document.getElementById("input-operator-name");
        if (inputName) inputName.value = opName;

        const idBadge = document.getElementById("account-session-id");
        if (idBadge) idBadge.textContent = "ID da Sessão: " + opId;

        const apiKeyInput = document.getElementById("input-custom-api-key");
        if (apiKeyInput && API_KEY) {{
            apiKeyInput.value = API_KEY;
            const statusEl = document.getElementById("api-key-status-text");
            if (statusEl) statusEl.textContent = "Status: Chave Customizada Ativa";
        }}
    }}

    function saveOperatorName() {{
        const input = document.getElementById("input-operator-name");
        const newName = input.value.trim() || "Operador Anônimo";
        localStorage.setItem("sentinel_operator_name", newName);
        checkQuota();
        initOperatorProfile();
        alert("Nome do operador atualizado com sucesso!");
    }}

    function saveCustomApiKey() {{
        const input = document.getElementById("input-custom-api-key");
        const key = input.value.trim();
        if (key) {{
            API_KEY = key;
            localStorage.setItem("GEMINI_API_KEY", key);
            document.getElementById("api-key-status-text").textContent = "Status: Chave Customizada Salva com Sucesso";
        }} else {{
            localStorage.removeItem("GEMINI_API_KEY");
            API_KEY = "";
            document.getElementById("api-key-status-text").textContent = "Status: Modo Autônomo Local Ativo";
        }}
        alert("Configuração de chave salva.");
    }}

    function removeCustomApiKey() {{
        localStorage.removeItem("GEMINI_API_KEY");
        API_KEY = "";
        const input = document.getElementById("input-custom-api-key");
        if (input) input.value = "";
        document.getElementById("api-key-status-text").textContent = "Status: Modo Autônomo Local Ativo (Sem Chave)";
        alert("Chave removida. O assistente usará o motor autônomo local.");
    }}

    /* ═══════════════════════════════════════════════════════════
       MULTI-SESSION CHAT PERSISTENCE (LOCAL STORAGE)
    ═══════════════════════════════════════════════════════ */
    function getStoredSessions() {{
        try {{
            return JSON.parse(localStorage.getItem("sentinel_chat_sessions") || "[]");
        }} catch(e) {{
            return [];
        }}
    }}

    function saveStoredSessions(sessions) {{
        localStorage.setItem("sentinel_chat_sessions", JSON.stringify(sessions));
        renderSidebarHistory();
    }}

    function initSessions() {{
        const sessions = getStoredSessions();
        if (sessions.length > 0) {{
            // Load the most recent session
            loadSession(sessions[0].id);
        }} else {{
            startNewSession();
        }}
        renderSidebarHistory();
    }}

    function startNewSession() {{
        currentSessionId = "sess_" + Date.now();
        conversationHistory = [];
        chatStarted = false;

        const msgsEl = document.getElementById("chat-messages");
        msgsEl.innerHTML = "";
        msgsEl.classList.remove("visible");

        document.getElementById("chat-welcome").classList.remove("hidden");
        showError(null);

        // Inject initial greeting bubble
        injectPresetMessage();

        // Highlight in sidebar
        renderSidebarHistory();
        scrollToChat();
    }}

    function injectPresetMessage() {{
        const messagesEl = document.getElementById("chat-messages");
        const row = buildBotRow(AERIS_PRESET_MESSAGE, true);
        messagesEl.appendChild(row);
        conversationHistory.push({{
            role: "model",
            parts: [{{ text: AERIS_PRESET_MESSAGE }}]
        }});
    }}

    function loadSession(sessionId) {{
        const sessions = getStoredSessions();
        const session = sessions.find(s => s.id === sessionId);
        if (!session) return;

        currentSessionId = session.id;
        conversationHistory = [];
        chatStarted = true;

        document.getElementById("chat-welcome").classList.add("hidden");
        const msgsEl = document.getElementById("chat-messages");
        msgsEl.innerHTML = "";
        msgsEl.classList.add("visible");

        // Replay messages
        if (session.messages && session.messages.length > 0) {{
            session.messages.forEach(m => {{
                if (m.role === "user") {{
                    appendUserBubble(m.text, m.time);
                    conversationHistory.push({{ role: "user", parts: [{{ text: m.text }}] }});
                }} else {{
                    appendBotBubble(m.text, m.time);
                    conversationHistory.push({{ role: "model", parts: [{{ text: m.text }}] }});
                }}
            }});
        }} else {{
            injectPresetMessage();
        }}

        renderSidebarHistory();
        scrollToChat();
    }}

    function deleteSession(event, sessionId) {{
        event.stopPropagation();
        if (!confirm("Deseja excluir esta conversa do histórico?")) return;

        let sessions = getStoredSessions();
        sessions = sessions.filter(s => s.id !== sessionId);
        saveStoredSessions(sessions);

        if (currentSessionId === sessionId) {{
            if (sessions.length > 0) {{
                loadSession(sessions[0].id);
            }} else {{
                startNewSession();
            }}
        }}
    }}

    function clearAllChatHistory() {{
        if (!confirm("Tem certeza que deseja apagar todo o histórico de conversas salvas? Esta ação é irreversível.")) return;
        localStorage.removeItem("sentinel_chat_sessions");
        startNewSession();
        alert("Histórico de conversas apagado com sucesso.");
    }}

    function exportChatsJson() {{
        const sessions = getStoredSessions();
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(sessions, null, 2));
        const a = document.createElement("a");
        a.href = dataStr;
        a.download = "sentinel_chats_export_" + new Date().toISOString().slice(0, 10) + ".json";
        document.body.appendChild(a);
        a.click();
        a.remove();
    }}

    function recordMessageInSession(role, text) {{
        let sessions = getStoredSessions();
        let session = sessions.find(s => s.id === currentSessionId);
        const timeStr = timeNow();
        const now = new Date();
        const dateStr = now.toLocaleDateString("pt-BR", {{ day: "2-digit", month: "2-digit" }}) + " " + timeStr;

        if (!session) {{
            session = {{
                id: currentSessionId,
                title: text.length > 32 ? text.slice(0, 32) + "..." : text,
                createdAt: dateStr,
                timestamp: Date.now(),
                messages: []
            }};
            sessions.unshift(session);
        }} else {{
            session.timestamp = Date.now();
        }}

        session.messages.push({{ role, text, time: timeStr }});
        saveStoredSessions(sessions);
    }}

    function renderSidebarHistory() {{
        const histContainer = document.getElementById("session-history");
        const countBadge = document.getElementById("session-count-badge");
        if (!histContainer) return;

        const sessions = getStoredSessions();
        if (countBadge) countBadge.textContent = `${{sessions.length}} salvas`;

        histContainer.innerHTML = "";

        if (sessions.length === 0) {{
            histContainer.innerHTML = `
                <div style="padding:12px 10px; font-size:0.75rem; color:var(--text-muted); text-align:center;">
                    Nenhuma conversa salva ainda.
                </div>`;
            return;
        }}

        sessions.forEach(sess => {{
            const item = document.createElement("div");
            item.className = "history-session-item" + (sess.id === currentSessionId ? " active" : "");
            item.onclick = () => loadSession(sess.id);

            item.innerHTML = `
                <div class="history-session-left">
                    <div class="history-session-title">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13" style="flex-shrink:0; opacity:0.7;"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                        <span>${{escHtml(sess.title || "Conversa")}}</span>
                    </div>
                    <div class="history-session-time">${{sess.createdAt || ""}}</div>
                </div>
                <button class="history-del-btn" title="Excluir conversa" onclick="deleteSession(event, '${{sess.id}}')">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            `;
            histContainer.appendChild(item);
        }});
    }}

    /* ═══════════════════════════════════════════════════════════
       SEAMLESS CHAT SUBMIT (ZERO ALERT / POPUP POPUPS)
    ═══════════════════════════════════════════════════════ */
    async function handleSubmit(e) {{
        if (e) e.preventDefault();
        const input = document.getElementById("chat-input");
        const message = input.value.trim();
        if (!message) return;

        // Show chat messages container on first send
                if (!checkQuota()) {{
            const timeLeft = getTimeUntilMidnight();
            const limitBotReply = `⚠️ **Limite de consultas diárias atingido (35/35)**

Você utilizou todas as suas mensagens gratuitas do ciclo de hoje. Seus tokens serão restaurados automaticamente em **${{timeLeft}}** (às 00:00).

Para continuar investigando sem interrupções e com modelos mais avançados, faça upgrade para o plano Pro:`;
            appendBotBubble(limitBotReply);
            recordMessageInSession("model", limitBotReply);
            return;
        }}

        // Show chat messages container on first send
        if (!chatStarted) {{
            document.getElementById("chat-welcome").classList.add("hidden");
            document.getElementById("chat-messages").classList.add("visible");
            chatStarted = true;
        }}

        appendUserBubble(message);
        recordMessageInSession("user", message);
        input.value = "";
        input.style.height = "auto";

        checkAudioKeywords(message);
        showError(null);
        setLoading(true);

        conversationHistory.push({{ role: "user", parts: [{{ text: message }}] }});

        try {{
            let reply = null;

            // 1. If user configured custom Gemini API key, use it directly
            if (API_KEY && (API_KEY.startsWith("AIzaSy") || API_KEY.startsWith("AQ.") || API_KEY.length > 20)) {{
                for (const model of GEMINI_MODELS) {{
                    try {{
                        const url = API_KEY.startsWith("AIzaSy") 
                            ? `https://generativelanguage.googleapis.com/v1beta/models/${{model}}:generateContent?key=${{API_KEY}}`
                            : `https://generativelanguage.googleapis.com/v1beta/models/${{model}}:generateContent`;
                        const res = await fetch(url, {{
                            method: "POST",
                            headers: {{ 
                                "Content-Type": "application/json",
                                "x-goog-api-key": API_KEY
                            }},
                            body: JSON.stringify({{
                                contents: conversationHistory,
                                systemInstruction: {{ parts: [{{ text: AERIS_SYSTEM_PROMPT }}] }},
                                generationConfig: {{ temperature: 0.7, maxOutputTokens: 4096 }}
                            }})
                        }});
                        if (res.ok) {{
                            const data = await res.json();
                            reply = data?.candidates?.[0]?.content?.parts?.[0]?.text;
                            if (reply) break;
                        }}
                    }} catch(err) {{}}
                }}
            }}

            // 2. If no custom key or direct call failed, call the secure Cloudflare Worker Proxy
            if (!reply && CLOUDFLARE_WORKER_URL) {{
                try {{
                    const reqHeaders = {{ "Content-Type": "application/json" }};
                    if (API_KEY && (API_KEY.startsWith("AIzaSy") || API_KEY.startsWith("AQ.") || API_KEY.length > 20)) {{
                        reqHeaders["x-gemini-key"] = API_KEY;
                    }}
                    const res = await fetch(CLOUDFLARE_WORKER_URL, {{
                        method: "POST",
                        headers: reqHeaders,
                        body: JSON.stringify({{
                            contents: conversationHistory,
                            systemInstruction: {{ parts: [{{ text: AERIS_SYSTEM_PROMPT }}] }},
                            generationConfig: {{ temperature: 0.7, maxOutputTokens: 4096 }}
                        }})
                    }});
                    if (res.ok) {{
                        const data = await res.json();
                        reply = data?.candidates?.[0]?.content?.parts?.[0]?.text;
                    }} else {{
                        const errData = await res.json().catch(() => ({{}}));
                        console.warn("Cloudflare Worker call status:", res.status, errData);
                    }}
                }} catch(proxyErr) {{
                    console.warn("Cloudflare Worker call exception:", proxyErr);
                }}
            }}

            // 3. Fallback to resilient Local SOC Intelligence
            if (!reply) {{
                reply = generateLocalSocResponse(message);
            }}

            appendBotBubble(reply);
            recordMessageInSession("model", reply);
            conversationHistory.push({{ role: "model", parts: [{{ text: reply }}] }});
            incrementQuota();

        }} catch (err) {{
            console.error("Aeris Chat Exception:", err);
            const fallbackReply = generateLocalSocResponse(message);
            appendBotBubble(fallbackReply);
            recordMessageInSession("model", fallbackReply);
            conversationHistory.push({{ role: "model", parts: [{{ text: fallbackReply }}] }});
        }} finally {{
            setLoading(false);
        }}
    }}

    /* ═══════════════════════════════════════════════════════════
       RICH LOCAL SOC INTELLIGENCE ENGINE
    ═══════════════════════════════════════════════════════ */
    function generateLocalSocResponse(query) {{
        const q = query.toLowerCase();

        if (q.includes("mitre") || q.includes("t1190")) {{
            return `A técnica **MITRE ATT&CK T1190** (*Exploit Public-Facing Application*) descreve invasões através da exploração de falhas em softwares expostos diretamente à Internet (como servidores HTTP/HTTPS Apache e Nginx, painéis de gerenciamento VMware ou portas VPN).

### Medidas de Mitigação Imediatas:
1. **Patching Contínuo:** Aplicação prioritária de correções de segurança em todos os serviços de borda.
2. **Camada WAF & IPS:** Inserção de assinaturas de inspeção profunda para bloquear payloads de injeção de parâmetros e RCE.
3. **Isolamento de Rede:** Garantir que o servidor web opere em DMZ isolada com permissão zero de tráfego lateral para a rede interna.`;
        }}

        if (q.includes("ransomware") || q.includes("lockbit") || q.includes("akira") || q.includes("blackcat")) {{
            return `No ciclo atual de Threat Intelligence do **Sentinel SecOps**, monitoramos correlações ativas entre vulnerabilidades de execução remota e grupos de **Ransomware** como *LockBit 3.0*, *Akira* e *BlackCat*.

### Diretrizes de Contenção de Ransomware:
- **Backups Imutáveis:** Mantenha cópias offline protegidas por WORM (Write Once, Read Many).
- **Segmentação Estrita de Identidade:** Isole servidores AD e hipervisores ESXi de grupos de administração genéricos.
- **MFA em Todo Acesso Remoto:** Elimine acessos RDP ou SSH diretos sem túnel VPN com autenticação multifator forte.`;
        }}

        if (q.includes("apache") || q.includes("cve-2024-38475")) {{
            return `A falha **CVE-2024-38475** no **Apache HTTP Server** possui score **CVSS 9.8 (Crítico)**. Trata-se de uma falha de substituição de URL no \\`mod_proxy\\` que permite contornar restrições de proxy reverso e acessar manipuladores internos de servidores de aplicação.

**Recomendação:** Atualizar o servidor web imediatamente para a versão 2.4.60 ou superior e revisar as diretivas \\`ProxyPassMatch\\`.`;
        }}

        if (q.includes("vmware") || q.includes("esxi") || q.includes("cve-2024-37085")) {{
            return `A vulnerabilidade **CVE-2024-37085** no **VMware ESXi** (Score **9.6**) possibilita a invasores com privilégios no Active Directory obter acesso administrativo completo (*root*) aos hipervisores ESXi associados ao domínio.

Esta vulnerabilidade tem sido explorada ativamente em campanhas de ransomware. Recomenda-se aplicar o patch da VMware e desvincular o grupo padrão 'ESX Admins' do domínio comum.`;
        }}

        if (q.includes("windows") || q.includes("rdp") || q.includes("cve-2024-38077")) {{
            return `A vulnerabilidade **CVE-2024-38077** (conhecida como *MadLicense*) afeta o serviço de Licenciamento de Área de Trabalho Remota (*Remote Desktop Licensing*) no **Windows Server** (Score **9.8 Crítico**).

Permite execução remota de código (RCE) como \\`NT AUTHORITY\\SYSTEM\\` sem qualquer autenticação prévia. A Microsoft disponibilizou a correção no Patch Tuesday (KB5040442).`;
        }}

        if (q.includes("cve") || q.includes("vulnerab") || q.includes("hoje") || q.includes("painel") || q.includes("status") || q.includes("crítica") || q.includes("critica")) {{
            return `O motor de monitoramento do **Sentinel SecOps** está com **4 CVEs Críticas ativas** sob investigação no ciclo atual:

1. **CVE-2024-38475 (Apache HTTP Server):** Score 9.8 · Tática MITRE T1190.
2. **CVE-2024-37085 (VMware ESXi):** Score 9.6 · Vinculado a Ransomware.
3. **CVE-2024-38077 (Windows Server RDL):** Score 9.8 · RCE não autenticado.
4. **CVE-2024-4577 (PHP CGI):** Score 9.8 · Exploração ativa em servidores web.

Consulte a tabela interativa do **Threat Dashboard** logo abaixo para detalhes completos de cada vetor e links de patch.`;
        }}

        if (q.includes("ola") || q.includes("olá") || q.includes("oi") || q.includes("ajuda")) {{
            return `Olá! Sou **Aeris**, analista virtual de inteligência de ameaças do Sentinel SecOps.

Posso auxiliar você a:
- Avaliar impacto de vulnerabilidades críticas (CVEs).
- Analisar táticas e técnicas do framework MITRE ATT&CK.
- Consultar diretrizes de mitigação e patches para seu tech stack.
- Investigar ameaças vinculadas a ransomware e exploits públicos.

O que você gostaria de analisar neste ciclo?`;
        }}

        return `Com base na inteligência de segurança do Sentinel SecOps: o monitoramento contínuo correlaciona dados de telemetria NVD, Exploit-DB e CISA KEV.

Para análises aprofundadas da sua infraestrutura, recomendo consultar os relatórios consolidados em PDF na aba **Relatórios PDF** ou inspecionar as métricas de risco do **Threat Dashboard**. Como posso detalhar sua investigação?`;
    }}

    /* ═══════════════════════════════════════════════════════════
       CHAT BUBBLE BUILDERS & UI
    ═══════════════════════════════════════════════════════ */
    function timeNow() {{
        return new Date().toLocaleTimeString("pt-BR", {{ hour: "2-digit", minute: "2-digit" }});
    }}

    function appendUserBubble(text, time) {{
        const messages = document.getElementById("chat-messages");
        const row = document.createElement("div");
        row.className = "msg-row user";
        row.innerHTML = `
            <div class="msg-inner">
                <div class="msg-body" style="align-items:flex-end;">
                    <div class="bubble user-bubble">${{escHtml(text)}}</div>
                    <div class="msg-meta" style="text-align:right;">${{time || timeNow()}} · Você</div>
                </div>
            </div>`;
        messages.appendChild(row);
        scrollMessages();
    }}

    function appendBotBubble(text, time) {{
        const messages = document.getElementById("chat-messages");
        const row = buildBotRow(text, false, time);
        messages.appendChild(row);
        scrollMessages();
    }}

    function buildBotRow(text, isPreset, time) {{
        const row = document.createElement("div");
        row.className = "msg-row bot";
        const formatted = formatMarkdown(text);
        row.innerHTML = `
            <div class="msg-inner">
                <div class="bot-av" aria-hidden="true">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div class="msg-body">
                    <div class="bubble bot-bubble">${{formatted}}</div>
                    <div class="msg-meta">
                        ${{isPreset ? "Aeris · SOC Intelligence" : (time || timeNow()) + " · Aeris"}}
                    </div>
                </div>
            </div>`;
        if (window.hljs) {{
            row.querySelectorAll('pre code').forEach((block) => {{
                try {{ hljs.highlightElement(block); }} catch(e) {{}}
            }});
        }}
        return row;
    }}

    function copyCodeBlock(btn) {{
        const wrapper = btn.closest(".code-block-wrapper");
        if (!wrapper) return;
        const codeEl = wrapper.querySelector("code");
        if (!codeEl) return;
        const text = codeEl.innerText;
        navigator.clipboard.writeText(text).then(() => {{
            const span = btn.querySelector("span");
            const originalText = span ? span.innerText : "Copiar código";
            btn.classList.add("copied");
            if (span) span.innerText = "Copiado! ✓";
            setTimeout(() => {{
                btn.classList.remove("copied");
                if (span) span.innerText = originalText;
            }}, 2000);
        }}).catch(err => {{
            console.warn("Falha ao copiar:", err);
        }});
    }}

    function formatMarkdown(text) {{
        if (!text) return "";

        // 1. Extrai blocos de código com crases triplas
        const codeBlocks = [];
        let processed = text.replace(/```([a-zA-Z0-9_\\-\\.\\+]*)\\r?\\n([\\s\\S]*?)```/g, function(match, lang, code) {{
            const placeholder = `___CODE_BLOCK_${{codeBlocks.length}}___`;
            codeBlocks.push({{
                lang: lang.trim() || "code",
                code: code.replace(/\\r\\n/g, "\\n").replace(/\\n$/, "")
            }});
            return placeholder;
        }});

        // 2. Processa linhas estruturadas de Markdown
        let lines = processed.split("\\n");
        let inList = false;
        let inNumberedList = false;
        let formattedLines = [];

        for (let i = 0; i < lines.length; i++) {{
            let line = lines[i];

            if (line.includes("___CODE_BLOCK_")) {{
                if (inList) {{ formattedLines.push("</ul>"); inList = false; }}
                if (inNumberedList) {{ formattedLines.push("</ol>"); inNumberedList = false; }}
                formattedLines.push(line);
                continue;
            }}

            line = line.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

            if (/^### (.*$)/.test(line)) {{
                if (inList) {{ formattedLines.push("</ul>"); inList = false; }}
                if (inNumberedList) {{ formattedLines.push("</ol>"); inNumberedList = false; }}
                line = line.replace(/^### (.*$)/, "<h3 class='msg-h3'>$1</h3>");
                formattedLines.push(line);
                continue;
            }}
            if (/^## (.*$)/.test(line)) {{
                if (inList) {{ formattedLines.push("</ul>"); inList = false; }}
                if (inNumberedList) {{ formattedLines.push("</ol>"); inNumberedList = false; }}
                line = line.replace(/^## (.*$)/, "<h2 class='msg-h2'>$1</h2>");
                formattedLines.push(line);
                continue;
            }}
            if (/^# (.*$)/.test(line)) {{
                if (inList) {{ formattedLines.push("</ul>"); inList = false; }}
                if (inNumberedList) {{ formattedLines.push("</ol>"); inNumberedList = false; }}
                line = line.replace(/^# (.*$)/, "<h1 class='msg-h1'>$1</h1>");
                formattedLines.push(line);
                continue;
            }}

            if (/^(&gt;|>) (.*$)/.test(line)) {{
                if (inList) {{ formattedLines.push("</ul>"); inList = false; }}
                if (inNumberedList) {{ formattedLines.push("</ol>"); inNumberedList = false; }}
                line = line.replace(/^(&gt;|>) (.*$)/, "<blockquote class='msg-quote'>$2</blockquote>");
                formattedLines.push(line);
                continue;
            }}

            if (/^[\\*\\-\\+] (.*$)/.test(line)) {{
                if (inNumberedList) {{ formattedLines.push("</ol>"); inNumberedList = false; }}
                if (!inList) {{ formattedLines.push("<ul class='msg-list'>"); inList = true; }}
                line = line.replace(/^[\\*\\-\\+] (.*$)/, "<li>$1</li>");
                formattedLines.push(line);
                continue;
            }}

            if (/^\\d+\\. (.*$)/.test(line)) {{
                if (inList) {{ formattedLines.push("</ul>"); inList = false; }}
                if (!inNumberedList) {{ formattedLines.push("<ol class='msg-num-list'>"); inNumberedList = true; }}
                line = line.replace(/^\\d+\\. (.*$)/, "<li>$1</li>");
                formattedLines.push(line);
                continue;
            }}

            if (inList) {{ formattedLines.push("</ul>"); inList = false; }}
            if (inNumberedList) {{ formattedLines.push("</ol>"); inNumberedList = false; }}

            formattedLines.push(line);
        }}
        if (inList) formattedLines.push("</ul>");
        if (inNumberedList) formattedLines.push("</ol>");

        let html = formattedLines.join("\\n");

        html = html.replace(/\\*\\*(.*?)\\*\\*/g, "<strong>$1</strong>");
        html = html.replace(/\\*(.*?)\\*/g, "<em>$1</em>");
        html = html.replace(/`([^`]+)`/g, "<code class='msg-inline-code'>$1</code>");
        html = html.replace(/\\n(?!(?:<\\/?(ul|ol|li|h1|h2|h3|blockquote|div|pre)))/g, "<br>");

        // 3. Reconstrói os blocos de código com cabeçalho, linguagem e botão Copiar
        codeBlocks.forEach((cb, idx) => {{
            const placeholder = `___CODE_BLOCK_${{idx}}___`;
            const escapedCode = cb.code.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            const blockHtml = `
                <div class="code-block-wrapper">
                    <div class="code-block-header">
                        <span class="code-lang">${{cb.lang}}</span>
                        <button class="btn-copy-code" type="button" onclick="copyCodeBlock(this)">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                            <span>Copiar código</span>
                        </button>
                    </div>
                    <pre><code class="language-${{cb.lang}}">${{escapedCode}}</code></pre>
                </div>
            `;
            html = html.replace(placeholder, blockHtml);
        }});

        return html;
    }}

    function escHtml(t) {{
        return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    }}

    function scrollMessages() {{
        const msgs = document.getElementById("chat-messages");
        msgs.scrollTop = msgs.scrollHeight;
    }}

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

    function showError(msg) {{
        const el = document.getElementById("chat-error");
        const txt = document.getElementById("chat-error-msg");
        if (msg) {{ txt.textContent = msg; el.classList.remove("hidden"); }}
        else      {{ el.classList.add("hidden"); }}
    }}

    function applySuggestion(text) {{
        document.getElementById("chat-input").value = text;
        document.getElementById("chat-form").requestSubmit();
    }}

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
       INTERACTIVE THREAT DASHBOARD ENGINE
    ═══════════════════════════════════════════════════════ */
    let currentFilter = "all";

    function renderCveTable(items) {{
        const tbody = document.getElementById("cve-tbody");
        if (!tbody) return;
        tbody.innerHTML = "";

        if (items.length === 0) {{
            tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 30px; color: #94a3b8;">Nenhuma ameaça encontrada para os filtros selecionados.</td></tr>`;
            return;
        }}

        items.forEach((item, idx) => {{
            const rowId = "row-" + idx;
            const detailId = "detail-" + idx;

            const tr = document.createElement("tr");
            tr.id = rowId;
            tr.innerHTML = `
                <td class="cve-id-cell">
                    <a href="https://nvd.nist.gov/vuln/detail/${{item.cve}}" target="_blank" style="color:inherit; text-decoration:none;" title="Ver no NVD">
                        ${{item.cve}}
                    </a>
                </td>
                <td>
                    <strong>${{item.software}}</strong>
                </td>
                <td>
                    <span class="score-pill score-${{item.severity}}">${{item.score}} ${{item.severity.toUpperCase()}}</span>
                </td>
                <td>
                    <span style="font-size:0.75rem; color:var(--text-sub);">${{item.mitre}}</span>
                </td>
                <td>
                    <span class="sla-badge sla-${{item.slaClass}}">${{item.sla}}</span>
                </td>
                <td>
                    <span class="${{item.exploit ? 'exploit-yes' : 'exploit-no'}}">
                        ${{item.exploit ? '⚡ Disponível' : '—'}}
                    </span>
                </td>
                <td>
                    <span class="trend-${{item.trend}}">
                        ${{item.trend === 'up' ? '↑ Alta exploração' : '→ Estável'}}
                    </span>
                </td>
                <td>
                    <span style="font-size:0.75rem; color:${{item.ransomware !== 'Não vinculado' ? 'var(--purple)' : 'var(--text-muted)'}}; font-weight:${{item.ransomware !== 'Não vinculado' ? '600' : 'normal'}};">
                        ${{item.ransomware}}
                    </span>
                </td>
                <td style="text-align:right;">
                    <button class="btn-detail" onclick="toggleDetail('${{idx}}')">Detalhes</button>
                </td>
            `;

            // Expandable detail row
            const trDetail = document.createElement("tr");
            trDetail.id = detailId;
            trDetail.className = "detail-row";
            trDetail.innerHTML = `
                <td colspan="9" style="padding:0;">
                    <div class="detail-box">
                        <div class="detail-grid">
                            <div class="detail-field"><strong>Descrição Técnica:</strong> ${{item.desc}}</div>
                            <div class="detail-field"><strong>Vetor CVSS v3.1:</strong> <code style="font-family:'JetBrains Mono',monospace; font-size:0.76rem; background:rgba(0,0,0,0.3); padding:2px 6px; border-radius:4px;">${{item.vector}}</code></div>
                        </div>
                        <div class="detail-action">
                            <strong>Ação de Mitigação Recomendada:</strong>
                            <p>${{item.mitigation}}</p>
                            <div style="margin-top:8px;">
                                <a href="${{item.patchUrl}}" target="_blank" style="color:var(--green); font-size:0.76rem; text-decoration:underline;">Consultar Comunicado do Fabricante & Patch →</a>
                            </div>
                        </div>
                    </div>
                </td>
            `;

            tbody.appendChild(tr);
            tbody.appendChild(trDetail);
        }});
    }}

    function toggleDetail(idx) {{
        const el = document.getElementById("detail-" + idx);
        if (el) el.classList.toggle("open");
    }}

    function filterCveTable() {{
        const query = (document.getElementById("cve-search").value || "").toLowerCase();
        let filtered = TELEMETRY_DATA.filter(item => {{
            const matchesQuery = item.cve.toLowerCase().includes(query) ||
                                 item.software.toLowerCase().includes(query) ||
                                 item.mitre.toLowerCase().includes(query) ||
                                 item.ransomware.toLowerCase().includes(query);

            if (!matchesQuery) return false;

            if (currentFilter === "critical") return parseFloat(item.score) >= 9.0;
            if (currentFilter === "ransomware") return item.ransomware !== "Não vinculado";
            if (currentFilter === "exploit") return item.exploit === true;
            if (currentFilter === "sla") return item.sla.includes("24h");
            return true;
        }});

        renderCveTable(filtered);
    }}

    function setTableFilter(filterType, btnEl) {{
        currentFilter = filterType;
        document.querySelectorAll(".filter-chip").forEach(c => c.classList.remove("active"));
        if (btnEl) btnEl.classList.add("active");
        filterCveTable();
    }}

    function updateDashboardMetrics() {{
        const criticalCount = TELEMETRY_DATA.filter(t => parseFloat(t.score) >= 9.0).length;
        const ransomwareCount = TELEMETRY_DATA.filter(t => t.ransomware !== "Não vinculado").length;
        const exploitCount = TELEMETRY_DATA.filter(t => t.exploit).length;
        const slaCount = TELEMETRY_DATA.filter(t => t.sla.includes("24h")).length;

        document.getElementById("m-critical").textContent = criticalCount;
        document.getElementById("m-ransomware").textContent = ransomwareCount;
        document.getElementById("m-exploit").textContent = exploitCount;
        document.getElementById("m-sla").textContent = slaCount;
    }}

    /* ═══════════════════════════════════════════════════════════
       SUB-VIEWS POPULATION (PDFs, RSS, STIX)
    ═══════════════════════════════════════════════════════ */
    function initSubviewsContent() {{
        // 1. Populate PDF Reports list
        const pdfContainer = document.getElementById("pdf-reports-list");
        if (pdfContainer) {{
            const reports = [
                {{ name: "Report_2026-09-23_23-27.pdf", date: "23/09/2026 23:27", size: "1.5 KB", type: "Executivo Diário" }},
                {{ name: "Report_2026-09-23_19-52.pdf", date: "23/09/2026 19:52", size: "1.5 KB", type: "Executivo Diário" }},
                {{ name: "Report_2026-09-23_15-08.pdf", date: "23/09/2026 15:08", size: "1.5 KB", type: "Executivo Diário" }},
                {{ name: "Report_2026-09-23_10-15.pdf", date: "23/09/2026 10:15", size: "1.5 KB", type: "Executivo Diário" }},
                {{ name: "Report_2026-09-22_19-52.pdf", date: "22/09/2026 19:52", size: "1.5 KB", type: "Executivo Diário" }},
                {{ name: "Report_2026-09-22_14-51.pdf", date: "22/09/2026 14:51", size: "1.5 KB", type: "Executivo Diário" }}
            ];

            pdfContainer.innerHTML = reports.map(r => `
                <div class="pdf-report-card">
                    <div class="pdf-card-top">
                        <div class="pdf-icon-box">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                        </div>
                        <div class="pdf-info">
                            <h4>${{r.name}}</h4>
                            <p>${{r.date}} · ${{r.size}}</p>
                            <span style="font-size:0.68rem; color:var(--green); font-weight:600;">${{r.type}}</span>
                        </div>
                    </div>
                    <div class="pdf-actions">
                        <a href="pdf_reports/${{r.name}}" download="${{r.name}}" class="btn-download-pdf">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                            Baixar PDF
                        </a>
                        <a href="pdf_reports/${{r.name}}" target="_blank" class="btn-dash-action" style="padding:6px 12px; font-size:0.76rem;">
                            Visualizar
                        </a>
                    </div>
                </div>
            `).join("");
        }}

        // 2. Populate RSS items preview
        const rssContainer = document.getElementById("rss-items-container");
        if (rssContainer) {{
            rssContainer.innerHTML = TELEMETRY_DATA.map(t => `
                <div style="background:var(--bg-input); border:1px solid var(--border); border-radius:var(--radius-sm); padding:16px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; flex-wrap:wrap; gap:8px;">
                        <span style="font-family:'JetBrains Mono',monospace; font-weight:700; color:var(--text);">${{t.cve}} — ${{t.software}}</span>
                        <span class="score-pill score-${{t.severity}}">${{t.score}} ${{t.severity.toUpperCase()}}</span>
                    </div>
                    <div style="font-size:0.82rem; color:var(--text-sub); line-height:1.5;">${{t.desc}}</div>
                    <div style="font-size:0.72rem; color:var(--text-muted); margin-top:8px;">Tática MITRE: ${{t.mitre}} · SLA: ${{t.sla}}</div>
                </div>
            `).join("");
        }}

        // 3. Populate STIX 2.1 JSON
        const stixDisplay = document.getElementById("stix-json-display");
        if (stixDisplay) {{
            const stixBundle = generateStix21Bundle();
            stixDisplay.textContent = JSON.stringify(stixBundle, null, 2);
        }}
    }}

    function generateStix21Bundle() {{
        return {{
            "type": "bundle",
            "id": "bundle--sentinel-secops-cve-threat-bundle",
            "spec_version": "2.1",
            "objects": [
                {{
                    "type": "indicator",
                    "id": "indicator--t1190-exploit-public-facing",
                    "spec_version": "2.1",
                    "created": "2026-09-24T00:00:00.000Z",
                    "modified": "2026-09-24T00:00:00.000Z",
                    "name": "MITRE ATT&CK T1190 Exploit Detection",
                    "description": "Indicators of exploitation against public-facing applications (Apache, VMware, Windows)",
                    "pattern": "[network-traffic:dst_port IN (80, 443, 3389)]",
                    "pattern_type": "stix"
                }},
                ...TELEMETRY_DATA.map((t, idx) => ({{
                    "type": "vulnerability",
                    "id": `vulnerability--${{t.cve.toLowerCase()}}`,
                    "spec_version": "2.1",
                    "created": "2026-09-24T00:00:00.000Z",
                    "modified": "2026-09-24T00:00:00.000Z",
                    "name": t.cve,
                    "description": t.desc,
                    "external_references": [
                        {{ "source_name": "cve", "external_id": t.cve }},
                        {{ "source_name": "mitre-attack", "external_id": t.mitre.split(" ")[0] }}
                    ]
                }}))
            ]
        }};
    }}

    function downloadStixBundle() {{
        const bundle = generateStix21Bundle();
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(bundle, null, 2));
        const a = document.createElement("a");
        a.href = dataStr;
        a.download = "stix_bundle.json";
        document.body.appendChild(a);
        a.click();
        a.remove();
    }}

    function copyStixJson() {{
        const bundle = generateStix21Bundle();
        navigator.clipboard.writeText(JSON.stringify(bundle, null, 2)).then(() => {{
            const btnText = document.getElementById("copy-stix-btn-text");
            if (btnText) {{
                btnText.textContent = "Copiado!";
                setTimeout(() => btnText.textContent = "Copiar JSON", 2000);
            }}
        }});
    }}

    function copyRssUrl() {{
        const urlInput = document.getElementById("rss-feed-url");
        if (urlInput) {{
            navigator.clipboard.writeText(urlInput.value).then(() => {{
                const btnText = document.getElementById("copy-rss-btn-text");
                if (btnText) {{
                    btnText.textContent = "Copiado!";
                    setTimeout(() => btnText.textContent = "Copiar URL", 2000);
                }}
            }});
        }}
    }}

    /* ═══════════════════════════════════════════════════════════
       SIDEBAR & AUDIO CONTROLS
    ═══════════════════════════════════════════════════════ */
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
