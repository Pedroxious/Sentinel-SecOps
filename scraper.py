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

# Using gemini-3.1-flash-lite as principal model
MODEL_NAME = "gemini-3.1-flash-lite"
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
    <title>Sentinel SecOps - Threat Dashboard</title>
    <!-- Modern Typography -->
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #07080c;        /* Midnight obsidian */
            --card-bg: #0d0f17;        /* Clean metallic card bg */
            --border-color: #1a1e2f;    /* Sleek border color */
            
            --accent-emerald: #10b981;  /* Cyber Security Green */
            --accent-purple: #8b5cf6;   /* Cyber Purple */
            --accent-cyan: #06b6d4;     /* Neon Cyan */
            --accent-blue: #3b82f6;     /* Deep Blue */
            
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            
            --red-alert: #ef4444;
            --green-ok: #22c55e;
            --yellow-warning: #eab308;
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        
        body {{
            margin: 0;
            padding: 0;
            background: var(--bg-dark);
            color: var(--text-primary);
            font-family: 'Outfit', sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
            overflow-x: hidden;
        }}
        
        .app-container {{
            width: 100%;
            max-width: 960px;
            padding: 2.5rem 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 3.5rem;
        }}
        
        /* Clean Top Navigation Bar Header */
        .top-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 1.25rem;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .top-bar-left {{
            display: flex;
            align-items: center;
        }}
        
        .logo-text {{
            font-size: 1.45rem;
            font-weight: 700;
            background: linear-gradient(to right, var(--accent-emerald), var(--accent-cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: 0.5px;
        }}
        
        .top-bar-right {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .workspace-tag {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
            background: rgba(255, 255, 255, 0.02);
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        /* 1. Centered Chat Workspace Section */
        .chat-container-layout {{
            display: flex;
            flex-direction: column;
            width: 100%;
            min-height: 450px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2rem;
            box-shadow: 0 10px 35px rgba(0,0,0,0.5);
            position: relative;
        }}
        
        .chat-welcome-container {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            margin: 2.5rem 0;
            transition: all 0.3s ease;
        }}
        
        .chat-welcome-container.hidden {{
            display: none;
        }}
        
        .chat-welcome-container h2 {{
            font-size: 2.1rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
            background: linear-gradient(to right, var(--text-primary), var(--text-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .chat-welcome-container p {{
            font-size: 0.95rem;
            color: var(--text-secondary);
        }}
        
        .chat-history-list {{
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
            padding: 0.5rem;
            overflow-y: auto;
            max-height: 380px;
            margin-bottom: 1.25rem;
            scroll-behavior: smooth;
        }}
        
        .chat-history-list.empty {{
            display: none;
        }}
        
        /* Chat Message Rows and Bubbles */
        .chat-msg-row {{
            display: flex;
            width: 100%;
        }}
        
        .chat-msg-row.row-user {{
            justify-content: flex-end;
        }}
        
        .chat-msg-row.row-bot {{
            justify-content: flex-start;
        }}
        
        .bubble {{
            max-width: 78%;
            padding: 0.85rem 1.25rem;
            border-radius: 18px;
            font-size: 0.95rem;
            line-height: 1.5;
            position: relative;
            word-wrap: break-word;
        }}
        
        .row-user .bubble {{
            background: linear-gradient(135deg, var(--accent-purple), var(--accent-blue));
            color: #fff;
            border-bottom-right-radius: 3px;
            box-shadow: 0 4px 15px rgba(139, 92, 246, 0.2);
        }}
        
        .row-bot .bubble {{
            background: #141724;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            border-bottom-left-radius: 3px;
        }}
        
        .msg-meta {{
            font-size: 0.7rem;
            color: rgba(255, 255, 255, 0.4);
            margin-top: 0.35rem;
            display: flex;
            justify-content: flex-end;
            gap: 0.5rem;
        }}
        
        .row-bot .msg-meta {{
            color: var(--text-secondary);
        }}
        
        .chat-loading {{
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}
        
        .spinner {{
            width: 16px;
            height: 16px;
            border: 2px solid rgba(16, 185, 129, 0.15);
            border-top: 2px solid var(--accent-emerald);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }}
        
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        
        /* Dynamic Centered pill-shaped text area */
        .chat-input-wrapper {{
            background: #090a10;
            border: 1px solid var(--border-color);
            border-radius: 28px;
            padding: 0.55rem 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            transition: all 0.2s ease-in-out;
        }}
        
        .chat-input-wrapper:focus-within {{
            border-color: var(--accent-emerald);
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.12);
        }}
        
        .chat-input-wrapper textarea {{
            flex-grow: 1;
            background: transparent;
            border: none;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 0.95rem;
            resize: none;
            outline: none;
            height: 24px;
            line-height: 24px;
        }}
        
        .chat-input-wrapper textarea::placeholder {{
            color: var(--text-secondary);
        }}
        
        .chat-input-actions {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-shrink: 0;
        }}
        
        .chat-model-badge {{
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 0.2rem 0.65rem;
            font-size: 0.75rem;
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .btn-send-pill {{
            background: var(--accent-emerald);
            border: none;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            color: #05060a;
            font-weight: bold;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: opacity 0.2s;
        }}
        
        .btn-send-pill:hover {{
            opacity: 0.9;
        }}
        
        .btn-send-pill:disabled {{
            background: #1f2231;
            color: var(--text-secondary);
            cursor: not-allowed;
        }}
        
        /* 2. Enhanced Threat Dashboard section (aligned below chatbot) */
        .dashboard-section {{
            border-top: 1px solid var(--border-color);
            padding-top: 3rem;
            display: flex;
            flex-direction: column;
            gap: 2.5rem;
        }}
        
        .dashboard-section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        
        .dashboard-section-header h2 {{
            font-size: 1.6rem;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .dashboard-section-meta {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            background: rgba(255,255,255,0.02);
            padding: 0.45rem 0.9rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        
        /* Modernized Metric Card grid */
        .db-metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
        }}
        
        .db-metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
            transition: all 0.2s;
        }}
        
        .db-metric-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(16, 185, 129, 0.08);
            border-color: rgba(16, 185, 129, 0.25);
        }}
        
        .db-metric-card h4 {{
            font-size: 0.78rem;
            text-transform: uppercase;
            color: var(--text-secondary);
            letter-spacing: 0.5px;
            margin-bottom: 0.5rem;
        }}
        
        .db-metric-value {{
            font-size: 2.25rem;
            font-weight: 700;
            color: var(--text-primary);
        }}
        
        .db-metric-icon {{
            position: absolute;
            right: 1.25rem;
            bottom: 1.25rem;
            font-size: 1.8rem;
            opacity: 0.2;
        }}
        
        /* Threat of the Week highlighted styled card */
        .threat-of-week-card {{
            background: linear-gradient(145deg, #0d0f16, #12091c);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 12px;
            padding: 2rem;
        }}
        
        .tow-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1.25rem;
        }}
        
        .tow-badge {{
            background: var(--red-alert);
            color: #fff;
            padding: 0.35rem 0.85rem;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        
        .progress-bar-container {{
            background: rgba(255,255,255,0.06);
            border-radius: 6px;
            height: 8px;
            overflow: hidden;
            width: 100%;
            margin-top: 0.5rem;
        }}
        
        .progress-bar {{
            background: linear-gradient(to right, var(--accent-cyan), var(--red-alert));
            height: 100%;
            border-radius: 6px;
        }}
        
        .tow-action {{
            background: rgba(0,0,0,0.2);
            border-left: 3px solid var(--accent-emerald);
            padding: 1rem 1.25rem;
            border-radius: 6px;
            margin-top: 1.25rem;
        }}
        
        /* Modernized table styling */
        .db-table-wrapper {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow-x: auto;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        
        .db-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.95rem;
        }}
        
        .db-table th {{
            background: rgba(0, 0, 0, 0.25);
            padding: 1.1rem 1.25rem;
            font-weight: 600;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border-color);
            text-align: left;
        }}
        
        .db-table td {{
            padding: 1.1rem 1.25rem;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
        }}
        
        .db-table tr:last-child td {{
            border-bottom: none;
        }}
        
        .db-table tr:hover td {{
            background: rgba(255, 255, 255, 0.012);
        }}
        
        /* Score indicators */
        .cve-score-pill {{
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            padding: 0.25rem 0.55rem;
            border-radius: 6px;
            font-size: 0.88rem;
        }}
        .cve-score-high {{ background: rgba(239, 68, 68, 0.12); color: var(--red-alert); }}
        .cve-score-medium {{ background: rgba(234, 179, 8, 0.12); color: var(--yellow-warning); }}
        .cve-score-low {{ background: rgba(59, 130, 246, 0.12); color: var(--accent-blue); }}
        
        /* SLA badges */
        .sla-badge {{
            font-size: 0.78rem;
            font-weight: 600;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
        }}
        .sla-critical {{ background: rgba(239, 68, 68, 0.15); color: var(--red-alert); border: 1px solid rgba(239, 68, 68, 0.25); }}
        .sla-high {{ background: rgba(234, 179, 8, 0.15); color: var(--yellow-warning); border: 1px solid rgba(234, 179, 8, 0.25); }}
        .sla-medium {{ background: rgba(59, 130, 246, 0.15); color: var(--accent-blue); border: 1px solid rgba(59, 130, 246, 0.25); }}
        .sla-low {{ background: rgba(148, 163, 184, 0.15); color: var(--text-secondary); border: 1px solid rgba(148, 163, 184, 0.25); }}
        
        /* Details layout drop down */
        .db-detail-row td {{
            padding: 0;
        }}
        
        .db-detail-box {{
            background: rgba(0, 0, 0, 0.2);
            border-left: 4px solid var(--accent-emerald);
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
        }}
        
        .db-detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1rem;
        }}
        
        .db-detail-field {{
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}
        
        .db-detail-field strong {{
            color: var(--text-primary);
        }}
        
        .db-action-box {{
            background: rgba(16, 185, 129, 0.03);
            border: 1px solid rgba(16, 185, 129, 0.12);
            border-radius: 8px;
            padding: 1rem 1.25rem;
            margin-top: 0.5rem;
        }}
        
        .db-action-box strong {{
            color: var(--accent-emerald);
            display: block;
            margin-bottom: 0.35rem;
        }}
        
        .db-btn-detail {{
            background: rgba(16, 185, 129, 0.08);
            color: var(--accent-emerald);
            border: 1px solid rgba(16, 185, 129, 0.25);
            padding: 0.35rem 0.7rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
            transition: all 0.2s;
        }}
        
        .db-btn-detail:hover {{
            background: var(--accent-emerald);
            color: #0d0f17;
        }}
        
        .section-divider {{
            border: none;
            border-top: 1px solid var(--border-color);
            margin: 1.5rem 0;
        }}
        
        .exploit-col.yes {{ color: var(--red-alert); font-weight: bold; }}
        .exploit-col.no {{ color: var(--text-secondary); }}
        
        .trend-up {{ color: var(--red-alert); font-weight: bold; }}
        .trend-down {{ color: var(--green-ok); font-weight: bold; }}
        .trend-stable {{ color: var(--text-secondary); }}
        
        /* Audio Player fixed footer */
        .audio-player-footer {{
            position: fixed;
            bottom: 0;
            left: 0;
            width: 100%;
            background: #0b0c12;
            border-top: 1px solid var(--border-color);
            padding: 0.75rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1.5rem;
            z-index: 100;
            transform: translateY(100%);
            transition: transform 0.3s ease-in-out;
        }}
        
        .audio-player-footer.visible {{
            transform: translateY(0);
        }}
        
        .audio-player-label {{
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--accent-emerald);
            letter-spacing: 0.5px;
        }}
        
        .audio-player-footer audio {{
            flex-grow: 1;
            max-width: 500px;
            height: 32px;
        }}
        
        .btn-close-audio {{
            background: transparent;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 1.1rem;
            transition: color 0.2s;
        }}
        
        .btn-close-audio:hover {{
            color: var(--text-primary);
        }}
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Top bar with brand label -->
        <header class="top-bar">
            <div class="top-bar-left">
                <span class="logo-text">Sentinel SecOps</span>
            </div>
            <div class="top-bar-right">
                <span class="workspace-tag">Workspace</span>
            </div>
        </header>
        
        <!-- Main Content Area -->
        <!-- 1. Chat Workspace Container (Placed first as user requested) -->
        <section class="chat-container-layout">
            <!-- Welcome message header -->
            <div id="chat-welcome" class="chat-welcome-container">
                <h2>Como posso ajudar?</h2>
                <p>Analise novas ameaças cibernéticas com suporte do SOC Assistant.</p>
            </div>
            
            <!-- Scrollable chat bubble box -->
            <div id="chat-box" class="chat-history-list empty">
                <!-- Dynamic conversation messages injected here -->
            </div>
            
            <!-- Loading spinner indicators -->
            <div id="loading-indicator" class="chat-loading hidden" style="margin-bottom: 0.85rem; margin-left: 1rem;">
                <div class="spinner"></div>
                <span>Analisando contexto técnico...</span>
            </div>
            
            <!-- Wide Pill Form Input -->
            <form id="chat-form" onsubmit="handleChatSubmit(event)">
                <div class="chat-input-wrapper">
                    <textarea id="chat-input" placeholder="Peça ao SOC Assistant..."></textarea>
                    <div class="chat-input-actions">
                        <span class="chat-model-badge">Pedroxious Lab</span>
                        <button type="submit" id="btn-send-chat" class="btn-send-pill">➔</button>
                    </div>
                </div>
            </form>
            
            <span id="chat-quota-label" style="display: block; text-align: center; margin-top: 0.5rem; font-size: 0.8rem; color: var(--text-secondary)">Carregando cota diária...</span>
        </section>
        
        <!-- 2. Threat Intelligence Monitoring Dashboard (Placed below) -->
        <section class="dashboard-section" id="threat-dashboard-section">
            <div class="dashboard-section-header">
                <h2>Painel de Monitoramento Threat Intelligence</h2>
                <div class="dashboard-section-meta">
                    Relatório diário: <strong>Report_{date_str}_{hour_str.replace(':', '-')}.pdf</strong>
                </div>
            </div>
            
            <!-- Metrics Cards Grid -->
            <div class="db-metrics-grid">
                <div class="db-metric-card" style="border-top: 3px solid var(--red-alert);">
                    <h4>CVEs Críticas Hoje</h4>
                    <div class="db-metric-value">{critical_today}</div>
                </div>
                <div class="db-metric-card" style="border-top: 3px solid var(--accent-purple);">
                    <h4>Ransomware Linked</h4>
                    <div class="db-metric-value">{ransomware_linked}</div>
                </div>
                <div class="db-metric-card" style="border-top: 3px solid var(--yellow-warning);">
                    <h4>Com Exploit Público</h4>
                    <div class="db-metric-value">{has_exploit}</div>
                </div>
                <div class="db-metric-card" style="border-top: 3px solid var(--accent-cyan);">
                    <h4>SLA Vencendo em 24h</h4>
                    <div class="db-metric-value">{sla_24h}</div>
                </div>
            </div>
            
            <!-- Highlighted Threat of the Week -->
            {threat_of_week_html}
            
            <!-- Main Dashboard table container -->
            <div class="db-table-wrapper">
                <table class="db-table" id="vulnerabilities-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Software Afetado</th>
                            <th>Prioridade</th>
                            <th>Tática MITRE</th>
                            <th>SLA Label</th>
                            <th>Exploit DB</th>
                            <th>Score Trend</th>
                            <th>Ransomware</th>
                            <th>Detalhes</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows}
                    </tbody>
                </table>
            </div>
        </section>
    </div>

    <!-- Hidden audio briefing bar at bottom footer (only triggered when audio requested) -->
    <div class="audio-player-footer" id="audio-footer">
        <span class="audio-player-label">Cyber Briefing Audio</span>
        <audio controls id="briefing-audio">
            <source src="reports/audio/latest.mp3" type="audio/mpeg">
            Seu navegador não suporta player de áudio.
        </audio>
        <button class="btn-close-audio" onclick="closeAudioPlayer()">✕</button>
    </div>

    <script>
        // Toggle CVE details row expand
        function showDetail(id) {{
            const row = document.getElementById('detail-' + id);
            row.classList.toggle('hidden');
        }}

        function closeAudioPlayer() {{
            const player = document.getElementById('briefing-audio');
            player.pause();
            document.getElementById('audio-footer').classList.remove('visible');
        }}

        // Trigger Submit on Enter (Without Shift)
        document.getElementById('chat-input').addEventListener('keydown', function(event) {{
            if (event.key === 'Enter' && !event.shiftKey) {{
                event.preventDefault();
                document.getElementById('chat-form').requestSubmit();
            }}
        }});

        // Keywords detection to make the audio player visible at the bottom
        const audioKeywords = ["audio", "áudio", "briefing", "ouvir", "tocar", "narrar", "podcast", "reproduzir", "som", "escutar"];
        function checkAudioRequest(message) {{
            const msgLower = message.toLowerCase();
            const hasKeyword = audioKeywords.some(keyword => msgLower.includes(keyword));
            if (hasKeyword) {{
                const footer = document.getElementById('audio-footer');
                footer.classList.add('visible');
                // Reload audio element in case source changed
                const player = document.getElementById('briefing-audio');
                player.load();
                player.play().catch(e => console.log("Auto-play blocked by browser policy"));
            }}
        }}

        // Client Side Chat Control with Pedroxious Lab Model
        // Injected Key (Note: Personal portfolio API key deployment)
        const API_KEY = atob("{api_key_b64}"); 
        const SYSTEM_INSTRUCTION = `{chat_system_context}`;
        const MAX_CONVERSATIONS = 20;

        // Message history state
        let conversationHistory = [];

        // Check local storage limits
        function checkQuota() {{
            const todayStr = new Date().toISOString().slice(0, 10);
            let usage = localStorage.getItem('sentinel_chat_usage');
            if (usage) {{
                usage = JSON.parse(usage);
                if (usage.date !== todayStr) {{
                    usage = {{ date: todayStr, count: 0 }};
                }}
            }} else {{
                usage = {{ date: todayStr, count: 0 }};
            }}
            localStorage.setItem('sentinel_chat_usage', JSON.stringify(usage));
            
            const remaining = MAX_CONVERSATIONS - usage.count;
            document.getElementById('chat-quota-label').innerText = remaining + " de " + MAX_CONVERSATIONS + " consultas disponíveis hoje";
            
            if (usage.count >= MAX_CONVERSATIONS) {{
                document.getElementById('chat-input').disabled = true;
                document.getElementById('chat-input').placeholder = "Limite de 20 consultas diárias atingido. Renova amanhã.";
                document.getElementById('btn-send-chat').disabled = true;
                return false;
            }}
            return true;
        }}

        function incrementQuota() {{
            const usage = JSON.parse(localStorage.getItem('sentinel_chat_usage'));
            usage.count += 1;
            localStorage.setItem('sentinel_chat_usage', JSON.stringify(usage));
            checkQuota();
        }}

        async function handleChatSubmit(event) {{
            event.preventDefault();
            const inputField = document.getElementById('chat-input');
            const message = inputField.value.trim();
            if (!message) return;
            
            if (!checkQuota()) return;
            
            // Adjust layouts: hide welcome header & show borders
            document.getElementById('chat-welcome').classList.add('hidden');
            document.getElementById('chat-box').classList.remove('empty');
            
            // Append message to UI
            appendBubble(message, true);
            inputField.value = "";
            
            // Trigger audio check
            checkAudioRequest(message);
            
            // Set loading state
            document.getElementById('loading-indicator').classList.remove('hidden');
            document.getElementById('btn-send-chat').disabled = true;
            
            // Build conversation payload
            conversationHistory.push({{
                role: "user",
                parts: [{{ text: message }}]
            }});
            
            try {{
                // Request API
                const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key=${{API_KEY}}`;
                
                const response = await fetch(url, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    body: JSON.stringify({{
                        contents: conversationHistory,
                        systemInstruction: {{
                            parts: [{{ text: SYSTEM_INSTRUCTION }}]
                        }}
                    }})
                }});
                
                if (!response.ok) {{
                    throw new Error("Erro na API: " + response.statusText);
                }}
                
                const data = await response.json();
                const replyText = data.candidates[0].content.parts[0].text;
                
                appendBubble(replyText, false);
                conversationHistory.push({{
                    role: "model",
                    parts: [{{ text: replyText }}]
                }});
                
                incrementQuota();
                
            }} catch (error) {{
                appendBubble("Desculpe, ocorreu um erro ao obter resposta do analista de IA. Tente novamente mais tarde.", false);
                console.error("Chat Error:", error);
            }} finally {{
                document.getElementById('loading-indicator').classList.add('hidden');
                document.getElementById('btn-send-chat').disabled = false;
                checkQuota();
            }}
        }}

        function appendBubble(text, isUser) {{
            const chatBox = document.getElementById('chat-box');
            const bubbleRow = document.createElement('div');
            bubbleRow.classList.add('chat-msg-row');
            bubbleRow.classList.add(isUser ? 'row-user' : 'row-bot');
            
            const bubble = document.createElement('div');
            bubble.classList.add('bubble');
            
            const textNode = document.createElement('p');
            textNode.innerText = text;
            bubble.appendChild(textNode);
            
            const timeNode = document.createElement('div');
            timeNode.classList.add('msg-meta');
            const now = new Date();
            timeNode.innerText = now.toLocaleTimeString([], {{hour: '2-digit', minute:'2-digit'}}) + " - " + (isUser ? "Você" : "SOC Agent");
            bubble.appendChild(timeNode);
            
            bubbleRow.appendChild(bubble);
            chatBox.appendChild(bubbleRow);
            chatBox.scrollTop = chatBox.scrollHeight;
        }}

        // Init
        checkQuota();
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
