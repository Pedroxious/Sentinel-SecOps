import os
import requests
import json
import time
import csv
from datetime import datetime, timezone, timedelta
import google.generativeai as genai
from collections import OrderedDict

# ==========================================
# CONFIGURAÇÕES E CHAVES DE API
# ==========================================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
NVD_API_KEY    = os.getenv("NVD_API_KEY")

genai.configure(api_key=GEMINI_API_KEY)

# Usa o modelo Gemini 2.0 Flash
MODEL_NAME = "gemini-2.0-flash"
model = genai.GenerativeModel(MODEL_NAME)

# ─── 1. Migração de CSV (de 10 ou 14 para 19 colunas) ──────────────────────────
def migrate_csv():
    """Verifica se o CSV tem o formato antigo e migra para o novo formato de 19 colunas."""
    csv_file = "historico.csv"
    if not os.path.exists(csv_file):
        return

    needs_migration = False
    rows = []
    
    with open(csv_file, mode="r", encoding="utf-8") as f:
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
        print(f"🔄 Atualizando {csv_file} para 19 colunas...")
        new_header = [
            "data", "hora", "cve_id", "score", "severidade", 
            "priority_score", "priority_rating", "in_cisa_kev", "epss",
            "cwe_id", "attack_vector", "attack_complexity",
            "ransomware_known", "ioc_count",
            "setor", "software", "tem_patch", "exploitabilidade", "resumo"
        ]
        
        with open(csv_file, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(new_header)
            
            for row in rows:
                # Pad row if necessary to avoid index errors
                row = row + [""] * (19 - len(row))
                
                # Assign values based on old format guess (10, 14, or mixed)
                data = row[0]
                hora = row[1]
                cve_id = row[2]
                score = row[3]
                sev = row[4]
                
                # If it was a 10 column, it might have setor at 5
                if len(row) <= 10:
                    pri_s = "0.0"
                    pri_r = "MÉDIA"
                    kev = "False"
                    epss = "0.0"
                    cwe = "N/A"
                    av = "UNKNOWN"
                    ac = "UNKNOWN"
                    rk = "não"
                    ioc = "0"
                    setor = row[5] if len(row)>5 else "Other"
                    soft = row[6] if len(row)>6 else "N/A"
                    patch = row[7] if len(row)>7 else "não"
                    expl = row[8] if len(row)>8 else "Média"
                    res = row[9] if len(row)>9 else ""
                elif len(row) <= 14:
                    pri_s = row[5]
                    pri_r = row[6]
                    kev = row[7]
                    epss = row[8]
                    cwe = "N/A"
                    av = "UNKNOWN"
                    ac = "UNKNOWN"
                    rk = "não"
                    ioc = "0"
                    setor = row[9]
                    soft = row[10]
                    patch = row[11]
                    expl = row[12]
                    res = row[13]
                else:
                    # It's somewhat between 15 and 19? Just use what we have
                    pri_s = row[5]
                    pri_r = row[6]
                    kev = row[7]
                    epss = row[8]
                    cwe = row[9] or "N/A"
                    av = row[10] or "UNKNOWN"
                    ac = row[11] or "UNKNOWN"
                    rk = row[12] or "não"
                    ioc = row[13] or "0"
                    setor = row[14]
                    soft = row[15]
                    patch = row[16]
                    expl = row[17]
                    res = row[18]
                
                writer.writerow([
                    data, hora, cve_id, score, sev,
                    pri_s, pri_r, kev, epss,
                    cwe, av, ac, rk, ioc,
                    setor, soft, patch, expl, res
                ])
        print("✅ Migração concluída com sucesso.")


# ─── 2. Busca na API do NVD ────────────────────────────────────────────────
def get_cves():
    """Busca CVEs das últimas horas na API v2 do NVD."""
    # Como as actions rodam de 6 em 6 ou 8 em 8, pego as últimas 8h
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=8)
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_time.strftime("%Y-%m-%dT%H:%M:%S.000%z").replace("+0000", "Z"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000%z").replace("+0000", "Z")
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    print(f"📡 Buscando CVEs publicados desde {params['pubStartDate']}...")
    try:
        response = requests.get(url, params=params, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"⚠️ Erro ao acessar NVD: {e}")
        return []


# ─── 3. Filtro de Severidade CRITICAL e HIGH com detalhes ─────────────────
def filter_critical(vulnerabilities):
    """Filtra apenas CVEs com baseScore >= 7.0 (HIGH/CRITICAL) e extrai mais detalhes."""
    critical_cves = []
    
    for item in vulnerabilities:
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        
        # Pega a descrição em inglês
        desc = "N/A"
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value")
                break
                
        # Extrai pontuação CVSS 3.1, ou 3.0, ou 2
        score = 0
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0]["cvssData"]
                score = cvss_data.get("baseScore", 0)
                severity = cvss_data.get("baseSeverity", entries[0].get("baseSeverity", "UNKNOWN"))
                break

        # Extrai CWE
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

        # Extrai Vetor e Complexidade de Ataque
        attack_vector = "UNKNOWN"
        attack_complexity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0]["cvssData"]
                attack_vector = cvss_data.get("attackVector", "UNKNOWN")
                attack_complexity = cvss_data.get("attackComplexity", "UNKNOWN")
                break
                
        if score >= 7.0: # Apenas HIGH (7.0-8.9) e CRITICAL (9.0-10.0)
            # Extrai URLs de referência
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


# ─── 4. Integração CISA KEV e EPSS ────────────────────────────────────────
def get_cisa_kev_cves():
    """Busca o catálogo CISA KEV com dados de ransomware e ações requeridas."""
    print("🔍 Baixando catálogo CISA KEV atualizado...")
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
        print(f"   ✅ {len(kev_data)} CVEs conhecidamente exploradas carregadas do CISA.")
        return kev_data
    except Exception as e:
        print(f"⚠️ Erro ao buscar CISA KEV: {e}")
        return {}


def get_epss_scores(cve_ids):
    """Busca o EPSS (Exploit Prediction Scoring System) para os CVEs no FIRST."""
    if not cve_ids:
        return {}
    
    print(f"🔍 Consultando API FIRST EPSS para {len(cve_ids)} vulnerabilidades...")
    results = {}
    
    # EPSS API suporta consultar múltiplos CVEs separados por vírgula
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
            print(f"   ⚠️ Erro ao buscar EPSS (chunk): {e}")
            
    return results


# ─── 4.5 Novas APIs de Enriquecimento (ThreatFox e GitHub) ───────────────
def get_threatfox_iocs(cve_ids):
    """Busca IOCs (Indicators of Compromise) associados aos CVEs via ThreatFox (abuse.ch)."""
    results = {}
    for cve_id in cve_ids:
        try:
            # Note: ThreatFox doesn't strictly search CVEs via search_ioc effectively without an API key,
            # but we implement it as requested. Often returns nothing without the right tags.
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
        except Exception as e:
            # Supress detailed error to avoid spam
            results[cve_id] = {"count": 0, "ioc_types": [], "malware_families": []}
    return results


def get_github_advisories(cve_ids):
    """Busca advisories do GitHub Security Advisory Database (GHSA). Sem autenticação."""
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
        except Exception as e:
            results[cve_id] = None
        time.sleep(0.5) # Respeita o rate limit (60/hr unauth) ou se possivel n exagerar
    return results


# ─── 5. Cálculo de Priorização Híbrida ────────────────────────────────────
def calculate_priority_score(cve_id, cvss_score, in_cisa_kev, epss_data,
                             ransomware_known=False, ioc_count=0,
                             attack_vector="UNKNOWN", attack_complexity="UNKNOWN"):
    cvss = float(cvss_score)
    # CVSS pesa 40% (máx 4.0)
    cvss_points = cvss * 0.4
    # CISA KEV pesa 25% (2.5 pontos)
    kev_points = 2.5 if in_cisa_kev else 0.0
    # EPSS pesa 10% (1.0 ponto)
    epss_prob = epss_data.get("epss", 0.0) if epss_data else 0.0
    epss_points = epss_prob * 1.0
    # Ransomware pesa 10% (1.0 ponto)
    ransomware_points = 1.0 if ransomware_known else 0.0
    # IOCs pesa 5% (0.5 ponto)
    ioc_points = 0.5 if ioc_count > 0 else 0.0
    # Network + Low complexity pesa 10% (1.0 ponto)
    net_points = 0.0
    if attack_vector == "NETWORK":
        net_points += 0.5
    if attack_complexity == "LOW":
        net_points += 0.5
    
    priority_score = min(10.0, cvss_points + kev_points + epss_points + ransomware_points + ioc_points + net_points)
    
    if priority_score >= 8.5:
        priority_rating = "IMEDIATA"
    elif priority_score >= 7.0:
        priority_rating = "CRÍTICA"
    elif priority_score >= 5.0:
        priority_rating = "ALTA"
    else:
        priority_rating = "MÉDIA"
    
    return priority_score, priority_rating


# ─── 6. Integração com Gemini ─────────────────────────────────────────────
def parse_json_response(text):
    """Limpa o texto do Gemini e extrai o JSON."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.endswith("```"):
        text = text[:-3]
    return json.loads(text.strip())

def analyze_batch_with_gemini(cves, start_idx, end_idx):
    """Envia um lote de CVEs para o Gemini analisar."""
    print(f"🤖 Solicitando análise do Gemini (Lote {start_idx+1} até {end_idx})...")
    
    cves_input = []
    for c in cves[start_idx:end_idx]:
        cves_input.append({
            "id": c["id"],
            "description": c["description"],
            "score": c["score"],
            "severity": c["severity"],
            "cwe_id": c.get("cwe_id", "N/A"),
            "attack_vector": c.get("attack_vector", "UNKNOWN"),
            "attack_complexity": c.get("attack_complexity", "UNKNOWN"),
            "priority_score": f"{c['priority_score']:.1f}",
            "priority_rating": c["priority_rating"],
            "in_cisa_kev": "sim" if c["in_cisa_kev"] else "não",
            "ransomware_known": "sim" if c.get("ransomware_known") else "não",
            "ioc_count": c.get("ioc_count", 0),
            "epss": f"{c['epss_data'].get('epss', 0.0)*100:.3f}%",
            "ghsa_id": c.get("ghsa_data", {}).get("ghsa_id", "") if c.get("ghsa_data") else "",
            "references": c["references"]
        })

    prompt = f"""
    Você é um especialista em CyberSecOps da Sentinel. Analise detalhadamente estas {len(cves_input)} vulnerabilidades recém publicadas.
    Eles possuem inteligência combinada de CVSS, EPSS, CISA KEV, Ransomware ThreatFox e GitHub.
    
    Dados de entrada JSON:
    {json.dumps(cves_input)}
    
    Para cada CVE fornecido, retorne APENAS um array JSON válido contendo objetos com esta estrutura:
    [
      {{
        "id": "CVE-XXXX-XXXX",
        "setor": "Windows/Linux/Web/Database/Network/Mobile/Cloud/Other",
        "software": "Nome do software/produto afetado (ex: Microsoft Exchange, Apache, WordPress)",
        "tem_patch": "sim ou não (deduza pela descrição, referencias e GitHub advisory se existe patch)",
        "exploitabilidade": "Alta, Média ou Baixa (considere: in_cisa_kev, network, low_complexity, epss)",
        "resumo_o_que_e": "1 frase simples e direta explicando a vulnerabilidade em PT-BR.",
        "resumo_quem_afeta": "1 frase listando quem está vulnerável.",
        "resumo_o_que_fazer": "1 frase com a ação imediata recomendada."
      }}
    ]
    
    Não inclua markdown fora do JSON. Certifique-se de que o ID bate com a entrada.
    Se não souber deduzir o software, coloque 'N/A'.
    """
    
    try:
        response = model.generate_content(prompt)
        return parse_json_response(response.text)
    except Exception as e:
        print(f"⚠️ Erro ao processar lote no Gemini: {e}")
        try:
            print("⏳ Tentando novamente em 15s...")
            time.sleep(15)
            response = model.generate_content(prompt)
            return parse_json_response(response.text)
        except Exception as e2:
            print(f"❌ Falha definitiva no lote: {e2}")
            return None


# ─── 7. Dashboard HTML — Preset Sentinel SecOps ──────────────────────────────
def get_dashboard_filename(date_str):
    """Retorna o nome do arquivo do dashboard baseado na data do dia."""
    return f"dashboard-{date_str}.html"


def generate_manifest(date_str, cve_count, status):
    """Gera/atualiza dashboards/manifest.json com o catálogo de todos os dashboards."""
    os.makedirs("dashboards", exist_ok=True)
    manifest_path = "dashboards/manifest.json"

    manifest = []
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception:
            manifest = []

    # Remove entrada do dia atual (será recriada com dados atualizados)
    manifest = [e for e in manifest if e.get("date") != date_str]

    manifest.append({
        "filename": get_dashboard_filename(date_str),
        "date": date_str,
        "cve_count": cve_count,
        "status": status
    })

    manifest.sort(key=lambda x: x["date"], reverse=True)

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    return manifest


def _build_cve_card(item):
    """Constrói o HTML de um card CVE individual para o dashboard."""
    cve = item["cve"]
    analysis = item["analysis_raw"]
    is_crit = cve["severity"] == "CRITICAL"

    border_cls = "border-red-500/40 shadow-red-500/5" if is_crit else "border-amber-500/30 shadow-amber-500/5"
    dot_cls = "bg-red-500" if is_crit else "bg-amber-500"
    glow_cls = "glow-critical" if is_crit else ""
    sev_badge = "bg-red-500/20 text-red-400" if is_crit else "bg-amber-500/20 text-amber-400"

    priority_styles = {
        "IMEDIATA": "bg-fuchsia-500/20 text-fuchsia-400 border-fuchsia-500/30",
        "CRÍTICA":  "bg-red-500/20 text-red-400 border-red-500/30",
        "ALTA":     "bg-amber-500/20 text-amber-400 border-amber-500/30",
        "MÉDIA":    "bg-blue-500/20 text-blue-400 border-blue-500/30",
    }
    pri_cls = priority_styles.get(cve["priority_rating"], priority_styles["MÉDIA"])

    kev_html = ""
    if cve["in_cisa_kev"]:
        kev_html = (
            '<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded '
            'text-[0.65rem] font-bold bg-red-500/20 text-red-400 border border-red-500/30 '
            'animate-pulse">⚠ CISA KEV</span>'
        )
        
    cwe_id = cve.get("cwe_id", "N/A")
    attack_vector = cve.get("attack_vector", "UNKNOWN")
    attack_complexity = cve.get("attack_complexity", "UNKNOWN")
    complexity_cls = "text-red-400 border-red-500/20" if attack_complexity == "LOW" else "text-sky-400 border-sky-500/20"
    
    ransomware_html = ''
    if cve.get("ransomware_known"):
        ransomware_html = '<span class="px-2 py-0.5 rounded text-[0.65rem] font-bold bg-pink-500/15 text-pink-400 border border-pink-500/30 animate-pulse">🦠 RANSOMWARE</span>'
        
    ioc_html = ''
    count = cve.get("ioc_count", 0)
    if count > 0:
        ioc_html = f'<span class="px-2 py-0.5 rounded text-[0.65rem] font-medium bg-orange-500/10 text-orange-400 border border-orange-500/20">🔗 {count} IOCs</span>'
        
    ghsa_html = ''
    ghsa_data = cve.get("ghsa_data")
    if ghsa_data:
        ghsa_html = f'<a href="{ghsa_data["url"]}" target="_blank" class="px-2 py-0.5 rounded text-[0.65rem] font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:bg-purple-500/20 transition-colors">{ghsa_data["ghsa_id"]}</a>'


    refs_html = ""
    if cve.get("references"):
        refs_links = "".join(
            f'<a href="{ref}" target="_blank" rel="noopener" '
            f'class="text-sentinel-cyan/70 hover:text-sentinel-cyan text-sm truncate block transition-colors">{ref}</a>'
            for ref in cve["references"]
        )
        refs_html = (
            '<div class="mt-4 pt-4 border-t border-white/5">'
            '<p class="text-xs text-gray-500 uppercase tracking-wider mb-2">Referências</p>'
            f'{refs_links}</div>'
        )

    compare_html = ""
    if analysis.get("comparacao_ontem"):
        compare_html = (
            f'<div class="mt-3 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20 text-sm">'
            f'<span class="text-amber-400 font-semibold">↻ Comparação:</span> '
            f'<span class="text-gray-300">{analysis["comparacao_ontem"]}</span></div>'
        )

    epss_val = cve["epss_data"].get("epss", 0.0) * 100
    epss_pct = cve["epss_data"].get("percentile", 0.0) * 100
    has_patch = analysis.get("tem_patch") == "sim"
    patch_cls = "text-emerald-400" if has_patch else "text-red-400"
    patch_txt = "✓ Disponível" if has_patch else "✗ Indisponível"
    exploit = analysis.get("exploitabilidade", "Média")
    exploit_cls = "text-red-400" if exploit == "Alta" else ("text-amber-400" if exploit == "Média" else "text-emerald-400")
    setor = analysis.get("setor", "Other")
    software = analysis.get("software", "N/A")
    kev_flag = "sim" if cve["in_cisa_kev"] else "não"

    return f'''<div class="glass-card rounded-2xl p-6 border {border_cls} shadow-lg hover:shadow-xl transition-all duration-300 hover:-translate-y-1 cve-card {glow_cls} fade-in"
     data-severity="{cve['severity']}" data-sector="{setor}" data-patch="{analysis.get('tem_patch', 'não')}" data-priority="{cve['priority_rating']}" data-kev="{kev_flag}" data-vector="{attack_vector}">
    <div class="flex flex-wrap items-start justify-between gap-3 mb-2">
        <div class="flex items-center gap-3 flex-wrap">
            <span class="w-2.5 h-2.5 rounded-full {dot_cls} animate-pulse"></span>
            <a href="https://nvd.nist.gov/vuln/detail/{cve['id']}" target="_blank"
               class="text-lg font-bold text-gray-100 hover:text-sentinel-cyan transition-colors">{cve['id']}</a>
            <span class="px-2 py-0.5 rounded text-[0.65rem] font-bold {sev_badge}">{cve['severity']}</span>
            <span class="px-2 py-0.5 rounded text-[0.65rem] font-semibold bg-white/5 text-gray-300 border border-white/10">CVSS {cve['score']}</span>
            <span class="px-2 py-0.5 rounded text-[0.65rem] font-bold border {pri_cls}">{cve['priority_rating']} ({cve['priority_score']:.1f})</span>
            {kev_html}
        </div>
        <span class="px-2.5 py-1 rounded-lg text-xs font-semibold bg-sentinel-cyan/10 text-sentinel-cyan border border-sentinel-cyan/20">{setor}</span>
    </div>
    
    <!-- Novo TIER de Intel Indicators -->
    <div class="flex flex-wrap gap-2 mb-3 mt-1">
        <span class="px-2 py-0.5 rounded text-[0.65rem] font-medium bg-violet-500/10 text-violet-400 border border-violet-500/20">{cwe_id}</span>
        <span class="px-2 py-0.5 rounded text-[0.65rem] font-medium bg-sky-500/10 text-sky-400 border border-sky-500/20">🎯 {attack_vector}</span>
        <span class="px-2 py-0.5 rounded text-[0.65rem] font-medium {complexity_cls}">⚙ {attack_complexity}</span>
        {ransomware_html}
        {ioc_html}
        {ghsa_html}
    </div>
    
    <div class="mb-4 p-3 rounded-lg bg-white/[0.02] border-l-2 border-sentinel-cyan/50">
        <p class="text-[0.65rem] text-gray-500 uppercase tracking-wider mb-1">Software Afetado</p>
        <p class="text-sm font-medium text-gray-200">{software}</p>
    </div>
    <div class="space-y-2.5 mb-4">
        <div class="flex gap-2"><span class="text-gray-500 font-medium text-sm shrink-0">O que é:</span><span class="text-sm text-gray-300">{analysis.get('resumo_o_que_e', '')}</span></div>
        <div class="flex gap-2"><span class="text-gray-500 font-medium text-sm shrink-0">Quem afeta:</span><span class="text-sm text-gray-300">{analysis.get('resumo_quem_afeta', '')}</span></div>
        <div class="flex gap-2"><span class="text-gray-500 font-medium text-sm shrink-0">O que fazer:</span><span class="text-sm text-gray-300">{analysis.get('resumo_o_que_fazer', '')}</span></div>
    </div>
    <div class="flex flex-wrap gap-3 text-xs">
        <div class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white/[0.03] border border-white/5">
            <span class="text-gray-500">EPSS:</span><span class="font-semibold text-gray-300">{epss_val:.3f}%</span><span class="text-gray-600">(P{epss_pct:.0f})</span>
        </div>
        <div class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white/[0.03] border border-white/5">
            <span class="text-gray-500">Patch:</span><span class="font-semibold {patch_cls}">{patch_txt}</span>
        </div>
        <div class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white/[0.03] border border-white/5">
            <span class="text-gray-500">Exploitabilidade:</span><span class="font-semibold {exploit_cls}">{exploit}</span>
        </div>
    </div>
    {compare_html}
    {refs_html}
</div>'''


def generate_dashboard(cves_analyzed, date_str, hour_str):
    """Cria o dashboard HTML5 diário com Tailwind CSS embutido + CSS3 custom."""
    os.makedirs("dashboards", exist_ok=True)
    filename = get_dashboard_filename(date_str)
    filepath = f"dashboards/{filename}"

    total   = len(cves_analyzed)
    crit    = sum(1 for i in cves_analyzed if i["cve"]["severity"] == "CRITICAL")
    imm     = sum(1 for i in cves_analyzed if i["cve"]["priority_rating"] == "IMEDIATA")
    kev     = sum(1 for i in cves_analyzed if i["cve"]["in_cisa_kev"])
    patched = sum(1 for i in cves_analyzed if i["analysis_raw"].get("tem_patch") == "sim")
    ransomware = sum(1 for i in cves_analyzed if i["cve"].get("ransomware_known"))
    iocs = sum(1 for i in cves_analyzed if i["cve"].get("ioc_count", 0) > 0)

    # ── Constrói os cards HTML ────────────────────────────────────────────────
    if not cves_analyzed:
        cards_html = (
            '<div class="col-span-full flex flex-col items-center justify-center py-20 '
            'glass-card rounded-2xl fade-in">'
            '<div class="text-6xl mb-4">🟢</div>'
            '<h3 class="text-2xl font-bold text-gray-100 mb-2">Tudo Limpo</h3>'
            '<p class="text-gray-400">Nenhuma vulnerabilidade HIGH ou CRITICAL nas últimas 8 horas.</p></div>'
        )
    else:
        cards_html = "\n".join(_build_cve_card(item) for item in cves_analyzed)

    # ── Status do dia ─────────────────────────────────────────────────────────
    if not cves_analyzed:
        status = "🟢 Calmo"
    elif imm > 0:
        status = "🚨 Ação Imediata"
    elif crit > 0:
        status = "🔴 Crítico"
    else:
        status = "🟡 Atenção"

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel SecOps — {date_str}</title>
    <meta name="description" content="Sentinel SecOps Threat Intelligence Dashboard — Relatório de {date_str}">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
    tailwind.config = {{
        theme: {{
            extend: {{
                colors: {{
                    sentinel: {{
                        bg: '#0a0f1e',
                        surface: '#111827',
                        border: '#1e293b',
                        cyan: '#00f0ff',
                        pink: '#ff2d55',
                    }}
                }},
                fontFamily: {{
                    sans: ['Inter', 'system-ui', 'sans-serif'],
                }}
            }}
        }}
    }}
    </script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        *,*::before,*::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: #0a0f1e;
            color: #f3f4f6;
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
        }}

        body::before {{
            content: '';
            position: fixed;
            inset: 0;
            background:
                radial-gradient(ellipse at 15% 0%, rgba(0,240,255,.08) 0%, transparent 50%),
                radial-gradient(ellipse at 85% 100%, rgba(255,45,85,.05) 0%, transparent 50%),
                linear-gradient(rgba(0,240,255,.025) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,240,255,.025) 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 44px 44px, 44px 44px;
            pointer-events: none;
            z-index: 0;
        }}

        .sentinel-wrap {{ position: relative; z-index: 1; }}

        .glass-card {{
            background: rgba(17, 24, 39, 0.6);
            backdrop-filter: blur(16px) saturate(1.2);
            -webkit-backdrop-filter: blur(16px) saturate(1.2);
            border: 1px solid rgba(255, 255, 255, 0.06);
        }}

        @keyframes scanline {{
            0%   {{ transform: translateY(-100%); opacity: 0; }}
            10%  {{ opacity: 1; }}
            90%  {{ opacity: 1; }}
            100% {{ transform: translateY(100vh); opacity: 0; }}
        }}
        .scanline {{
            position: fixed; top: 0; left: 0; width: 100%; height: 2px;
            background: linear-gradient(90deg, transparent 0%, rgba(0,240,255,.5) 50%, transparent 100%);
            animation: scanline 7s linear infinite;
            pointer-events: none; z-index: 100;
        }}

        @keyframes glowPulse {{
            0%,100% {{ box-shadow: inset 0 0 20px rgba(239,68,68,.08), 0 0 12px rgba(239,68,68,.04); }}
            50%     {{ box-shadow: inset 0 0 30px rgba(239,68,68,.14), 0 0 22px rgba(239,68,68,.08); }}
        }}
        .glow-critical {{ animation: glowPulse 3s ease-in-out infinite; }}

        @keyframes fadeInUp {{
            from {{ opacity: 0; transform: translateY(16px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}
        .fade-in {{ animation: fadeInUp .45s ease-out forwards; opacity: 0; }}
        .fade-in:nth-child(1)  {{ animation-delay: .04s; }}
        .fade-in:nth-child(2)  {{ animation-delay: .08s; }}
        .fade-in:nth-child(3)  {{ animation-delay: .12s; }}
        .fade-in:nth-child(4)  {{ animation-delay: .16s; }}
        .fade-in:nth-child(5)  {{ animation-delay: .20s; }}

        .brand-gradient {{
            background: linear-gradient(135deg, #00f0ff 0%, #3b82f6 50%, #8b5cf6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .stat-glow {{ transition: box-shadow .3s, transform .3s; }}
        .stat-glow:hover {{
            box-shadow: 0 0 28px rgba(0,240,255,.08);
            transform: translateY(-2px);
        }}

        ::-webkit-scrollbar       {{ width: 5px; }}
        ::-webkit-scrollbar-track {{ background: #0a0f1e; }}
        ::-webkit-scrollbar-thumb {{ background: #1e293b; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #334155; }}

        select.sentinel-sel {{
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath d='M6 8L1 3h10z' fill='%234b5563'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right .75rem center;
            padding-right: 2.25rem;
        }}
    </style>
</head>
<body class="text-gray-100 min-h-screen">
    <div class="scanline"></div>

    <div class="sentinel-wrap max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">

        <header class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8 fade-in">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-lg shadow-lg shadow-cyan-500/20">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div>
                    <h1 class="text-2xl font-extrabold brand-gradient tracking-tight">Sentinel SecOps</h1>
                    <p class="text-[0.65rem] text-gray-500 tracking-[0.2em] uppercase">Threat Intelligence Dashboard</p>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <a href="../index.html" class="text-xs text-sentinel-cyan/60 hover:text-sentinel-cyan border border-sentinel-cyan/20 hover:border-sentinel-cyan/40 px-3 py-1.5 rounded-lg transition-all duration-200">
                    ← Hub Principal
                </a>
                <div class="text-right">
                    <p class="text-sm text-gray-400">Relatório de <span class="text-gray-200 font-semibold">{date_str}</span></p>
                    <p class="text-xs text-gray-500">Atualizado às {hour_str} (Brasília)</p>
                </div>
            </div>
        </header>

        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-8">
            <div class="glass-card rounded-xl p-4 text-center stat-glow fade-in">
                <div class="text-3xl font-extrabold text-cyan-400 mb-1" id="s-total">{total}</div>
                <div class="text-[0.6rem] text-gray-500 uppercase tracking-[0.15em] font-medium">Total CVEs</div>
            </div>
            <div class="glass-card rounded-xl p-4 text-center stat-glow fade-in">
                <div class="text-3xl font-extrabold text-fuchsia-400 mb-1" id="s-imm">{imm}</div>
                <div class="text-[0.6rem] text-gray-500 uppercase tracking-[0.15em] font-medium">Ação Imediata</div>
            </div>
            <div class="glass-card rounded-xl p-4 text-center stat-glow fade-in">
                <div class="text-3xl font-extrabold text-red-400 mb-1" id="s-kev">{kev}</div>
                <div class="text-[0.6rem] text-gray-500 uppercase tracking-[0.15em] font-medium">CISA KEV</div>
            </div>
            <div class="glass-card rounded-xl p-4 text-center stat-glow fade-in">
                <div class="text-3xl font-extrabold text-pink-400 mb-1" id="s-ran">{ransomware}</div>
                <div class="text-[0.6rem] text-gray-500 uppercase tracking-[0.15em] font-medium">Ransomware</div>
            </div>
            <div class="glass-card rounded-xl p-4 text-center stat-glow fade-in">
                <div class="text-3xl font-extrabold text-orange-400 mb-1" id="s-ioc">{iocs}</div>
                <div class="text-[0.6rem] text-gray-500 uppercase tracking-[0.15em] font-medium">IOCs Ativos</div>
            </div>
        </div>

        <div class="glass-card rounded-xl p-5 mb-8 fade-in">
            <div class="flex items-center gap-2 mb-4">
                <span class="text-sentinel-cyan text-sm">⚡</span>
                <span class="text-xs font-semibold text-gray-400 uppercase tracking-[0.15em]">Filtros Interativos</span>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                <div>
                    <label class="block text-[0.6rem] text-gray-500 uppercase tracking-[0.15em] mb-1.5 font-medium" for="q">Pesquisa</label>
                    <input type="text" id="q" placeholder="CVE, software..."
                           class="w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2.5 text-sm text-gray-200 focus:border-sentinel-cyan/50 outline-none transition-all duration-200"
                           oninput="applyFilters()">
                </div>
                <div>
                    <label class="block text-[0.6rem] text-gray-500 uppercase tracking-[0.15em] mb-1.5 font-medium" for="f-sev">Severidade</label>
                    <select id="f-sev" class="sentinel-sel w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2.5 text-sm text-gray-200 focus:border-sentinel-cyan/50 outline-none transition-all duration-200" onchange="applyFilters()">
                        <option value="all">Todas</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option>
                    </select>
                </div>
                <div>
                    <label class="block text-[0.6rem] text-gray-500 uppercase tracking-[0.15em] mb-1.5 font-medium" for="f-sec">Setor</label>
                    <select id="f-sec" class="sentinel-sel w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2.5 text-sm text-gray-200 focus:border-sentinel-cyan/50 outline-none transition-all duration-200" onchange="applyFilters()">
                        <option value="all">Todos</option><option value="Windows">Windows</option><option value="Linux">Linux</option>
                        <option value="Web">Web</option><option value="Database">Database</option><option value="Network">Network</option>
                        <option value="Mobile">Mobile</option><option value="Cloud">Cloud</option><option value="Other">Other</option>
                    </select>
                </div>
                <div>
                    <label class="block text-[0.6rem] text-gray-500 uppercase tracking-[0.15em] mb-1.5 font-medium" for="f-pat">Patch</label>
                    <select id="f-pat" class="sentinel-sel w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2.5 text-sm text-gray-200 focus:border-sentinel-cyan/50 outline-none transition-all duration-200" onchange="applyFilters()">
                        <option value="all">Todos</option><option value="sim">Com Patch ✓</option><option value="não">Sem Patch ✗</option>
                    </select>
                </div>
                <div>
                    <label class="block text-[0.6rem] text-gray-500 uppercase tracking-[0.15em] mb-1.5 font-medium" for="f-vec">Vetor de Ataque</label>
                    <select id="f-vec" class="sentinel-sel w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2.5 text-sm text-gray-200 focus:border-sentinel-cyan/50 outline-none transition-all duration-200" onchange="applyFilters()">
                        <option value="all">Todos</option><option value="NETWORK">Network</option><option value="LOCAL">Local</option><option value="ADJACENT_NETWORK">Adjacent</option>
                    </select>
                </div>
            </div>
        </div>

        <div class="space-y-4" id="cve-list">
            {cards_html}
        </div>

        <footer class="mt-12 pt-6 border-t border-white/[0.04] text-center">
            <p class="text-[0.7rem] text-gray-600">
                Sentinel SecOps · Automated Threat Intelligence ·
                <a href="https://github.com/Pedroxious/Sentinel-SecOps" target="_blank"
                   class="text-sentinel-cyan/40 hover:text-sentinel-cyan transition-colors">GitHub</a> ·
                <a href="https://github.com/Pedroxious" target="_blank"
                   class="text-sentinel-cyan/40 hover:text-sentinel-cyan transition-colors">@Pedroxious</a>
            </p>
        </footer>

    </div>

    <script>
    function applyFilters() {{
        const q   = document.getElementById('q').value.toLowerCase();
        const sev = document.getElementById('f-sev').value;
        const sec = document.getElementById('f-sec').value;
        const pat = document.getElementById('f-pat').value;
        const vec = document.getElementById('f-vec').value;
        
        let t = 0;

        document.querySelectorAll('.cve-card').forEach(c => {{
            const text = c.textContent.toLowerCase();
            const show =
                (q === '' || text.includes(q)) &&
                (sev === 'all' || c.dataset.severity === sev) &&
                (sec === 'all' || c.dataset.sector === sec) &&
                (pat === 'all' || c.dataset.patch === pat) &&
                (vec === 'all' || c.dataset.vector === vec);

            c.style.display = show ? '' : 'none';
            if (show) t++;
        }});

        document.getElementById('s-total').textContent = t;
    }}
    </script>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    generate_manifest(date_str, total, status)
    print(f"   📄 Dashboard salvo: {filepath}")
    return filename

# ─── 8. Relatório Markdown Diário ─────────────────────────────────────────
def get_yesterday_report_content():
    """Tenta recuperar o relatório gerado no ciclo anterior."""
    try:
        with open("README.md", "r", encoding="utf-8") as f:
            content = f.read()
        if "## Relatório do Turno" in content:
            start_idx = content.find("## Relatório do Turno")
            return content[start_idx:]
    except:
        pass
    return ""

def generate_report(cves_analyzed, date_str, hour_str, yesterday_content=""):
    """Gera a porção do relatório para colocar no README."""
    report = [f"## Relatório do Turno ({hour_str} - Brasília)\n\n"]
    
    if not cves_analyzed:
        report.append("✅ **Tudo limpo!** Nenhuma vulnerabilidade CRITICAL ou HIGH detectada no último ciclo.\n")
    else:
        for item in cves_analyzed:
            cve = item["cve"]
            analysis = item["analysis_raw"]
            is_crit = cve["severity"] == "CRITICAL"
            sev_icon = "🔴" if is_crit else "🟠"
            kev_text = "🚨 **CISA KEV:** SIM (Risco Imediato!)" if cve["in_cisa_kev"] else "CISA KEV: Não"
            
            report.append(f"### {sev_icon} [{cve['id']}](https://nvd.nist.gov/vuln/detail/{cve['id']}) - {analysis.get('software', 'N/A')}\n")
            report.append(f"- **Prioridade:** {cve['priority_rating']} (Score: {cve['priority_score']:.1f}/10.0)\n")
            report.append(f"- **CVSS:** {cve['score']} ({cve['severity']})\n")
            report.append(f"- **EPSS:** {cve['epss_data'].get('epss', 0.0)*100:.2f}%\n")
            report.append(f"- **CWE:** `{cve.get('cwe_id', 'N/A')}`\n")
            report.append(f"- **Vetor de Ataque:** `{cve.get('attack_vector', 'N/A')}` | Complexidade: `{cve.get('attack_complexity', 'N/A')}`\n")
            
            if cve.get('ransomware_known'):
                report.append(f"- **🦠 Ransomware:** Associação CONHECIDA\n")
                
            ioc_data = cve.get('ioc_data', {})
            if ioc_data and ioc_data.get('count', 0) > 0:
                report.append(f"- **IOCs (ThreatFox):** {ioc_data['count']} indicador(es) encontrado(s)\n")
                
            ghsa = cve.get('ghsa_data')
            if ghsa:
                report.append(f"- **GitHub Advisory:** [{ghsa['ghsa_id']}]({ghsa.get('url', '')})\n")
                
            report.append(f"- **{kev_text}**\n")
            report.append(f"- **Patch:** {'✅ Sim' if analysis.get('tem_patch') == 'sim' else '❌ Não ou Desconhecido'}\n")
            report.append(f"- **Resumo:** {analysis.get('resumo_o_que_e', '')}\n")
            report.append(f"- **Recomendação:** {analysis.get('resumo_o_que_fazer', '')}\n\n")

    return "".join(report)

# ─── 9. Atualização do CSV de Histórico ──────────────────────────────────
def update_csv(cves_analyzed, date_str, hour_str):
    csv_file = "historico.csv"
    file_exists = os.path.exists(csv_file)
    
    with open(csv_file, mode="a", encoding="utf-8", newline="") as f:
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
                date_str,
                hour_str,
                cve["id"],
                cve["score"],
                cve["severity"],
                f"{cve['priority_score']:.1f}",
                cve["priority_rating"],
                cve["in_cisa_kev"],
                cve["epss_data"].get("epss", 0.0),
                cve.get("cwe_id", "N/A"),
                cve.get("attack_vector", "UNKNOWN"),
                cve.get("attack_complexity", "UNKNOWN"),
                "sim" if cve.get("ransomware_known") else "não",
                cve.get("ioc_count", 0),
                an.get("setor", "Other"),
                an.get("software", "N/A"),
                an.get("tem_patch", "não"),
                an.get("exploitabilidade", "Média"),
                an.get("resumo_o_que_e", "")
            ])

# ─── 10. Atualiza README ──────────────────────────────────────────────────
def update_readme(date_str, hour_str, count_cves, dashboard_file, status_badge):
    """Atualiza o arquivo README.md principal com o novo relatório."""
    print("📝 Atualizando README.md...")
    
    with open("README.md", "r", encoding="utf-8") as f:
        content = f.read()

    new_status = (
        f"**Última Atualização:** {date_str} {hour_str} (Brasília)\n\n"
        f"**Status da Rede:** {status_badge}\n\n"
        f"**CVEs Críticos Hoje:** {count_cves}\n\n"
        f"**📊 [Ver Dashboard Detalhado](dashboards/{dashboard_file})**\n\n"
    )

    try:
        start_idx = content.find("<!-- STATUS_START -->") + len("<!-- STATUS_START -->\n")
        end_idx = content.find("<!-- STATUS_END -->")
        if start_idx != -1 and end_idx != -1:
            content = content[:start_idx] + new_status + content[end_idx:]
    except Exception as e:
        print(f"⚠️ Erro ao atualizar status no README: {e}")

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(content)


# ─── 11. MAIN FLOW ────────────────────────────────────────────────────────
def main():
    print("🚀 Iniciando o Sentinel SecOps - Threat Intel Automation\n")
    
    migrate_csv()
    
    now_br = datetime.now(timezone.utc) - timedelta(hours=3)
    date_str = now_br.strftime("%Y-%m-%d")
    hour_str = now_br.strftime("%H:%M")
    
    # 1. Busca CVEs no NVD
    raw_vulnerabilities = get_cves()
    print(f"   Encontradas {len(raw_vulnerabilities)} vulnerabilidades nas últimas horas.")
    
    if not raw_vulnerabilities:
        print("   Tudo calmo! Finalizando.")
        # Gera dashboard limpo
        dashboard_file = generate_dashboard([], date_str, hour_str)
        update_readme(date_str, hour_str, 0, dashboard_file, "🟢 Seguro - Nenhum novo alerta crítico")
        return

    # 2. Filtra HIGH/CRITICAL e enriquece intel básica
    critical_cves = filter_critical(raw_vulnerabilities)
    print(f"   Filtradas {len(critical_cves)} vulnerabilidades com Score >= 7.0 (HIGH/CRITICAL).")
    
    if not critical_cves:
        dashboard_file = generate_dashboard([], date_str, hour_str)
        update_readme(date_str, hour_str, 0, dashboard_file, "🟢 Seguro - Apenas alertas de baixa severidade")
        return

    # 3. Enriquece com CISA KEV, EPSS, ThreatFox, GitHub
    cve_ids = [c["id"] for c in critical_cves]
    kev_data = get_cisa_kev_cves()
    epss_scores = get_epss_scores(cve_ids)
    
    print("🔍 Buscando IOCs no ThreatFox (abuse.ch)...")
    threatfox_data = get_threatfox_iocs(cve_ids)
    
    print("🔍 Buscando advisories no GitHub Security...")
    ghsa_data = get_github_advisories(cve_ids)

    for cve in critical_cves:
        cve_id = cve["id"]
        cve["in_cisa_kev"] = cve_id in kev_data
        cve["ransomware_known"] = kev_data.get(cve_id, {}).get("ransomware_known", "Unknown") == "Known"
        cve["kev_action"] = kev_data.get(cve_id, {}).get("required_action", "N/A")
        cve["kev_due_date"] = kev_data.get(cve_id, {}).get("due_date", "N/A")
        cve["epss_data"] = epss_scores.get(cve_id, {"epss": 0.0, "percentile": 0.0})
        cve["ioc_data"] = threatfox_data.get(cve_id, {"count": 0, "ioc_types": [], "malware_families": []})
        cve["ioc_count"] = cve["ioc_data"]["count"]
        cve["ghsa_data"] = ghsa_data.get(cve_id)
        
        priority_score, priority_rating = calculate_priority_score(
            cve_id, cve["score"], cve["in_cisa_kev"], cve["epss_data"],
            ransomware_known=cve["ransomware_known"],
            ioc_count=cve["ioc_count"],
            attack_vector=cve.get("attack_vector", "UNKNOWN"),
            attack_complexity=cve.get("attack_complexity", "UNKNOWN")
        )
        cve["priority_score"] = priority_score
        cve["priority_rating"] = priority_rating

    # 4. Envia pro Gemini analisar em lotes de 10
    cves_analyzed = []
    batch_size = 10
    for i in range(0, len(critical_cves), batch_size):
        end_idx = min(i + batch_size, len(critical_cves))
        gemini_results = analyze_batch_with_gemini(critical_cves, i, end_idx)
        
        if gemini_results:
            # Associa a analise do Gemini com os dados brutos
            # O gemini pode retornar fora de ordem, entao criamos um dict lookup
            lookup = {r["id"]: r for r in gemini_results if "id" in r}
            for cve in critical_cves[i:end_idx]:
                if cve["id"] in lookup:
                    cves_analyzed.append({
                        "cve": cve,
                        "analysis_raw": lookup[cve["id"]]
                    })
                else:
                    print(f"⚠️ Gemini não retornou análise para {cve['id']}")
        
        # Pausa para não estourar rate limit da API gratuita do Gemini
        time.sleep(3)

    print(f"\n✅ Análise concluída para {len(cves_analyzed)} CVEs.\n")

    # 5. Salva dados, gera relatorio e atualiza dashboard
    update_csv(cves_analyzed, date_str, hour_str)
    
    # 6. Gera Dashboard do Dia (cria ou atualiza arquivo do dia)
    dashboard_file = generate_dashboard(cves_analyzed, date_str, hour_str)
    
    status_badge = "🟡 Atenção"
    if any(item["cve"]["priority_rating"] == "IMEDIATA" for item in cves_analyzed):
        status_badge = "🚨 CRÍTICO - Ação Imediata Requerida"
    elif any(item["cve"]["severity"] == "CRITICAL" for item in cves_analyzed):
        status_badge = "🔴 Alerta Vermelho"

    update_readme(date_str, hour_str, len(cves_analyzed), dashboard_file, status_badge)
    
    print("\n✨ Sentinel SecOps finalizado com sucesso!")

if __name__ == "__main__":
    main()
