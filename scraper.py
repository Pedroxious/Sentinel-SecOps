import os
import json
import requests
import csv
from datetime import datetime, timedelta, timezone

import google.generativeai as genai

# ─── Config ───────────────────────────────────────────────────────────────────
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
NVD_API_KEY    = os.environ.get("NVD_API_KEY", "")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.0-flash")
else:
    model = None


# ─── 0. Migração do CSV ───────────────────────────────────────────────────────
def migrate_csv():
    """Migra o historico.csv do formato de 4 colunas para o de 10 colunas."""
    filepath = "historico.csv"
    if not os.path.exists(filepath):
        return

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except Exception as e:
        print(f"⚠️ Erro ao ler historico.csv para migração: {e}")
        return

    if not content:
        return

    lines = content.split("\n")
    header = [h.strip() for h in lines[0].split(",")]
    
    new_header = [
        "data", "hora", "cve_id", "score", "severidade", 
        "setor", "software", "tem_patch", "exploitabilidade", "resumo"
    ]

    # Se o cabeçalho tiver menos colunas, migra
    if len(header) < len(new_header):
        print("📊 Detectado historico.csv antigo. Migrando para o formato de 10 colunas...")
        rows = []
        try:
            reader = csv.DictReader(lines)
            for row in reader:
                new_row = {
                    "data": row.get("data", "").strip(),
                    "hora": "00:00",
                    "cve_id": row.get("cve_id", "").strip(),
                    "score": row.get("score", "").strip(),
                    "severidade": row.get("severidade", "").strip(),
                    "setor": "Other",
                    "software": "N/A",
                    "tem_patch": "não",
                    "exploitabilidade": "Média",
                    "resumo": "N/A"
                }
                rows.append(new_row)
        except Exception as e:
            print(f"❌ Erro ao parsear CSV antigo: {e}")
            return

        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=new_header)
                writer.writeheader()
                for r in rows:
                    writer.writerow(r)
            print("✅ historico.csv migrado com sucesso!")
        except Exception as e:
            print(f"❌ Erro ao escrever historico.csv migrado: {e}")


# ─── 1. Busca CVEs na NVD ─────────────────────────────────────────────────────
def get_cves():
    """Busca CVEs publicados nas últimas 8 horas."""
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=8)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   now.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    resp = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params=params,
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


# ─── 2. Filtra HIGH e CRITICAL ────────────────────────────────────────────────
def filter_critical(cves):
    """Mantém apenas CVEs com severidade HIGH ou CRITICAL."""
    filtered = []

    for item in cves:
        cve     = item.get("cve", {})
        metrics = cve.get("metrics", {})

        score    = None
        severity = None

        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                score    = entries[0]["cvssData"]["baseScore"]
                severity = entries[0]["cvssData"]["baseSeverity"]
                break

        if score is None:
            entries = metrics.get("cvssMetricV2", [])
            if entries:
                score    = entries[0]["cvssData"]["baseScore"]
                severity = "HIGH" if float(score) >= 7.0 else "MEDIUM"

        if severity in ("HIGH", "CRITICAL") and score is not None:
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "No description available.",
            )
            filtered.append({
                "id":          cve.get("id"),
                "description": desc,
                "score":       score,
                "severity":    severity,
                "published":   cve.get("published", ""),
                "references":  [r.get("url") for r in cve.get("references", [])[:3]],
            })

    # Retorna os 10 mais graves
    return sorted(filtered, key=lambda x: x["score"], reverse=True)[:10]


# ─── 3. Analisa em Batch com Gemini ───────────────────────────────────────────
def parse_json_response(text):
    """Extrai e parseia o array JSON da resposta do Gemini."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    return json.loads(text)


def analyze_batch_with_gemini(cves, yesterday_report_content=""):
    """Pede ao Gemini uma análise em batch e estruturada dos CVEs."""
    if not model:
        raise ValueError("Gemini model não configurado. Verifique GEMINI_API_KEY.")

    cves_input = []
    for c in cves:
        cves_input.append({
            "id": c["id"],
            "description": c["description"],
            "score": c["score"],
            "severity": c["severity"],
            "references": c["references"]
        })
        
    cves_json_str = json.dumps(cves_input, indent=2, ensure_ascii=False)
    
    yesterday_context = ""
    if yesterday_report_content:
        # Limita o tamanho do relatório de ontem para evitar estouro de tokens
        yesterday_context = f"\nConteúdo do relatório de ontem (para comparação de novos patches, criticidade ou reincidências):\n{yesterday_report_content[:5000]}\n"
        
    prompt = f"""Você é um especialista em SecOps de alta senioridade.
Sua tarefa é analisar em lote (batch) os seguintes CVEs publicados recentemente.

{yesterday_context}

Lista de CVEs a analisar:
{cves_json_str}

Instruções importantes:
1. Filtre ruídos: Avalie a relevância/importância real de cada vulnerabilidade. Softwares obsoletos, muito específicos ou de baixo impacto prático devem ser marcados como "relevante": false. Apenas vulnerabilidades que realmente valem a atenção de uma equipe de SecOps devem ter "relevante": true.
2. Modo Ultra-resumido: O resumo deve ter exatamente 3 linhas explicativas curtas e em português (brasileiro):
   - Linha 1: O que é a vulnerabilidade.
   - Linha 2: Quem ou o que ela afeta.
   - Linha 3: O que fazer para se proteger ou mitigar.
3. Classifique o setor: Escolha EXATAMENTE um dos seguintes: Windows | Linux | Web | Database | Network | Mobile | Cloud | Other.
4. Detecte patch: Analise a descrição e referências para indicar se há correção/patch disponível ("sim" ou "não").
5. Exploitabilidade: Avalie a facilidade de exploração prática como "Baixa", "Média" ou "Alta", acompanhado de uma justificativa curta.
6. Comparação com ontem: Se a vulnerabilidade foi mencionada no relatório de ontem e teve atualizações importantes (como novo patch ou gravidade maior) ou se é uma reincidência, explique em uma frase curta no campo "comparacao_ontem". Se não houve alterações ou não se aplica, coloque null.

Retorne EXATAMENTE um array JSON contendo um objeto para cada CVE analisado no seguinte formato (sem explicações antes ou depois do JSON):
[
  {{
    "cve_id": "CVE-YYYY-XXXX",
    "relevante": true,
    "setor": "Web",
    "software": "Apache HTTP Server 2.4.58",
    "tem_patch": "sim",
    "exploitabilidade": "Alta",
    "justificativa_exploitabilidade": "Exploit público disponível e execução remota de código simples.",
    "resumo_o_que_e": "O que é...",
    "resumo_quem_afeta": "Quem afeta...",
    "resumo_o_que_fazer": "O que fazer...",
    "comparacao_ontem": null
  }}
]
"""

    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        return parse_json_response(response.text)
    except Exception as e:
        print(f"⚠️ Erro na análise em lote: {e}. Tentando fallback individual...")
        # Fallback para análise individual caso o batch completo falhe
        analyzed_list = []
        for cve in cves:
            try:
                single_prompt = f"""Você é um especialista em SecOps. Analise o seguinte CVE de forma individual e retorne no formato JSON descrito.
                
                CVE: {json.dumps(cve, ensure_ascii=False)}
                
                Retorne um objeto JSON com as chaves:
                - "cve_id": "{cve['id']}"
                - "relevante": true
                - "setor": "Windows | Linux | Web | Database | Network | Mobile | Cloud | Other"
                - "software": nome do software afetado
                - "tem_patch": "sim" ou "não"
                - "exploitabilidade": "Baixa" ou "Média" ou "Alta"
                - "justificativa_exploitabilidade": justificativa
                - "resumo_o_que_e": "O que é"
                - "resumo_quem_afeta": "Quem afeta"
                - "resumo_o_que_fazer": "O que fazer"
                - "comparacao_ontem": null
                """
                resp = model.generate_content(
                    single_prompt,
                    generation_config={"response_mime_type": "application/json"}
                )
                data = json.loads(resp.text.strip())
                analyzed_list.append(data)
            except Exception as ex:
                print(f"❌ Erro no fallback do CVE {cve['id']}: {ex}")
                analyzed_list.append({
                    "cve_id": cve["id"],
                    "relevante": True,
                    "setor": "Other",
                    "software": "N/A",
                    "tem_patch": "não",
                    "exploitabilidade": "Média",
                    "justificativa_exploitabilidade": "Não analisado devido a erro.",
                    "resumo_o_que_e": cve["description"][:100],
                    "resumo_quem_afeta": "N/A",
                    "resumo_o_que_fazer": "Consulte as referências.",
                    "comparacao_ontem": None
                })
        return analyzed_list


# ─── 4. Tendência Semanal ─────────────────────────────────────────────────────
def weekly_trend(today_str):
    """Gera um parágrafo sobre a tendência de segurança da semana."""
    if not model or not os.path.exists("historico.csv"):
        return ""

    try:
        today = datetime.strptime(today_str, "%Y-%m-%d")
        start_date = today - timedelta(days=7)
    except Exception:
        return ""

    weekly_rows = []
    try:
        with open("historico.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                row_date_str = row.get("data")
                if row_date_str:
                    try:
                        row_date = datetime.strptime(row_date_str, "%Y-%m-%d")
                        if start_date <= row_date <= today:
                            weekly_rows.append(row)
                    except ValueError:
                        pass
    except Exception as e:
        print(f"⚠️ Erro ao ler histórico para tendência semanal: {e}")
        return ""

    if not weekly_rows:
        return ""

    rows_text = ""
    for r in weekly_rows:
        rows_text += f"- Data: {r.get('data')}, CVE: {r.get('cve_id')}, Severidade: {r.get('severidade')}, Setor: {r.get('setor')}, Software: {r.get('software')}\n"

    prompt = f"""Você é um analista SecOps experiente. Analise a lista de CVEs encontrados no monitoramento na última semana e gere uma análise de tendência semanal estruturada em exatamente um parágrafo claro e objetivo em português.
Destaque:
1. Quais foram os vetores de ataque ou setores mais visados.
2. Quais sistemas/softwares foram mais afetados.
3. Qual a recomendação geral de segurança para a infraestrutura.

Lista de CVEs da semana:
{rows_text}

Forneça APENAS o parágrafo de texto corrido (sem títulos, sem cabeçalhos e sem marcações markdown como negrito no início)."""

    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"⚠️ Erro ao gerar tendência semanal com o Gemini: {e}")
        return ""


# ─── 5. Gera relatório .md ────────────────────────────────────────────────────
def get_yesterday_report_content(brasilia):
    """Busca o conteúdo do relatório de ontem se houver."""
    yesterday = brasilia - timedelta(days=1)
    yesterday_str = yesterday.strftime("%Y-%m-%d")
    filepath = f"reports/{yesterday_str}.md"
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            print(f"⚠️ Erro ao ler relatório de ontem: {e}")
    return ""


def generate_report(cves_analyzed, date_str, hour_str, trend_paragraph=""):
    """Escreve as análises no relatório .md diário."""
    os.makedirs("reports", exist_ok=True)
    filepath = f"reports/{date_str}.md"
    mode     = "a" if os.path.exists(filepath) else "w"

    with open(filepath, mode, encoding="utf-8") as f:
        if mode == "w":
            f.write(f"# 🔐 Sentinel SecOps — {date_str}\n\n")
            f.write("*Daily SecOps intelligence — automated CVE monitoring, AI-powered threat analysis & vulnerability insights*\n\n")
            f.write("---\n\n")
            
            if trend_paragraph:
                f.write(f"## 📊 Análise de Tendência Semanal\n\n")
                f.write(f"{trend_paragraph}\n\n")
                f.write("---\n\n")

        f.write(f"## 🕐 Atualização das {hour_str} (Brasília)\n\n")

        if not cves_analyzed:
            f.write("✅ Nenhuma vulnerabilidade **HIGH** ou **CRITICAL** publicada neste período.\n\n")
            return

        f.write(f"> ⚠️ **{len(cves_analyzed)} vulnerabilidade(s) encontrada(s)**\n\n")

        for item in cves_analyzed:
            cve      = item["cve"]
            analysis = item["analysis_raw"]
            emoji    = "🔴" if cve["severity"] == "CRITICAL" else "🟠"

            f.write(f"### {emoji} [{cve['id']}](https://nvd.nist.gov/vuln/detail/{cve['id']}) — Score: `{cve['score']}/10` ({cve['severity']})\n\n")
            
            f.write(f"**O que é:** {analysis.get('resumo_o_que_e', '')}\n")
            f.write(f"**Quem afeta:** {analysis.get('resumo_quem_afeta', '')}\n")
            f.write(f"**O que fazer:** {analysis.get('resumo_o_que_fazer', '')}\n\n")
            
            f.write(f"- **Setor:** `{analysis.get('setor', 'Other')}`\n")
            f.write(f"- **Software afetado:** {analysis.get('software', 'N/A')}\n")
            f.write(f"- **Correção disponível (Patch):** `{analysis.get('tem_patch', 'não')}`\n")
            f.write(f"- **Exploitabilidade:** `{analysis.get('exploitabilidade', 'Média')}` ({analysis.get('justificativa_exploitabilidade', '')})\n")
            
            if analysis.get("comparacao_ontem"):
                f.write(f"- **Comparação com ontem:** {analysis['comparacao_ontem']}\n")
                
            f.write("\n")

            if cve["references"]:
                f.write("**Referências:**\n")
                for ref in cve["references"]:
                    f.write(f"- {ref}\n")

            f.write("\n---\n\n")


# ─── 6. Atualiza historico.csv ────────────────────────────────────────────────
def update_csv(cves_analyzed, date_str, hour_str):
    """Registra os novos CVEs analisados no CSV de histórico."""
    filepath = "historico.csv"
    file_exists = os.path.exists(filepath)
    
    existing_cves = set()
    if file_exists:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cid = row.get("cve_id")
                    if cid:
                        existing_cves.add(cid)
        except Exception as e:
            print(f"⚠️ Erro ao ler CVEs existentes do histórico: {e}")

    new_header = [
        "data", "hora", "cve_id", "score", "severidade", 
        "setor", "software", "tem_patch", "exploitabilidade", "resumo"
    ]
    
    mode = "a" if file_exists else "w"
    with open(filepath, mode, newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=new_header)
        if not file_exists:
            writer.writeheader()
            
        for item in cves_analyzed:
            cve = item["cve"]
            analysis = item["analysis_raw"]
            
            # Garante que nunca duplica entradas na mesma execução ou anteriores
            if cve["id"] in existing_cves:
                continue
                
            resumo_str = f"O que é: {analysis.get('resumo_o_que_e', '')} | Quem afeta: {analysis.get('resumo_quem_afeta', '')} | O que fazer: {analysis.get('resumo_o_que_fazer', '')}"
            
            writer.writerow({
                "data": date_str,
                "hora": hour_str,
                "cve_id": cve["id"],
                "score": cve["score"],
                "severidade": cve["severity"],
                "setor": analysis.get("setor", "Other"),
                "software": analysis.get("software", "N/A"),
                "tem_patch": analysis.get("tem_patch", "não"),
                "exploitabilidade": analysis.get("exploitabilidade", "Média"),
                "resumo": resumo_str
            })
            existing_cves.add(cve["id"])


# ─── 7. Dashboard Interativo HTML ─────────────────────────────────────────────
def get_next_dashboard_number():
    """Retorna o número sequencial correto para o novo dashboard."""
    os.makedirs("dashboards", exist_ok=True)
    files = os.listdir("dashboards")
    numbers = []
    for f in files:
        if f.startswith("html") and f.endswith(".html"):
            try:
                num = int(f[4:-5])
                numbers.append(num)
            except ValueError:
                pass
    if not numbers:
        return 1
    return max(numbers) + 1


def generate_dashboard(cves_analyzed, date_str, hour_str):
    """Cria um arquivo de dashboard HTML dinâmico, interativo e com design premium."""
    num = get_next_dashboard_number()
    filepath = f"dashboards/html{num}.html"
    
    total_count = len(cves_analyzed)
    critical_count = sum(1 for item in cves_analyzed if item["cve"]["severity"] == "CRITICAL")
    high_count = sum(1 for item in cves_analyzed if item["cve"]["severity"] == "HIGH")
    patch_count = sum(1 for item in cves_analyzed if item["analysis_raw"].get("tem_patch") == "sim")
    no_patch_count = total_count - patch_count
    
    cve_cards_list = []
    if not cves_analyzed:
        cards_html = '<div class="no-data"><h3>Nenhuma vulnerabilidade encontrada</h3><p>Tudo sob controle nas últimas 8 horas.</p></div>'
    else:
        for item in cves_analyzed:
            cve = item["cve"]
            analysis = item["analysis_raw"]
            severity_class = "critical" if cve["severity"] == "CRITICAL" else "high"
            
            ref_list_html = ""
            if cve.get("references"):
                ref_list_html = '<div class="references-box"><div class="references-title">Referências:</div><ul class="references-list">'
                for ref in cve["references"]:
                    ref_list_html += f'<li><a href="{ref}" target="_blank">{ref}</a></li>'
                ref_list_html += '</ul></div>'
                
            compare_html = ""
            if analysis.get("comparacao_ontem"):
                compare_html = f'<div class="compare-box"><strong>Comparação com ontem:</strong> {analysis["comparacao_ontem"]}</div>'
                
            card_html = f"""
            <div class="cve-card {severity_class}" data-severity="{cve['severity']}" data-sector="{analysis.get('setor', 'Other')}" data-patch="{analysis.get('tem_patch', 'não')}">
                <div class="cve-header">
                    <div class="cve-title-area">
                        <a href="https://nvd.nist.gov/vuln/detail/{cve['id']}" target="_blank" class="cve-id">{cve['id']}</a>
                        <span class="badge badge-{severity_class}">{cve['severity']}</span>
                        <span class="badge badge-score">Score: {cve['score']}</span>
                        <span class="badge badge-sector">{analysis.get('setor', 'Other')}</span>
                    </div>
                    <div class="cve-meta-badges">
                        <div class="meta-property">
                            <span class="meta-property-label">Patch:</span>
                            <span class="meta-property-value patch-{analysis.get('tem_patch', 'não')}">{analysis.get('tem_patch', 'não').upper()}</span>
                        </div>
                        <div class="meta-property">
                            <span class="meta-property-label">Exploitabilidade:</span>
                            <span class="meta-property-value exploit-{analysis.get('exploitabilidade', 'Média')}">{analysis.get('exploitabilidade', 'Média')}</span>
                        </div>
                    </div>
                </div>
                <div class="cve-body">
                    <div class="software-affected">
                        <strong>Software Afetado:</strong>
                        <span class="software-affected-name">{analysis.get('software', 'Não especificado')}</span>
                    </div>
                    <div class="summary-box">
                        <div class="summary-line"><strong>O que é:</strong> {analysis.get('resumo_o_que_e', '')}</div>
                        <div class="summary-line"><strong>Quem afeta:</strong> {analysis.get('resumo_quem_afeta', '')}</div>
                        <div class="summary-line"><strong>O que fazer:</strong> {analysis.get('resumo_o_que_fazer', '')}</div>
                    </div>
                    {compare_html}
                    {ref_list_html}
                </div>
            </div>
            """
            cve_cards_list.append(card_html)
        cards_html = "\n".join(cve_cards_list)
        
    html_template = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel SecOps - Dashboard {date_str}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #080b11;
            --card-bg: rgba(17, 24, 39, 0.7);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-critical: #ef4444;
            --accent-high: #f97316;
            --accent-patch: #10b981;
            --accent-no-patch: #6b7280;
            --accent-blue: #3b82f6;
            --glow-critical: rgba(239, 68, 68, 0.15);
            --glow-high: rgba(249, 115, 22, 0.15);
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            min-height: 100vh;
            background-image: 
                radial-gradient(at 0% 0%, rgba(59, 130, 246, 0.1) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(239, 68, 68, 0.05) 0px, transparent 50%);
            background-attachment: fixed;
            padding: 2rem;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--card-border);
        }}

        .logo {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}

        .logo h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            background: linear-gradient(to right, #3b82f6, #ef4444);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .meta-info {{
            text-align: right;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}

        .meta-info span {{
            color: var(--text-primary);
            font-weight: 600;
        }}

        /* Stats Section */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 1.25rem;
            text-align: center;
            backdrop-filter: blur(8px);
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }}

        .stat-val {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }}

        .stat-label {{
            font-size: 0.875rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .stat-total {{ color: var(--accent-blue); }}
        .stat-critical {{ color: var(--accent-critical); }}
        .stat-high {{ color: var(--accent-high); }}
        .stat-patch {{ color: var(--accent-patch); }}
        .stat-no-patch {{ color: var(--accent-no-patch); }}

        /* Filter Section */
        .controls-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 2rem;
            backdrop-filter: blur(8px);
        }}

        .filters-title {{
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .filters-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}

        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}

        .filter-group label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .filter-control {{
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--card-border);
            border-radius: 6px;
            padding: 0.6rem 0.75rem;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 0.875rem;
            outline: none;
            cursor: pointer;
            transition: border-color 0.2s;
        }}

        .filter-control:focus {{
            border-color: var(--accent-blue);
        }}

        .search-control {{
            width: 100%;
        }}

        /* CVE Cards */
        .cve-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 1.5rem;
        }}

        .cve-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 14px;
            padding: 1.75rem;
            backdrop-filter: blur(8px);
            transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s;
            position: relative;
            overflow: hidden;
        }}

        .cve-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
        }}

        .cve-card.critical::before {{ background-color: var(--accent-critical); }}
        .cve-card.high::before {{ background-color: var(--accent-high); }}

        .cve-card.critical {{
            box-shadow: inset 0 0 15px var(--glow-critical);
        }}
        .cve-card.high {{
            box-shadow: inset 0 0 15px var(--glow-high);
        }}

        .cve-card:hover {{
            transform: translateY(-2px);
            border-color: rgba(255, 255, 255, 0.15);
        }}

        .cve-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1.25rem;
        }}

        .cve-title-area {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }}

        .cve-id {{
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-primary);
            text-decoration: none;
        }}

        .cve-id:hover {{
            text-decoration: underline;
            color: var(--accent-blue);
        }}

        .badge {{
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}

        .badge-critical {{
            background-color: rgba(239, 68, 68, 0.15);
            color: var(--accent-critical);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}

        .badge-high {{
            background-color: rgba(249, 115, 22, 0.15);
            color: var(--accent-high);
            border: 1px solid rgba(249, 115, 22, 0.3);
        }}

        .badge-score {{
            background-color: rgba(255, 255, 255, 0.05);
            color: var(--text-primary);
            border: 1px solid var(--card-border);
        }}

        .badge-sector {{
            background-color: rgba(59, 130, 246, 0.15);
            color: var(--accent-blue);
            border: 1px solid rgba(59, 130, 246, 0.3);
        }}

        .cve-meta-badges {{
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }}

        /* Badges for exploitability and patch */
        .meta-property {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            background: rgba(0, 0, 0, 0.2);
            padding: 0.4rem 0.75rem;
            border-radius: 6px;
            border: 1px solid var(--card-border);
        }}

        .meta-property-label {{
            color: var(--text-secondary);
        }}

        .meta-property-value {{
            font-weight: 600;
        }}

        .patch-sim {{ color: var(--accent-patch); }}
        .patch-nao {{ color: var(--accent-critical); }}
        
        .exploit-Alta {{ color: var(--accent-critical); }}
        .exploit-Media {{ color: var(--accent-high); }}
        .exploit-Baixa {{ color: var(--accent-patch); }}

        .cve-body {{
            margin-bottom: 1.5rem;
        }}

        .software-affected {{
            font-size: 0.95rem;
            margin-bottom: 1rem;
            padding: 0.75rem;
            background: rgba(255, 255, 255, 0.02);
            border-left: 3px solid var(--accent-blue);
            border-radius: 0 6px 6px 0;
        }}

        .software-affected strong {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            display: block;
            margin-bottom: 0.25rem;
            text-transform: uppercase;
        }}

        /* 3-line Summary */
        .summary-box {{
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            margin-bottom: 1.25rem;
        }}

        .summary-line {{
            font-size: 0.95rem;
            line-height: 1.5;
        }}

        .summary-line strong {{
            color: var(--text-secondary);
            font-weight: 600;
            margin-right: 0.25rem;
        }}

        .compare-box {{
            background: rgba(249, 115, 22, 0.08);
            border: 1px solid rgba(249, 115, 22, 0.2);
            border-radius: 8px;
            padding: 0.75rem;
            margin-bottom: 1.25rem;
            font-size: 0.9rem;
        }}

        .compare-box strong {{
            color: var(--accent-high);
        }}

        .references-box {{
            border-top: 1px solid var(--card-border);
            padding-top: 1rem;
        }}

        .references-title {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }}

        .references-list {{
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }}

        .references-list a {{
            color: var(--accent-blue);
            text-decoration: none;
            font-size: 0.875rem;
            word-break: break-all;
        }}

        .references-list a:hover {{
            text-decoration: underline;
        }}

        .no-data {{
            text-align: center;
            padding: 4rem;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            color: var(--text-secondary);
        }}

        .no-data h3 {{
            font-size: 1.5rem;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }}

        @media (max-width: 768px) {{
            body {{ padding: 1rem; }}
            header {{ flex-direction: column; align-items: flex-start; gap: 1rem; }}
            .meta-info {{ text-align: left; }}
            .cve-header {{ flex-direction: column; align-items: flex-start; }}
            .cve-meta-badges {{ flex-wrap: wrap; width: 100%; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <span>🛡️</span>
                <h1>Sentinel SecOps</h1>
            </div>
            <div class="meta-info">
                Relatório Diário de Ameaças<br>
                Atualizado em: <span>{date_str} às {hour_str}</span> (Brasília)
            </div>
        </header>

        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-val stat-total" id="stat-total">{total_count}</div>
                <div class="stat-label">Total CVEs</div>
            </div>
            <div class="stat-card">
                <div class="stat-val stat-critical" id="stat-critical">{critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-val stat-high" id="stat-high">{high_count}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-val stat-patch" id="stat-patch">{patch_count}</div>
                <div class="stat-label">Com Patch</div>
            </div>
            <div class="stat-card">
                <div class="stat-val stat-no-patch" id="stat-no-patch">{no_patch_count}</div>
                <div class="stat-label">Sem Patch</div>
            </div>
        </div>

        <!-- Controls -->
        <div class="controls-card">
            <div class="filters-title">
                <span>🔍</span> Filtros Interativos
            </div>
            <div class="filters-grid">
                <div class="filter-group">
                    <label for="search-input">Pesquisa</label>
                    <input type="text" id="search-input" class="filter-control search-control" placeholder="Buscar por CVE, software ou descrição..." oninput="filterCVEs()">
                </div>
                <div class="filter-group">
                    <label for="severity-filter">Severidade</label>
                    <select id="severity-filter" class="filter-control" onchange="filterCVEs()">
                        <option value="all">Todas</option>
                        <option value="CRITICAL">CRITICAL</option>
                        <option value="HIGH">HIGH</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="sector-filter">Setor</label>
                    <select id="sector-filter" class="filter-control" onchange="filterCVEs()">
                        <option value="all">Todos</option>
                        <option value="Windows">Windows</option>
                        <option value="Linux">Linux</option>
                        <option value="Web">Web</option>
                        <option value="Database">Database</option>
                        <option value="Network">Network</option>
                        <option value="Mobile">Mobile</option>
                        <option value="Cloud">Cloud</option>
                        <option value="Other">Other</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="patch-filter">Correção (Patch)</label>
                    <select id="patch-filter" class="filter-control" onchange="filterCVEs()">
                        <option value="all">Todos</option>
                        <option value="sim">Com Correção (Sim)</option>
                        <option value="não">Sem Correção (Não)</option>
                    </select>
                </div>
            </div>
        </div>

        <!-- CVE List -->
        <div class="cve-grid" id="cve-container">
            {cards_html}
        </div>
    </div>

    <script>
        function filterCVEs() {{
            const searchQuery = document.getElementById('search-input').value.toLowerCase();
            const severityFilter = document.getElementById('severity-filter').value;
            const sectorFilter = document.getElementById('sector-filter').value;
            const patchFilter = document.getElementById('patch-filter').value;
            
            const cards = document.querySelectorAll('.cve-card');
            let visibleCount = 0;
            let criticalCount = 0;
            let highCount = 0;
            let patchCount = 0;
            let noPatchCount = 0;

            cards.forEach(card => {{
                const id = card.querySelector('.cve-id').textContent.toLowerCase();
                const softwareEl = card.querySelector('.software-affected-name');
                const software = softwareEl ? softwareEl.textContent.toLowerCase() : '';
                const bodyText = card.querySelector('.cve-body').textContent.toLowerCase();
                
                const sev = card.getAttribute('data-severity');
                const sector = card.getAttribute('data-sector');
                const patch = card.getAttribute('data-patch');
                
                const matchesSearch = id.includes(searchQuery) || software.includes(searchQuery) || bodyText.includes(searchQuery);
                const matchesSeverity = (severityFilter === 'all' || sev === severityFilter);
                const matchesSector = (sectorFilter === 'all' || sector === sectorFilter);
                const matchesPatch = (patchFilter === 'all' || patch === patchFilter);
                
                if (matchesSearch && matchesSeverity && matchesSector && matchesPatch) {{
                    card.style.display = 'block';
                    visibleCount++;
                    if (sev === 'CRITICAL') criticalCount++;
                    if (sev === 'HIGH') highCount++;
                    if (patch === 'sim') patchCount++;
                    if (patch === 'não') noPatchCount++;
                }} else {{
                    card.style.display = 'none';
                }}
            }});

            // Update stats cards based on filter
            document.getElementById('stat-total').textContent = visibleCount;
            document.getElementById('stat-critical').textContent = criticalCount;
            document.getElementById('stat-high').textContent = highCount;
            document.getElementById('stat-patch').textContent = patchCount;
            document.getElementById('stat-no-patch').textContent = noPatchCount;

            // Handle no results
            let noDataEl = document.getElementById('no-results-msg');
            if (visibleCount === 0) {{
                if (!noDataEl) {{
                    noDataEl = document.createElement('div');
                    noDataEl.id = 'no-results-msg';
                    noDataEl.className = 'no-data';
                    noDataEl.innerHTML = '<h3>Nenhum CVE encontrado</h3><p>Tente ajustar os filtros ou a busca.</p>';
                    document.getElementById('cve-container').appendChild(noDataEl);
                }}
            }} else if (noDataEl) {{
                noDataEl.remove();
            }}
        }}
    </script>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_template)
    return num


# ─── 8. Atualiza README ───────────────────────────────────────────────────────
def update_readme(date_str, hour_str, count, dashboard_num, status_badge):
    """Atualiza o arquivo README.md com o badge de status e link do dashboard."""
    if not os.path.exists("README.md"):
        return

    try:
        with open("README.md", "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"⚠️ Erro ao ler README.md: {e}")
        return

    new_badge = (
        f"> 🕐 **Última atualização:** {date_str} às {hour_str} (Brasília) "
        f"| 📊 **Status:** {status_badge} ({count} novos) "
        f"| 🖥️ **[Dashboard Atual](./dashboards/html{dashboard_num}.html)**"
    )

    lines = content.split("\n")
    replaced = False
    for i, line in enumerate(lines):
        if "Última atualização:" in line:
            lines[i] = new_badge
            replaced = True
            break
            
    if not replaced:
        lines.insert(2, new_badge)

    try:
        with open("README.md", "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    except Exception as e:
        print(f"⚠️ Erro ao escrever README.md: {e}")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    # 0. Migração do CSV para 10 colunas se necessário
    migrate_csv()

    if not GEMINI_API_KEY:
        print("❌ Erro: A variável de ambiente GEMINI_API_KEY não está definida.")
        return

    now          = datetime.now(timezone.utc)
    brasilia     = now - timedelta(hours=3)
    date_str     = brasilia.strftime("%Y-%m-%d")
    hour_str     = brasilia.strftime("%H:%M")

    print(f"\n🛡️  Sentinel SecOps iniciado — {date_str} às {hour_str} (Brasília)\n")

    # 1. Busca
    print("🔍 Buscando CVEs nas últimas 8h...")
    try:
        raw_cves = get_cves()
        print(f"   📥 {len(raw_cves)} CVEs encontrados\n")
    except Exception as e:
        print(f"   ❌ Erro na busca de CVEs: {e}")
        return

    # 2. Filtra
    critical_cves = filter_critical(raw_cves)
    print(f"⚠️  {len(critical_cves)} são HIGH ou CRITICAL")

    # 3. Filtra CVEs já presentes no histórico local para economizar créditos do Gemini
    existing_cves = set()
    if os.path.exists("historico.csv"):
        try:
            with open("historico.csv", "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cid = row.get("cve_id")
                    if cid:
                        existing_cves.add(cid.strip())
        except Exception as e:
            print(f"   ⚠️ Erro ao ler histórico para filtrar duplicados: {e}")

    new_cves = [c for c in critical_cves if c["id"] not in existing_cves]
    print(f"🆕 {len(new_cves)} são novos CVEs para análise\n")

    cves_analyzed = []
    if new_cves:
        # Lê o relatório de ontem para comparação (se existir)
        yesterday_content = get_yesterday_report_content(brasilia)
        
        print(f"🤖 Analisando {len(new_cves)} CVEs em batch com Gemini...")
        try:
            gemini_results = analyze_batch_with_gemini(new_cves, yesterday_content)
            results_by_id = {res["cve_id"]: res for res in gemini_results if "cve_id" in res}
            
            for cve in new_cves:
                analysis = results_by_id.get(cve["id"])
                if analysis:
                    if analysis.get("relevante", True):
                        cves_analyzed.append({
                            "cve": cve,
                            "analysis_raw": analysis
                        })
                    else:
                        print(f"   🧹 CVE {cve['id']} ignorado como ruído/irrelevante.")
                else:
                    print(f"   ⚠️ CVE {cve['id']} ausente na resposta principal da IA. Usando fallback individual...")
                    # Fallback individual em caso de perda de algum ID no JSON do lote
                    try:
                        single_results = analyze_batch_with_gemini([cve], yesterday_content)
                        if single_results and single_results[0].get("relevante", True):
                            cves_analyzed.append({
                                "cve": cve,
                                "analysis_raw": single_results[0]
                            })
                    except Exception as ex:
                        print(f"   ❌ Erro no fallback individual de {cve['id']}: {ex}")
        except Exception as e:
            print(f"   ❌ Erro crítico na análise em lote: {e}")
    else:
        print("   Nenhum novo CVE para analisar.")

    # 4. Tendência Semanal (toda segunda-feira)
    trend_paragraph = ""
    if brasilia.weekday() == 0:
        print("📊 Hoje é segunda-feira! Gerando análise de tendência semanal...")
        trend_paragraph = weekly_trend(date_str)
        if trend_paragraph:
            print("   ✅ Tendência semanal gerada com sucesso.")

    # 5. Gera relatório
    generate_report(cves_analyzed, date_str, hour_str, trend_paragraph)
    print(f"\n📝 Relatório salvo em reports/{date_str}.md")

    # 6. Atualiza CSV
    if cves_analyzed:
        update_csv(cves_analyzed, date_str, hour_str)
        print("📊 historico.csv updated")

    # 7. Gera Dashboard HTML
    dashboard_num = generate_dashboard(cves_analyzed, date_str, hour_str)
    print(f"🖥️  Dashboard html{dashboard_num}.html gerado com sucesso!")

    # 8. Atualiza README
    if not cves_analyzed:
        status_badge = "🟢 Calmo"
    elif any(item["cve"]["score"] >= 9.0 for item in cves_analyzed):
        status_badge = "🔴 Crítico"
    elif len(cves_analyzed) > 3:
        status_badge = "🔴 Crítico"
    else:
        status_badge = "🟡 Moderado"

    update_readme(date_str, hour_str, len(cves_analyzed), dashboard_num, status_badge)
    print("📄 README.md atualizado")

    print("\n✅ Sentinel SecOps finalizado com sucesso!\n")


if __name__ == "__main__":
    main()
