import os
import requests
import csv
from datetime import datetime, timedelta, timezone

import google.generativeai as genai

# ─── Config ───────────────────────────────────────────────────────────────────
GEMINI_API_KEY = os.environ["GEMINI_API_KEY"]
NVD_API_KEY    = os.environ.get("NVD_API_KEY", "")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-2.0-flash")


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


# ─── 3. Analisa com Gemini ────────────────────────────────────────────────────
def analyze_with_gemini(cve):
    """Pede ao Gemini uma análise em português do CVE."""
    prompt = f"""Você é um especialista em segurança cibernética. Analise esta vulnerabilidade e responda em português brasileiro de forma clara e objetiva.

CVE ID: {cve['id']}
Score CVSS: {cve['score']} ({cve['severity']})
Descrição técnica: {cve['description']}

Responda EXATAMENTE neste formato (sem texto fora dele):

**O que é:** [explique em 1-2 frases simples o que é a vulnerabilidade]
**Software afetado:** [qual software, versão ou sistema está vulnerável]
**Impacto:** [o que um atacante consegue fazer ao explorar isso]
**Recomendação:** [o que fazer para se proteger — atualizar, mitigar, etc.]
**Risco para infra/devs:** [baixo / médio / alto — e por quê em uma frase curta]"""

    response = model.generate_content(prompt)
    return response.text


# ─── 4. Gera relatório .md ────────────────────────────────────────────────────
def generate_report(cves_analyzed, date_str, hour_str):
    os.makedirs("reports", exist_ok=True)
    filepath = f"reports/{date_str}.md"
    mode     = "a" if os.path.exists(filepath) else "w"

    with open(filepath, mode, encoding="utf-8") as f:
        if mode == "w":
            f.write(f"# 🔐 Sentinel SecOps — {date_str}\n\n")
            f.write("*Daily SecOps intelligence — automated CVE monitoring, AI-powered threat analysis & vulnerability insights*\n\n")
            f.write("---\n\n")

        f.write(f"## 🕐 Atualização das {hour_str} (Brasília)\n\n")

        if not cves_analyzed:
            f.write("✅ Nenhuma vulnerabilidade **HIGH** ou **CRITICAL** publicada neste período.\n\n")
            return

        f.write(f"> ⚠️ **{len(cves_analyzed)} vulnerabilidade(s) encontrada(s)**\n\n")

        for item in cves_analyzed:
            cve      = item["cve"]
            analysis = item["analysis"]
            emoji    = "🔴" if cve["severity"] == "CRITICAL" else "🟠"

            f.write(f"### {emoji} [{cve['id']}](https://nvd.nist.gov/vuln/detail/{cve['id']}) — Score: `{cve['score']}/10` ({cve['severity']})\n\n")
            f.write(f"{analysis}\n\n")

            if cve["references"]:
                f.write("**Referências:**\n")
                for ref in cve["references"]:
                    f.write(f"- {ref}\n")

            f.write("\n---\n\n")


# ─── 5. Atualiza historico.csv ────────────────────────────────────────────────
def update_csv(cves, date_str):
    file_exists = os.path.exists("historico.csv")

    with open("historico.csv", "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["data", "cve_id", "score", "severidade"])
        for cve in cves:
            writer.writerow([date_str, cve["id"], cve["score"], cve["severity"]])


# ─── 6. Atualiza README ───────────────────────────────────────────────────────
def update_readme(date_str, hour_str, count):
    if not os.path.exists("README.md"):
        return

    with open("README.md", "r", encoding="utf-8") as f:
        content = f.read()

    new_badge = (
        f"> 🕐 **Última atualização:** {date_str} às {hour_str} (Brasília) "
        f"| 📊 **CVEs críticos:** {count} encontrados"
    )

    lines = content.split("\n")
    for i, line in enumerate(lines):
        if "Última atualização:" in line:
            lines[i] = new_badge
            break
    else:
        # Se não achou a linha, adiciona após o título
        lines.insert(2, new_badge)

    with open("README.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    now          = datetime.now(timezone.utc)
    brasilia     = now - timedelta(hours=3)
    date_str     = brasilia.strftime("%Y-%m-%d")
    hour_str     = brasilia.strftime("%H:%M")

    print(f"\n🛡️  Sentinel SecOps iniciado — {date_str} às {hour_str} (Brasília)\n")

    # 1. Busca
    print("🔍 Buscando CVEs nas últimas 8h...")
    raw_cves = get_cves()
    print(f"   📥 {len(raw_cves)} CVEs encontrados\n")

    # 2. Filtra
    critical_cves = filter_critical(raw_cves)
    print(f"⚠️  {len(critical_cves)} são HIGH ou CRITICAL\n")

    # 3. Analisa com IA
    cves_analyzed = []
    for cve in critical_cves:
        print(f"🤖 Analisando {cve['id']} (Score: {cve['score']})...")
        try:
            analysis = analyze_with_gemini(cve)
            cves_analyzed.append({"cve": cve, "analysis": analysis})
        except Exception as e:
            print(f"   ❌ Erro: {e}")

    # 4. Gera relatório
    generate_report(cves_analyzed, date_str, hour_str)
    print(f"\n📝 Relatório salvo em reports/{date_str}.md")

    # 5. Atualiza CSV
    update_csv(critical_cves, date_str)
    print("📊 historico.csv atualizado")

    # 6. Atualiza README
    update_readme(date_str, hour_str, len(critical_cves))
    print("📄 README.md atualizado")

    print("\n✅ Sentinel SecOps finalizado com sucesso!\n")


if __name__ == "__main__":
    main()
