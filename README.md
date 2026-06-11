# 🔐 Sentinel SecOps

*Daily SecOps intelligence — automated CVE monitoring, AI-powered threat analysis & vulnerability insights*

> 🕐 **Última atualização:** 2026-06-11 às 15:58 (Brasília) | 📊 **CVEs críticos:** 10 encontrados

---

## O que é?

**Sentinel SecOps** é um agente de segurança automatizado que roda **3 vezes por dia** via GitHub Actions.

Ele monitora a [NVD (National Vulnerability Database)](https://nvd.nist.gov/) — o maior banco de vulnerabilidades do mundo — filtra as falhas de severidade **HIGH** e **CRITICAL**, e usa **Gemini AI** para explicar cada uma em português: o que é, o que foi afetado, qual o impacto real e o que fazer.

---

## Como funciona

```
GitHub Actions (05h, 11h, 17h — Brasília)
        ↓
   scraper.py
        ↓
  NVD API → busca CVEs das últimas 8h
        ↓
  Filtra HIGH e CRITICAL (score ≥ 7.0)
        ↓
  Gemini 2.0 Flash → analisa em português
        ↓
  Gera reports/YYYY-MM-DD.md
  Atualiza historico.csv
  Commit automático no repositório
```

---

## Stack

| Tecnologia | Função |
|---|---|
| Python 3.11 | Script principal |
| NVD API (NIST) | Fonte oficial de CVEs |
| Gemini 2.0 Flash | Análise com IA em pt-BR |
| GitHub Actions | Agendamento e commit automático |

---

## Relatórios

Os relatórios diários ficam na pasta [`/reports`](./reports), um arquivo `.md` por dia.

Cada CVE encontrado aparece com:
- 🔴 CRITICAL ou 🟠 HIGH
- Score CVSS (0–10)
- Explicação em português pelo Gemini
- Software afetado e recomendação de ação
- Links de referência

---

## Histórico

O arquivo [`historico.csv`](./historico.csv) registra todos os CVEs encontrados com data, ID, score e severidade — útil para acompanhar tendências ao longo do tempo.

---

## Executar manualmente

Vá em **Actions → 🛡️ Sentinel SecOps — CVE Monitor → Run workflow**.

---

*Projeto de portfólio — automação de segurança com IA | by [Pedro](https://github.com/Pedroxious)*
