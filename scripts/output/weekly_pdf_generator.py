import os
import csv
import pandas as pd
from datetime import datetime, timezone, timedelta
from fpdf import FPDF

class WeeklyPDF(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font("helvetica", "B", 10)
            self.set_text_color(100, 100, 100)
            self.cell(0, 10, "Sentinel SecOps - Relatório Executivo Semanal", border=False, ln=False, align="L")
            self.cell(0, 10, "CONFIDENCIAL — USO INTERNO", border=False, ln=True, align="R")
            self.line(10, 18, 200, 18)
            self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

def generate_weekly_report():
    csv_path = os.path.join("dashboards", "historico.csv")
    os.makedirs(os.path.join("reports", "weekly"), exist_ok=True)
    
    if not os.path.exists(csv_path):
        print(f"CSV file not found at {csv_path}. Cannot generate weekly report.")
        return None
        
    try:
        df = pd.read_csv(csv_path, dtype=str)
        # Parse dates
        df["parsed_date"] = pd.to_datetime(df["data"], format="%Y-%m-%d", errors="coerce")
        df = df.dropna(subset=["parsed_date"])
        
        # Current time context
        today = datetime.now(timezone.utc).date()
        start_date = today - timedelta(days=7)
        prev_start_date = today - timedelta(days=14)
        
        # Filter data
        this_week_df = df[(df["parsed_date"].dt.date >= start_date) & (df["parsed_date"].dt.date < today)].copy()
        prev_week_df = df[(df["parsed_date"].dt.date >= prev_start_date) & (df["parsed_date"].dt.date < start_date)].copy()
        
        total_this = len(this_week_df)
        total_prev = len(prev_week_df)
        delta = total_this - total_prev
        delta_str = f"+{delta}" if delta >= 0 else f"{delta}"
        
        # Severity Distribution
        this_week_df["priority_score_f"] = pd.to_numeric(this_week_df["priority_score"], errors="coerce").fillna(0.0)
        
        critical_count = len(this_week_df[this_week_df["priority_score_f"] >= 9.0])
        high_count = len(this_week_df[(this_week_df["priority_score_f"] >= 7.0) & (this_week_df["priority_score_f"] < 9.0)])
        medium_count = len(this_week_df[(this_week_df["priority_score_f"] >= 5.0) & (this_week_df["priority_score_f"] < 7.0)])
        low_count = len(this_week_df[this_week_df["priority_score_f"] < 5.0])
        
        # Ransomware percentage
        # Check column ransomware_known or in_cisa_kev
        ransomware_count = 0
        if "ransomware_known" in this_week_df.columns:
            # Let's count how many have 'sim' or 'true' or True
            ransomware_count = len(this_week_df[this_week_df["ransomware_known"].str.lower().isin(["sim", "true", "yes", "1"])])
        ransomware_pct = (ransomware_count / total_this * 100) if total_this > 0 else 0.0
        
        # Exploit DB percentage
        exploit_count = 0
        if "exploitdb_has_exploit" in this_week_df.columns:
            exploit_count = len(this_week_df[this_week_df["exploitdb_has_exploit"].str.lower().isin(["sim", "true", "yes", "1"])])
        exploit_pct = (exploit_count / total_this * 100) if total_this > 0 else 0.0
        
        # Top 10 Threat List
        top_10 = this_week_df.sort_values(by="priority_score_f", ascending=False).head(10)
        
        # Escalated CVEs (score_trend = UP)
        escalated = []
        if "score_trend" in this_week_df.columns:
            escalated = this_week_df[this_week_df["score_trend"] == "UP"]
        
        # Start PDF generation
        pdf = WeeklyPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # PAGE 1 - Cover page
        pdf.set_font("helvetica", "B", 24)
        pdf.set_text_color(15, 23, 42) # Slate-900
        pdf.cell(0, 40, "Sentinel SecOps", ln=True, align="C")
        
        pdf.set_font("helvetica", "B", 18)
        pdf.set_text_color(51, 65, 85) # Slate-700
        pdf.cell(0, 10, "Relatório Executivo Semanal", ln=True, align="C")
        pdf.ln(5)
        
        pdf.set_font("helvetica", "", 12)
        pdf.cell(0, 10, f"Período: {start_date.strftime('%d/%m/%Y')} a {today.strftime('%d/%m/%Y')}", ln=True, align="C")
        pdf.ln(10)
        
        # Cover image
        header_image = os.path.join("assets", "dashboard_header.png")
        if os.path.exists(header_image):
            pdf.image(header_image, x=15, w=180, h=60)
            pdf.ln(65)
        else:
            pdf.ln(60)
            
        pdf.set_font("helvetica", "B", 10)
        pdf.set_text_color(220, 38, 38) # Red-600
        pdf.cell(0, 10, "CLASSIFICAÇÃO: CONFIDENCIAL — USO INTERNO", ln=True, align="C")
        
        # PAGE 2 - Sumário Executivo
        pdf.add_page()
        pdf.set_font("helvetica", "B", 16)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 10, "Sumário Executivo", ln=True)
        pdf.ln(5)
        
        pdf.set_font("helvetica", "", 11)
        pdf.set_text_color(51, 65, 85)
        summary_intro = (
            f"Durante a semana de {start_date.strftime('%d/%m/%Y')} a {today.strftime('%d/%m/%Y')}, o sistema "
            f"autônomo monitorou e analisou um total de {total_this} vulnerabilidades críticas ou de alta severidade. "
            f"Isso representa uma variação de {delta_str} em comparação com a semana anterior, na qual foram registradas "
            f"{total_prev} vulnerabilidades."
        )
        pdf.multi_cell(0, 6, summary_intro)
        pdf.ln(10)
        
        # Table of metrics
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 8, "Métricas de Severidade e Ameaça", ln=True)
        
        pdf.set_font("helvetica", "B", 10)
        pdf.set_fill_color(241, 245, 249)
        pdf.cell(90, 8, "Métrica / Categoria", border=1, fill=True)
        pdf.cell(50, 8, "Quantidade", border=1, fill=True, align="C")
        pdf.cell(50, 8, "Percentual", border=1, fill=True, align="C")
        pdf.ln()
        
        pdf.set_font("helvetica", "", 10)
        
        categories = [
            ("Crítica (Score >= 9.0)", critical_count, f"{(critical_count/total_this*100):.1f}%" if total_this > 0 else "0%"),
            ("Alta (7.0 <= Score < 8.9)", high_count, f"{(high_count/total_this*100):.1f}%" if total_this > 0 else "0%"),
            ("Média (5.0 <= Score < 6.9)", medium_count, f"{(medium_count/total_this*100):.1f}%" if total_this > 0 else "0%"),
            ("Baixa (Score < 5.0)", low_count, f"{(low_count/total_this*100):.1f}%" if total_this > 0 else "0%"),
            ("Associada a Ransomware", ransomware_count, f"{ransomware_pct:.1f}%"),
            ("Com Exploit Público (Exploit-DB)", exploit_count, f"{exploit_pct:.1f}%")
        ]
        
        for name, count, pct in categories:
            pdf.cell(90, 8, name, border=1)
            pdf.cell(50, 8, str(count), border=1, align="C")
            pdf.cell(50, 8, pct, border=1, align="C")
            pdf.ln()
            
        pdf.ln(10)
        
        # PAGE 3+ - Top 10 Ameaças
        pdf.add_page()
        pdf.set_font("helvetica", "B", 16)
        pdf.cell(0, 10, "Top 10 Ameaças da Semana", ln=True)
        pdf.ln(5)
        
        if top_10.empty:
            pdf.set_font("helvetica", "I", 11)
            pdf.cell(0, 10, "Nenhuma vulnerabilidade registrada para exibição.", ln=True)
        else:
            for idx, (_, row) in enumerate(top_10.iterrows(), 1):
                pdf.set_font("helvetica", "B", 11)
                pdf.set_text_color(220, 38, 38) if float(row.get("priority_score_f", 0.0)) >= 9.0 else pdf.set_text_color(15, 23, 42)
                pdf.cell(0, 8, f"{idx}. {row['cve_id']} - {row.get('software', 'N/A')} (Score: {float(row.get('priority_score', 0.0)):.1f})", ln=True)
                
                pdf.set_font("helvetica", "", 9)
                pdf.set_text_color(71, 85, 105)
                
                exploit_db_status = "Sim" if str(row.get("exploitdb_has_exploit")).lower() in ["sim", "true", "1", "yes"] else "Não"
                ransom_status = "Sim" if str(row.get("ransomware_known")).lower() in ["sim", "true", "1", "yes"] else "Não"
                
                meta_line = (
                    f"CVSS Original: {row['score']} ({row['severidade']}) | "
                    f"SLA: {row.get('sla_label', 'N/A')} | "
                    f"MITRE Tactic: {row.get('mitre_tactic', 'N/A')} | "
                    f"Exploit DB: {exploit_db_status} | "
                    f"Ransomware: {ransom_status}"
                )
                pdf.cell(0, 5, meta_line, ln=True)
                pdf.ln(1)
                
                pdf.set_font("helvetica", "", 10)
                pdf.set_text_color(51, 65, 85)
                # Resumo
                resumo_val = row.get("resumo", "Sem detalhes adicionais.")
                pdf.multi_cell(0, 5, resumo_val)
                pdf.ln(3)
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(3)
                
        # Last Page: CVEs que Escalaram de Risco
        pdf.add_page()
        pdf.set_font("helvetica", "B", 16)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 10, "CVEs que Escalaram de Risco", ln=True)
        pdf.ln(5)
        
        if len(escalated) == 0:
            pdf.set_font("helvetica", "I", 11)
            pdf.cell(0, 10, "Nenhuma vulnerabilidade registrou aumento de score de prioridade nesta semana.", ln=True)
        else:
            pdf.set_font("helvetica", "", 10)
            pdf.set_text_color(51, 65, 85)
            pdf.multi_cell(0, 6, "As seguintes vulnerabilidades tiveram sua prioridade de risco elevada durante a semana devido a novos vetores de ataque, iocs identificados ou campanhas de ransomware associadas:")
            pdf.ln(5)
            
            for _, row in escalated.iterrows():
                pdf.set_font("helvetica", "B", 11)
                pdf.set_text_color(220, 38, 38)
                pdf.cell(0, 8, f"{row['cve_id']} - {row.get('software', 'N/A')}", ln=True)
                
                pdf.set_font("helvetica", "", 9)
                pdf.set_text_color(71, 85, 105)
                delta_score_str = f"Score Anterior: {row.get('score_previous', 'N/A')} -> Novo Score: {row.get('score_current', row.get('priority_score', 'N/A'))}"
                pdf.cell(0, 5, delta_score_str, ln=True)
                pdf.ln(2)

        output_filename = f"reports/weekly/executive_report_{today.strftime('%Y')}-W{today.strftime('%V')}.pdf"
        pdf.output(output_filename)
        print(f"Weekly consolidated report generated successfully at {output_filename}")
        return output_filename
        
    except Exception as e:
        print(f"Error generating weekly executive report: {e}")
        return None

if __name__ == "__main__":
    generate_weekly_report()
