from fpdf import FPDF
import datetime
import os
import re

from db_manager import get_alerts, get_stats

def sanitize(text):
    """Remove emoji and non-latin1 characters for PDF compatibility."""
    if not text:
        return ''
    # Remove emojis and special unicode symbols
    cleaned = re.sub(r'[^\x00-\xff]', '', str(text))
    # Clean up extra whitespace
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return cleaned

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

class ShieldReport(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 22)
        self.set_text_color(0, 120, 200)
        self.cell(0, 12, 'CanaryShield', new_x="LMARGIN", new_y="NEXT", align='C')
        self.set_font('Helvetica', '', 11)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, 'Rapport Forensique - Detection Ransomware', new_x="LMARGIN", new_y="NEXT", align='C')
        self.line(10, 32, 200, 32)
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} | Genere le {datetime.datetime.now().strftime("%d/%m/%Y %H:%M")}', align='C')

def generate_report():
    os.makedirs(REPORTS_DIR, exist_ok=True)

    alerts = get_alerts(limit=100)
    stats = get_stats()

    pdf = ShieldReport()
    pdf.alias_nb_pages()
    pdf.add_page()

    # --- Summary Section ---
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, '1. Resume', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font('Helvetica', '', 11)
    pdf.set_text_color(50, 50, 50)

    summary_data = [
        ('Date du rapport', datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")),
        ('Total alertes enregistrees', str(stats['total_alerts'])),
        ('Alertes aujourd\'hui', str(stats['today_alerts'])),
        ('Fichiers uniques touches', str(stats['unique_files_hit'])),
        ('Seuil d\'entropie', '7.5 / 8.0'),
        ('Methode de detection', 'Entropie de Shannon + Surveillance Canari'),
    ]

    for label, value in summary_data:
        pdf.set_font('Helvetica', 'B', 10)
        pdf.cell(80, 7, label, border=0)
        pdf.set_font('Helvetica', '', 10)
        pdf.cell(0, 7, value, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    # --- Alerts Table ---
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, '2. Historique des Alertes', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    if not alerts:
        pdf.set_font('Helvetica', 'I', 11)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, 'Aucune alerte enregistree.', new_x="LMARGIN", new_y="NEXT")
    else:
        # Table header
        pdf.set_fill_color(0, 100, 180)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 9)
        col_widths = [35, 55, 22, 78]
        headers = ['Date/Heure', 'Fichier', 'Entropie', 'Action']
        for i, h in enumerate(headers):
            pdf.cell(col_widths[i], 8, h, border=1, fill=True, align='C')
        pdf.ln()

        # Table rows
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(40, 40, 40)
        fill = False
        for alert in alerts[:30]:  # Max 30 rows
            if fill:
                pdf.set_fill_color(240, 245, 250)
            else:
                pdf.set_fill_color(255, 255, 255)

            pdf.cell(col_widths[0], 7, sanitize(alert['timestamp']), border=1, fill=True, align='C')
            pdf.cell(col_widths[1], 7, sanitize(alert['filename'])[:25], border=1, fill=True)

            # Color entropy red if above threshold
            ent = alert['entropy']
            if ent > 7.5:
                pdf.set_text_color(200, 0, 0)
            pdf.cell(col_widths[2], 7, f"{ent:.2f}", border=1, fill=True, align='C')
            pdf.set_text_color(40, 40, 40)

            action = sanitize(alert.get('action_taken') or '')[:40]
            pdf.cell(col_widths[3], 7, action, border=1, fill=True)
            pdf.ln()
            fill = not fill

    pdf.ln(6)

    # --- Methodology Section ---
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, '3. Methodologie de Detection', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(50, 50, 50)
    methodology = [
        "1. Des fichiers leurres (canaris) sont deployes dans des repertoires surveilles.",
        "2. Le systeme surveille en temps reel les modifications via la librairie Watchdog.",
        "3. A chaque modification, l'entropie de Shannon du fichier est recalculee.",
        "4. Si l'entropie depasse le seuil de 7.5/8.0, une alerte critique est declenchee.",
        "5. Le processus malveillant est identifie via psutil et automatiquement arrete.",
        "6. Une alarme sonore se declenche et l'evenement est enregistre en base de donnees.",
        "7. Les fichiers peuvent etre restaures depuis la sauvegarde automatique.",
    ]
    for line in methodology:
        pdf.cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")

    # Save
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"rapport_forensique_{ts}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    pdf.output(filepath)

    return filepath, filename
