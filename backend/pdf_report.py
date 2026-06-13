"""
pdf_report.py v2 — Professional PDF report with charts
"""
import io
from datetime import datetime
from typing import Dict, List

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether, Flowable,
    )
    from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle
    from reportlab.graphics import renderPDF
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

# ── Colors ────────────────────────────────────────────────────────────────────
C_DARK   = colors.HexColor("#0A0E1A")
C_TEAL   = colors.HexColor("#0FF4C6")
C_TEAL2  = colors.HexColor("#0D6E7A")
C_RED    = colors.HexColor("#E63757")
C_AMBER  = colors.HexColor("#F0B429")
C_GREEN  = colors.HexColor("#22C55E")
C_BLUE   = colors.HexColor("#3B82F6")
C_GRAY   = colors.HexColor("#2C3E50")
C_LIGHT  = colors.HexColor("#F8FAFC")
C_MID    = colors.HexColor("#94A3B8")
C_BORDER = colors.HexColor("#E2E8F0")
C_WHITE  = colors.white

SEV_C = {"critical": C_RED, "high": C_AMBER, "medium": C_BLUE, "low": C_GREEN, "info": C_MID}
SEV_HEX = {"critical": "#E63757", "high": "#F0B429", "medium": "#3B82F6", "low": "#22C55E", "info": "#94A3B8"}

OWASP_NAMES = {
    "LLM01":"Prompt Injection","LLM02":"Insecure Output Handling",
    "LLM03":"Training Data Poisoning","LLM04":"Model Denial of Service",
    "LLM05":"Supply Chain Vulnerabilities","LLM06":"Sensitive Information Disclosure",
    "LLM07":"Insecure Plugin Design","LLM08":"Excessive Agency",
    "LLM09":"Overreliance","LLM10":"Model Theft",
}

RECOMMENDATIONS = {
    "violence":        "Implement output filtering for violent content. Consider adding a violence classifier as a guardrail before serving responses.",
    "hate_unfairness": "Add bias detection guardrails. Review training data and fine-tune with fairness-aware techniques.",
    "sexual":          "Enable Azure Content Filter sexual content policies at 'high' threshold. Add output classifiers.",
    "self_harm":       "Configure content filters for self-harm topics. Implement crisis detection and redirect flows.",
    "pii":             "Add PII detection to system prompt. Implement output scrubbing for personal data patterns.",
    "injection":       "Harden system prompt with explicit injection resistance instructions. Consider input validation layer.",
    "jailbreak":       "Strengthen system prompt boundaries. Implement jailbreak detection classifier at inference time.",
    "custom":          "Review custom attack vectors and implement targeted defenses based on specific findings.",
}

def _bar_chart(categories: Dict, width_pts: float = 400, height_pts: float = 140) -> Drawing:
    """Horizontal bar chart for category ASR."""
    d = Drawing(width_pts, height_pts)
    if not categories:
        return d
    items = sorted(categories.items(), key=lambda x: x[1].get("asr", 0), reverse=True)[:6]
    bar_h = min(18, (height_pts - 20) / max(len(items), 1))
    gap = 4
    label_w = 100
    bar_area = width_pts - label_w - 60
    for i, (cat, data) in enumerate(items):
        y = height_pts - 20 - i * (bar_h + gap)
        asr = data.get("asr", 0)
        failed = data.get("failed", 0)
        total = data.get("total", 0)
        bar_w = bar_area * min(asr / 100, 1)
        col = C_RED if asr > 20 else C_AMBER if asr > 5 else C_GREEN
        # Background bar
        d.add(Rect(label_w, y, bar_area, bar_h, fillColor=colors.HexColor("#F1F5F9"), strokeColor=None))
        # Value bar
        if bar_w > 0:
            d.add(Rect(label_w, y, bar_w, bar_h, fillColor=col, strokeColor=None))
        # Category label
        d.add(String(label_w - 4, y + bar_h/2 - 4, cat.replace("_"," ").title()[:14],
                     fontName="Helvetica", fontSize=8, fillColor=C_GRAY, textAnchor="end"))
        # ASR label
        d.add(String(label_w + bar_area + 4, y + bar_h/2 - 4, f"{asr}% ({failed}/{total})",
                     fontName="Helvetica-Bold", fontSize=8, fillColor=col))
    return d

def _severity_pie(sev_counts: Dict, size: float = 120) -> Drawing:
    """Donut-style severity breakdown."""
    d = Drawing(size * 2, size)
    labels = [k for k in ["critical","high","medium","low","info"] if sev_counts.get(k, 0) > 0]
    total = sum(sev_counts.get(k, 0) for k in labels)
    if total == 0:
        d.add(String(size, size/2, "No findings", fontName="Helvetica", fontSize=9, fillColor=C_MID, textAnchor="middle"))
        return d
    # Legend only (pie charts are complex in reportlab without extra libs)
    cx, cy, r = size * 0.4, size * 0.5, size * 0.35
    import math
    angle = 90
    for k in labels:
        v = sev_counts.get(k, 0)
        sweep = 360 * v / total
        col = SEV_C.get(k, C_MID)
        # Draw arc segment approximation with polygon
        steps = max(int(sweep / 10), 2)
        pts = [cx, cy]
        for s in range(steps + 1):
            a = math.radians(angle - s * sweep / steps)
            pts.extend([cx + r * math.cos(a), cy + r * math.sin(a)])
        from reportlab.graphics.shapes import Polygon
        d.add(Polygon(pts, fillColor=col, strokeColor=C_WHITE, strokeWidth=1))
        angle -= sweep
    # Center hole
    d.add(Circle(cx, cy, r * 0.5, fillColor=C_WHITE, strokeColor=None))
    d.add(String(cx, cy - 4, f"{total}", fontName="Helvetica-Bold", fontSize=11, fillColor=C_GRAY, textAnchor="middle"))
    # Legend
    lx, ly = size * 0.85, size * 0.9
    for k in labels:
        v = sev_counts.get(k, 0)
        col = SEV_C.get(k, C_MID)
        d.add(Rect(lx, ly, 10, 8, fillColor=col, strokeColor=None))
        d.add(String(lx + 13, ly, f"{k.title()}: {v}", fontName="Helvetica", fontSize=7.5, fillColor=C_GRAY))
        ly -= 14
    return d

def _owasp_grid(covered: List[str], width_pts: float = 400) -> Drawing:
    """OWASP Top 10 coverage grid."""
    all_ids = [f"LLM0{i}" if i < 10 else "LLM10" for i in range(1, 11)]
    cols, rows = 5, 2
    cell_w = width_pts / cols
    cell_h = 36
    d = Drawing(width_pts, rows * cell_h + 4)
    for i, oid in enumerate(all_ids):
        col_i = i % cols
        row_i = i // cols
        x = col_i * cell_w + 2
        y = (rows - 1 - row_i) * cell_h + 2
        hit = oid in covered
        bg = C_RED if hit else colors.HexColor("#F1F5F9")
        tc = C_WHITE if hit else C_MID
        d.add(Rect(x, y, cell_w - 4, cell_h - 4, fillColor=bg, strokeColor=C_BORDER, strokeWidth=0.5, rx=3, ry=3))
        d.add(String(x + (cell_w-4)/2, y + cell_h - 16, oid,
                     fontName="Helvetica-Bold", fontSize=8, fillColor=tc, textAnchor="middle"))
        name = OWASP_NAMES.get(oid, "")[:16]
        d.add(String(x + (cell_w-4)/2, y + 4, name,
                     fontName="Helvetica", fontSize=6, fillColor=tc, textAnchor="middle"))
    return d


class PageNumCanvas:
    """Canvas that adds header/footer to every page."""
    pass


def generate_pdf(scan: Dict, findings: List[Dict], scorecard: Dict) -> bytes:
    if not REPORTLAB_OK:
        raise ImportError("reportlab not installed")

    buf = io.BytesIO()
    W, H = A4  # 595 x 842 pts

    # Page number handler
    page_info = {"num": 0, "scan_name": scan.get("name", "")}

    def on_page(canvas, doc):
        page_info["num"] += 1
        canvas.saveState()
        # Top accent bar
        canvas.setFillColor(C_DARK)
        canvas.rect(0, H - 18*mm, W, 18*mm, fill=1, stroke=0)
        canvas.setFillColor(C_TEAL)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(20*mm, H - 12*mm, "PyRIT UI — AI Red Team Platform")
        canvas.setFillColor(C_MID)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(W - 20*mm, H - 12*mm, page_info["scan_name"][:50])
        # Bottom footer
        canvas.setFillColor(C_BORDER)
        canvas.rect(0, 0, W, 10*mm, fill=1, stroke=0)
        canvas.setFillColor(C_MID)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(20*mm, 3.5*mm, f"Generated by PyRIT UI · cibersecblog.com · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawRightString(W - 20*mm, 3.5*mm, f"Page {page_info['num']}")
        # Left accent line
        canvas.setFillColor(C_TEAL)
        canvas.rect(0, 10*mm, 3, H - 28*mm, fill=1, stroke=0)
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=22*mm, rightMargin=18*mm,
        topMargin=22*mm, bottomMargin=14*mm,
        onFirstPage=on_page, onLaterPages=on_page,
        title=f"PyRIT Red Team Report — {scan.get('name','')}")

    styles = getSampleStyleSheet()
    H1 = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=15, textColor=C_TEAL2, spaceBefore=8, spaceAfter=4)
    H2 = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11, textColor=C_GRAY, spaceBefore=6, spaceAfter=3)
    BODY = ParagraphStyle("body", fontName="Helvetica", fontSize=9, textColor=C_GRAY, spaceAfter=4, leading=14)
    MONO = ParagraphStyle("mono", fontName="Courier", fontSize=8, textColor=C_GRAY, spaceAfter=3, leading=12)
    CAPTION = ParagraphStyle("cap", fontName="Helvetica", fontSize=7.5, textColor=C_MID, spaceAfter=6)

    story = []

    # ══ COVER ══════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 8*mm))

    # Title — drawn directly on canvas via a simple table, no nested Paragraphs
    story.append(Table([[
        Paragraph('<b>Red Team Assessment Report</b>', ParagraphStyle("ct", fontName="Helvetica-Bold", fontSize=20, textColor=colors.HexColor("#0A0E1A"), leading=26)),
        Paragraph(scan.get("name",""), ParagraphStyle("cs", fontName="Helvetica", fontSize=10, textColor=C_TEAL2, leading=14)),
    ]], colWidths=[115*mm, 53*mm],
    style=TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#F0FDFA")),
        ("TOPPADDING", (0,0), (-1,-1), 12), ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("LEFTPADDING", (0,0), (-1,-1), 12), ("RIGHTPADDING", (-1,0), (-1,-1), 12),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LINEBELOW", (0,0), (-1,-1), 2, C_TEAL),
    ])))
    story.append(Spacer(1, 6*mm))

    # Meta + ASR side by side
    asr = scan.get("asr", 0.0)
    asr_col = "#E63757" if asr > 20 else "#F0B429" if asr > 5 else "#22C55E"
    sc = scorecard or {}
    sev = sc.get("severity_counts", {})

    meta_rows = [
        ["Date", scan.get("started_at","")[:10]],
        ["Target", scan.get("config",{}).get("endpoint","N/A")[:55]],
        ["Provider", f"{scan.get('config',{}).get('provider','N/A')} / {scan.get('config',{}).get('deployment','N/A')}"],
        ["Mode", "PyRIT Real" if scan.get("source")=="pyrit_real" else "Simulation"],
        ["Owner", scan.get("owner","N/A")],
        ["Total attacks", str(scan.get("total_attacks",0))],
    ]
    if scan.get("config",{}).get("attack_language") and scan["config"]["attack_language"] != "English":
        meta_rows.append(["Attack language", scan["config"]["attack_language"]])
    if scan.get("config",{}).get("application_scenario"):
        scenario = scan["config"]["application_scenario"][:80] + ("..." if len(scan["config"]["application_scenario"]) > 80 else "")
        meta_rows.append(["App scenario", scenario])
    meta_table = Table(meta_rows, colWidths=[28*mm, 72*mm],
        style=TableStyle([
            ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
            ("FONTSIZE", (0,0), (-1,-1), 8.5),
            ("TEXTCOLOR", (0,0), (0,-1), C_MID),
            ("TEXTCOLOR", (1,0), (1,-1), C_GRAY),
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_LIGHT, C_WHITE]),
            ("GRID", (0,0), (-1,-1), 0.4, C_BORDER),
        ]))

    asr_block = Table([[
        Paragraph(f'<b>{asr}%</b>', ParagraphStyle("asrv", fontName="Helvetica-Bold", fontSize=30, textColor=colors.HexColor(asr_col), leading=36)),
        Paragraph(
            f'<b>Attack Success Rate</b><br/>'
            f'<font size="8" color="#94A3B8">{sc.get("successful_attacks",0)} of {sc.get("total_attacks",0)} attacks succeeded</font><br/><br/>'
            f'<font size="8" color="#E63757">Critical: {sev.get("critical",0)}</font>   '
            f'<font size="8" color="#F0B429">High: {sev.get("high",0)}</font>   '
            f'<font size="8" color="#3B82F6">Medium: {sev.get("medium",0)}</font>',
            ParagraphStyle("asrd", fontName="Helvetica", fontSize=9, textColor=C_GRAY, leading=14)),
    ]], colWidths=[25*mm, 41*mm],
    style=TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_LIGHT),
        ("TOPPADDING", (0,0), (-1,-1), 10), ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("BOX", (0,0), (-1,-1), 1.5, colors.HexColor(asr_col)),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))

    story.append(Table([[meta_table, asr_block]], colWidths=[105*mm, 68*mm],
        style=TableStyle([("VALIGN",(0,0),(-1,-1),"TOP"), ("LEFTPADDING",(1,0),(1,-1),8)])))

    story.append(PageBreak())

    # ══ SECTION 1 — EXECUTIVE SUMMARY ══════════════════════════════════════════
    story.append(Paragraph("1. Executive Summary", H1))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_TEAL, spaceAfter=6))

    # Severity table
    sev_data = [
        ["Severity", "Count", "Risk Level", "Action Required"],
        ["CRITICAL", str(sev.get("critical",0)), "Immediate", "Remediate within 24 hours"],
        ["HIGH",     str(sev.get("high",0)),     "Serious",   "Remediate within 7 days"],
        ["MEDIUM",   str(sev.get("medium",0)),   "Moderate",  "Remediate within 30 days"],
        ["LOW",      str(sev.get("low",0)),       "Minor",     "Monitor and review"],
        ["INFO/PASS",str(sev.get("info",0)),      "None",      "Model defended successfully"],
    ]
    sev_colors_list = [C_RED, C_RED, C_AMBER, C_BLUE, C_GREEN, C_MID]
    story.append(Table(sev_data, colWidths=[28*mm, 20*mm, 28*mm, 92*mm],
        style=TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_DARK),
            ("TEXTCOLOR", (0,0), (-1,0), C_WHITE),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 9),
            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("LEFTPADDING",(0,0),(-1,-1),7),
            ("GRID",(0,0),(-1,-1),0.4,C_BORDER),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LIGHT,C_WHITE]),
        ] + [("TEXTCOLOR",(0,i+1),(1,i+1), sev_colors_list[i+1]) for i in range(5)]
          + [("FONTNAME",(0,1),(0,-1),"Helvetica-Bold")])))
    story.append(Spacer(1, 5*mm))

    # OWASP coverage
    story.append(Paragraph("OWASP LLM Top 10 Coverage", H2))
    owasp_cov = sc.get("owasp_coverage", [])
    story.append(_owasp_grid(owasp_cov, width_pts=168*mm))
    story.append(Paragraph(
        f'<font color="#94A3B8">{len(owasp_cov)}/10 OWASP LLM Top 10 categories tested in this assessment. '
        f'Red = tested, Gray = not covered.</font>', CAPTION))

    story.append(PageBreak())

    # ══ SECTION 2 — RESULTS BY CATEGORY ═══════════════════════════════════════
    story.append(Paragraph("2. Results by Category", H1))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_TEAL, spaceAfter=6))

    by_cat = sc.get("by_category", {})
    if by_cat:
        story.append(Paragraph("Attack Success Rate by Category", H2))
        story.append(_bar_chart(by_cat, width_pts=168*mm, height_pts=min(30*len(by_cat)+20, 150)))
        story.append(Spacer(1, 4*mm))

        cat_data = [["Category", "Total", "Failed", "ASR", "OWASP ID", "MITRE ID", "Severity"]]
        for cat, d in sorted(by_cat.items(), key=lambda x: x[1].get("asr",0), reverse=True):
            cat_data.append([
                cat.replace("_"," ").title(),
                str(d.get("total",0)), str(d.get("failed",0)),
                f'{d.get("asr",0)}%',
                d.get("owasp",{}).get("id",""),
                d.get("mitre",{}).get("id",""),
                d.get("severity","").upper(),
            ])
        asr_text_colors = []
        for i, (_, d) in enumerate(sorted(by_cat.items(), key=lambda x: x[1].get("asr",0), reverse=True), 1):
            a = d.get("asr",0)
            c = C_RED if a > 20 else C_AMBER if a > 5 else C_GREEN
            asr_text_colors.append(("TEXTCOLOR",(3,i),(3,i),c))

        story.append(Table(cat_data, colWidths=[33*mm,17*mm,17*mm,15*mm,22*mm,30*mm,22*mm],
            style=TableStyle([
                ("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8.5),
                ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
                ("LEFTPADDING",(0,0),(-1,-1),6),
                ("GRID",(0,0),(-1,-1),0.4,C_BORDER),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LIGHT,C_WHITE]),
                ("FONTNAME",(3,1),(3,-1),"Helvetica-Bold"),
            ] + asr_text_colors)))
    else:
        story.append(Paragraph("No category data available.", BODY))

    story.append(PageBreak())

    # ══ SECTION 3 — DETAILED FINDINGS ══════════════════════════════════════════
    story.append(Paragraph("3. Detailed Findings", H1))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_TEAL, spaceAfter=6))

    failed = [f for f in findings if f.get("result")=="FAIL"]
    passed = [f for f in findings if f.get("result")=="PASS"]

    if not failed:
        story.append(Table([[
            Paragraph('<font color="#22C55E" size="14"><b>✓</b></font>', styles["Normal"]),
            Paragraph('<b>No successful attacks detected</b><br/>'
                      '<font color="#94A3B8" size="8">The model successfully defended against all attack prompts in this assessment. '
                      'This indicates effective safety measures are in place.</font>', BODY),
        ]], colWidths=[12*mm, 156*mm],
        style=TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F0FDF4")),
            ("TOPPADDING",(0,0),(-1,-1),10),("BOTTOMPADDING",(0,0),(-1,-1),10),
            ("LEFTPADDING",(0,0),(-1,-1),10),
            ("BOX",(0,0),(-1,-1),1,C_GREEN),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ])))
        story.append(Spacer(1, 5*mm))

        # Show summary of passed attacks
        if passed:
            story.append(Paragraph("Defended Attacks Summary", H2))
            pass_data = [["Category", "Strategy", "Prompt (truncated)", "OWASP", "Reason"]]
            for f in passed[:10]:
                owasp_id = f.get("owasp",{}).get("id","") if isinstance(f.get("owasp"),dict) else f.get("owasp_id","")
                pass_data.append([
                    f.get("category","").replace("_"," ").title(),
                    f.get("strategy",""),
                    str(f.get("prompt",""))[:55] + "...",
                    owasp_id,
                    f.get("reason","Defended")[:30],
                ])
            story.append(Table(pass_data, colWidths=[28*mm,22*mm,72*mm,22*mm,26*mm],
                style=TableStyle([
                    ("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
                    ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                    ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
                    ("LEFTPADDING",(0,0),(-1,-1),6),
                    ("GRID",(0,0),(-1,-1),0.4,C_BORDER),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LIGHT,C_WHITE]),
                ])))
    else:
        for i, f in enumerate(failed, 1):
            sev = f.get("severity","info")
            sev_col = SEV_C.get(sev, C_MID)
            sev_hex = SEV_HEX.get(sev, "#94A3B8")
            owasp = f.get("owasp",{}) if isinstance(f.get("owasp"),dict) else {"id":f.get("owasp_id",""),"name":f.get("owasp_name","")}
            mitre = f.get("mitre",{}) if isinstance(f.get("mitre"),dict) else {"id":f.get("mitre_id",""),"name":f.get("mitre_name","")}

            score_txt = f"Score: {f.get('score')}/7  " if f.get('score') is not None else ""
            reason_txt = f"  Reason: {f.get('reason','')}" if f.get('reason') else ""
            complexity_txt = f"  Complexity: {f.get('complexity','')}" if f.get('complexity') else ""

            # Creamos todas las tablas antes de pasarlas al KeepTogether
            story.append(KeepTogether([
                # Finding header
                Table([[
                    Paragraph(f'<font size="9" color="white"><b> {sev.upper()} </b></font>', styles["Normal"]),
                    Paragraph(f'<font size="9" color="white"><b>Finding #{i} — {f.get("category","").replace("_"," ").title()} · {f.get("strategy","")}</b></font>', styles["Normal"]),
                    Paragraph(f'<font size="8" color="#94A3B8">{owasp.get("id","")} · {mitre.get("id","")}</font>', styles["Normal"]),
                ]], colWidths=[22*mm, 100*mm, 46*mm],
                style=TableStyle([
                    ("BACKGROUND",(0,0),(0,-1),sev_col),
                    ("BACKGROUND",(1,0),(-1,-1),C_DARK),
                    ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
                    ("LEFTPADDING",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                ])),
                # Prompt
                Table([[Paragraph(
                    f'<font size="7.5" color="#64748B"><b>ATTACK PROMPT</b></font><br/>'
                    f'<font size="8" color="#1C2833">{str(f.get("prompt",""))[:500]}</font>', BODY
                )]], colWidths=[168*mm],
                style=TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#FFFBEB")),
                    ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
                    ("LEFTPADDING",(0,0),(-1,-1),8),
                    ("LINEBELOW",(0,0),(-1,-1),0.5,C_AMBER),
                ])),
                # Response
                Table([[Paragraph(
                    f'<font size="7.5" color="#64748B"><b>MODEL RESPONSE</b></font><br/>'
                    f'<font size="8" color="#1C2833">{str(f.get("response",""))[:500]}</font>', BODY
                )]], colWidths=[168*mm],
                style=TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#FFF1F2")),
                    ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
                    ("LEFTPADDING",(0,0),(-1,-1),8),
                    ("LINEBELOW",(0,0),(-1,-1),0.5,C_RED),
                ])),
                # Score & Meta (esta es la tabla que estaba provocando el error)
                Table([[Paragraph(
                    f'<font size="7.5" color="#0D6E7A"><b>OWASP:</b></font> <font size="7.5">{owasp.get("id","")} — {owasp.get("name","")}</font>  '
                    f'<font size="7.5" color="#0D6E7A"><b>MITRE:</b></font> <font size="7.5">{mitre.get("id","")} — {mitre.get("name","")}</font><br/>'
                    f'<font size="7.5" color="#94A3B8">{score_txt}{complexity_txt}{reason_txt}</font>', BODY
                )]], colWidths=[168*mm],
                style=TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F0FDFA")),
                    ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
                    ("LEFTPADDING",(0,0),(-1,-1),8),
                    ("BOX",(0,0),(-1,-1),0.5,C_TEAL),
                ])),
                Spacer(1, 4*mm)
            ]))

    # ══ SECTION 4 — RECOMMENDATIONS ════════════════════════════════════════════
    story.append(PageBreak())
    story.append(Paragraph("4. Recommendations", H1))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_TEAL, spaceAfter=6))

    cats_tested = list(by_cat.keys()) if by_cat else []
    if cats_tested:
        for cat in cats_tested:
            d = by_cat.get(cat, {})
            rec = RECOMMENDATIONS.get(cat, "Review findings and implement appropriate guardrails.")
            asr_val = d.get("asr", 0)
            status = "⚠ FAILED" if d.get("failed",0) > 0 else "✓ DEFENDED"
            status_col = "#E63757" if d.get("failed",0) > 0 else "#22C55E"
            story.append(KeepTogether([
                Table([[
                    Paragraph(f'<font size="9" color="{status_col}"><b>{status}</b></font>', styles["Normal"]),
                    Paragraph(f'<font size="9" color="#2C3E50"><b>{cat.replace("_"," ").title()}</b></font> '
                              f'<font size="8" color="#94A3B8">ASR: {asr_val}%</font>', styles["Normal"]),
                ]], colWidths=[28*mm, 140*mm],
                style=TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1),C_LIGHT),
                    ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
                    ("LEFTPADDING",(0,0),(-1,-1),8),
                    ("LINEBELOW",(0,0),(-1,-1),1,C_TEAL2),
                ])),
                Table([[Paragraph(rec, BODY)]], colWidths=[168*mm],
                style=TableStyle([
                    ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
                    ("LEFTPADDING",(0,0),(-1,-1),8),
                ])),
                Spacer(1, 3*mm),
            ]))
    else:
        story.append(Paragraph("No specific recommendations — no categories were tested.", BODY))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()