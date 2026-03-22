"""
PDF Report Generator for Fuzzi scan results.
"""
import io
import logging
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

logger = logging.getLogger(__name__)

RISK_COLORS = {
    "LOW": colors.HexColor("#22c55e"),
    "MEDIUM": colors.HexColor("#f59e0b"),
    "HIGH": colors.HexColor("#ef4444"),
    "CRITICAL": colors.HexColor("#7c3aed"),
}

SEVERITY_COLORS = {
    "info": colors.HexColor("#3b82f6"),
    "low": colors.HexColor("#22c55e"),
    "medium": colors.HexColor("#f59e0b"),
    "high": colors.HexColor("#ef4444"),
    "critical": colors.HexColor("#7c3aed"),
}


def build_pdf_report(scan_data: dict, fuzzy_data: dict, recommendations: list) -> bytes:
    """
    Generate a PDF report and return raw bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Title"], fontSize=22, textColor=colors.HexColor("#1e293b"), spaceAfter=6)
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, textColor=colors.HexColor("#334155"), spaceBefore=12, spaceAfter=4)
    body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=14)
    small_style = ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, textColor=colors.grey)

    story = []

    # ---- Header ----
    story.append(Paragraph("FUZZI", ParagraphStyle("Brand", parent=styles["Title"], fontSize=28,
                                                    textColor=colors.HexColor("#6366f1"), alignment=TA_CENTER)))
    story.append(Paragraph("Web Security Audit Report", ParagraphStyle("Sub", parent=styles["Normal"],
                                                                        fontSize=14, alignment=TA_CENTER,
                                                                        textColor=colors.HexColor("#64748b"))))
    story.append(Spacer(1, 0.4*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#6366f1")))
    story.append(Spacer(1, 0.4*cm))

    # ---- Scan metadata ----
    risk_level = fuzzy_data.get("risk_level", "UNKNOWN")
    risk_color = RISK_COLORS.get(risk_level, colors.grey)
    risk_score = fuzzy_data.get("risk_score", 0)

    meta_data = [
        ["Target URL", scan_data.get("target_url", "N/A")],
        ["Scan ID", str(scan_data.get("id", "N/A"))],
        ["Scan Date", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Status", scan_data.get("status", "N/A").upper()],
        ["Risk Score", f"{risk_score:.2f} / 1.00"],
        ["Risk Level", risk_level],
    ]
    meta_table = Table(meta_data, colWidths=[4*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TEXTCOLOR", (1, 5), (1, 5), risk_color),
        ("FONTNAME", (1, 5), (1, 5), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5*cm))

    # ---- Risk summary ----
    story.append(Paragraph("Risk Assessment Summary", h2_style))
    story.append(Paragraph(
        f"The fuzzy logic engine assessed <b>{scan_data.get('target_url', '')}</b> and assigned a "
        f"risk score of <b>{risk_score:.2f}</b> with a risk level of "
        f"<font color='#{_color_hex(risk_color)}'><b>{risk_level}</b></font>. "
        f"Confidence: {fuzzy_data.get('confidence', 0)*100:.1f}%.",
        body_style
    ))
    story.append(Spacer(1, 0.3*cm))

    # ---- Factor scores ----
    story.append(Paragraph("Security Factor Scores", h2_style))
    fuzzy_inputs = fuzzy_data.get("fuzzy_inputs", {})
    memberships = fuzzy_data.get("fuzzy_memberships", {})
    factor_rows = [["Factor", "Raw Score", "LOW", "MEDIUM", "HIGH", "Dominant Level"]]
    for factor, score in fuzzy_inputs.items():
        m = memberships.get(factor, {})
        dominant = max(m, key=m.get) if m else "N/A"
        factor_rows.append([
            factor.replace("_", " ").title(),
            f"{score:.2f}",
            f"{m.get('LOW', 0):.2f}",
            f"{m.get('MEDIUM', 0):.2f}",
            f"{m.get('HIGH', 0):.2f}",
            dominant,
        ])
    factor_table = Table(factor_rows, colWidths=[4.5*cm, 2*cm, 2*cm, 2*cm, 2*cm, 3*cm])
    factor_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(factor_table)
    story.append(Spacer(1, 0.5*cm))

    # ---- Triggered rules ----
    triggered = fuzzy_data.get("triggered_rules", [])
    story.append(Paragraph(f"Triggered Rules ({len(triggered)})", h2_style))
    if triggered:
        rule_rows = [["Rule ID", "Description", "Consequent", "Strength"]]
        for r in triggered:
            rule_rows.append([
                r["rule_id"],
                r["description"],
                r["consequent"],
                f"{r['firing_strength']:.3f}",
            ])
        rule_table = Table(rule_rows, colWidths=[1.5*cm, 9*cm, 2.5*cm, 2.5*cm])
        rule_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(rule_table)
    else:
        story.append(Paragraph("No rules triggered.", body_style))
    story.append(Spacer(1, 0.5*cm))

    # ---- Recommendations ----
    story.append(Paragraph(f"Recommendations ({len(recommendations)})", h2_style))
    for rec in recommendations:
        sev = rec.get("severity", "info")
        sev_color = SEVERITY_COLORS.get(sev, colors.grey)
        rec_block = [
            Paragraph(f"[{sev.upper()}] {rec.get('title', '')}", ParagraphStyle(
                "RecTitle", parent=styles["Normal"], fontSize=10,
                fontName="Helvetica-Bold", textColor=sev_color,
            )),
            Paragraph(rec.get("description", ""), body_style),
            Paragraph(f"<b>Remediation:</b> {rec.get('remediation', '')}", body_style),
            Spacer(1, 0.2*cm),
        ]
        story.append(KeepTogether(rec_block))

    # ---- Footer ----
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Paragraph(
        f"Generated by Fuzzi Security Platform · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7,
                       textColor=colors.grey, alignment=TA_CENTER)
    ))

    doc.build(story)
    return buffer.getvalue()


def _color_hex(color) -> str:
    try:
        r = int(color.red * 255)
        g = int(color.green * 255)
        b = int(color.blue * 255)
        return f"{r:02x}{g:02x}{b:02x}"
    except Exception:
        return "000000"
