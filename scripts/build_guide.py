"""Build the Spanish operator guide. Local files only; no scanning or network.

Usage: python scripts/build_guide.py
Dependencies: python -m pip install reportlab
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, CondPageBreak, Frame, PageBreak, PageTemplate, Paragraph, Preformatted,
    Spacer, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "GUIA_BBHunter.md"
OUTPUT = ROOT / "output" / "pdf" / "GUIA_BBHunter.pdf"
NAVY = colors.HexColor("#12263A")
TEAL = colors.HexColor("#087F8C")
INK = colors.HexColor("#243746")
MUTED = colors.HexColor("#536878")
PALE = colors.HexColor("#F1F6F8")
WIDTH, HEIGHT = A4
LEFT, RIGHT, TOP, BOTTOM = 21 * mm, 19 * mm, 23 * mm, 20 * mm
CONTENT_WIDTH = WIDTH - LEFT - RIGHT


def fonts():
    families = [
        (Path("C:/Windows/Fonts"), "arial.ttf", "arialbd.ttf", "ariali.ttf", "consola.ttf"),
        (Path("/usr/share/fonts/truetype/dejavu"), "DejaVuSans.ttf",
         "DejaVuSans-Bold.ttf", "DejaVuSans-Oblique.ttf", "DejaVuSansMono.ttf"),
        (Path("/usr/share/fonts/truetype/liberation2"), "LiberationSans-Regular.ttf",
         "LiberationSans-Bold.ttf", "LiberationSans-Italic.ttf", "LiberationMono-Regular.ttf"),
    ]
    for folder, regular, bold, italic, mono in families:
        if all((folder / name).exists() for name in (regular, bold, italic, mono)):
            for name, file in (("Guide", regular), ("GuideBold", bold),
                               ("GuideItalic", italic), ("GuideMono", mono)):
                pdfmetrics.registerFont(TTFont(name, str(folder / file)))
            pdfmetrics.registerFontFamily("Guide", normal="Guide", bold="GuideBold",
                                          italic="GuideItalic", boldItalic="GuideBold")
            return "Guide", "GuideBold", "GuideMono"
    return "Helvetica", "Helvetica-Bold", "Courier"


REGULAR, BOLD, MONO = fonts()
styles = getSampleStyleSheet()
styles.add(ParagraphStyle("BodyGuide", fontName=REGULAR, fontSize=9.6, leading=14,
                         textColor=INK, spaceAfter=7, splitLongWords=True,
                         allowWidows=0, allowOrphans=0))
styles.add(ParagraphStyle("ChapterGuide", fontName=BOLD, fontSize=21, leading=26,
                         textColor=NAVY, spaceAfter=16, keepWithNext=True))
styles.add(ParagraphStyle("SubGuide", fontName=BOLD, fontSize=12, leading=16,
                         textColor=TEAL, spaceBefore=10, spaceAfter=7, keepWithNext=True))
styles.add(ParagraphStyle("MinorGuide", parent=styles["SubGuide"], fontSize=10,
                         leading=14, textColor=NAVY, spaceBefore=7))
styles.add(ParagraphStyle("BulletGuide", parent=styles["BodyGuide"], leftIndent=12,
                         firstLineIndent=-10, spaceAfter=5))
styles.add(ParagraphStyle("CalloutGuide", parent=styles["BodyGuide"], spaceAfter=0))
styles.add(ParagraphStyle("CodeGuide", fontName=MONO, fontSize=7.8, leading=10.4,
                         textColor=NAVY, backColor=PALE, borderColor=colors.HexColor("#D6E1E8"),
                         borderWidth=.4, borderPadding=8, spaceBefore=6, spaceAfter=13))
styles.add(ParagraphStyle("CellGuide", parent=styles["BodyGuide"], fontSize=8.2,
                         leading=11.5, spaceAfter=0))
styles.add(ParagraphStyle("CellHeaderGuide", parent=styles["CellGuide"],
                         fontName=BOLD, textColor=colors.white))
styles.add(ParagraphStyle("ContentsGuide", fontName=REGULAR, fontSize=10,
                         leading=14, textColor=INK, leftIndent=0, firstLineIndent=0,
                         spaceBefore=0, spaceAfter=0))
styles.add(ParagraphStyle("ContentsHeading", parent=styles["ChapterGuide"]))
styles.add(ParagraphStyle("TableHeading", parent=styles["SubGuide"], keepWithNext=False))


class CodeBlock(Preformatted):
    def split(self, availWidth, availHeight):
        # Every example is shorter than one page; keep commands copyable together.
        return []

    def draw(self):
        self.canv.saveState()
        self.canv.setFillColor(PALE)
        self.canv.setStrokeColor(colors.HexColor("#D6E1E8"))
        self.canv.setLineWidth(.4)
        self.canv.roundRect(-7, -6, self.width + 14, self.height + 12, 4, fill=1, stroke=1)
        self.canv.restoreState()
        super().draw()


def inline(value: str) -> str:
    value = escape(value)
    value = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)",
                   lambda m: f'<link href={quoteattr(m[2])} color="#087F8C">{m[1]}</link>', value)
    value = re.sub(r"`([^`]+)`", lambda m: f'<font name="{MONO}" size="8.4">{m[1]}</font>', value)
    value = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", value)
    return value


class GuideDoc(BaseDocTemplate):
    def __init__(self, filename):
        super().__init__(str(filename), pagesize=A4, leftMargin=LEFT, rightMargin=RIGHT,
                         topMargin=TOP, bottomMargin=BOTTOM, title="BBHunter | Guía práctica de bug bounty",
                         author="BBHunter", subject="Instalación, alcance, enumeración, validación e informe",
                         lang="es-ES")
        self.chapter_pages = {}
        frame = Frame(LEFT, BOTTOM, CONTENT_WIDTH, HEIGHT - TOP - BOTTOM,
                      leftPadding=0, bottomPadding=0, rightPadding=0, topPadding=0)
        self.addPageTemplates(PageTemplate(id="guide", frames=[frame], onPage=self.page_decor))

    def page_decor(self, canvas, doc):
        canvas.saveState()
        if doc.page == 1:
            canvas.setFillColor(NAVY)
            canvas.rect(0, HEIGHT - 66 * mm, WIDTH, 66 * mm, fill=1, stroke=0)
            canvas.setFillColor(TEAL)
            canvas.rect(0, HEIGHT - 68 * mm, WIDTH, 2 * mm, fill=1, stroke=0)
            canvas.setFillColor(colors.white)
            canvas.setFont(BOLD, 30)
            canvas.drawString(LEFT, HEIGHT - 36 * mm, "BBHunter")
            canvas.setFont(REGULAR, 11)
            canvas.drawString(LEFT, HEIGHT - 47 * mm, "MANUAL DE CAMPO / EDICIÓN 2026")
        else:
            canvas.setStrokeColor(colors.HexColor("#D6E1E8"))
            canvas.line(LEFT, HEIGHT - 15.5 * mm, WIDTH - RIGHT, HEIGHT - 15.5 * mm)
            canvas.setFont(BOLD, 8)
            canvas.setFillColor(TEAL)
            canvas.drawString(LEFT, HEIGHT - 12 * mm, "BBHUNTER / GUÍA PRÁCTICA")
            canvas.setFillColor(MUTED)
            canvas.setFont(REGULAR, 7.6)
            canvas.drawRightString(WIDTH - RIGHT, HEIGHT - 12 * mm, "24 NOV 2026")
        canvas.setStrokeColor(colors.HexColor("#D6E1E8"))
        canvas.line(LEFT, 15 * mm, WIDTH - RIGHT, 15 * mm)
        canvas.setFont(REGULAR, 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(LEFT, 10 * mm, "Programas autorizados | Evidencia verificable | Envío manual")
        canvas.drawRightString(WIDTH - RIGHT, 10 * mm, f"{doc.page}")
        canvas.restoreState()

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name == "ChapterGuide":
            title = flowable.getPlainText()
            key = "chapter-" + str(getattr(flowable, "chapter_index", 0))
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(title, key, level=0, closed=False)
            self.notify("TOCEntry", (0, title, self.page, key))
            self.chapter_pages[title] = self.page


def callout(markup: str) -> Table:
    """Recuadro destacado. Va en una tabla de una celda: su relleno ocupa espacio real
    en el flujo (borderPadding de un Paragraph se dibuja fuera y tapaba el texto vecino)."""
    box = Table([[Paragraph(markup, styles["CalloutGuide"])]], colWidths=[CONTENT_WIDTH],
                hAlign="LEFT", spaceBefore=8, spaceAfter=14)
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), .5, colors.HexColor("#C2DDE0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return box


def table(block):
    rows = [[part.strip() for part in line.strip().strip("|").split("|")] for line in block]
    rows = [row for row in rows if not all(re.fullmatch(r":?-+:?", col or " ") for col in row)]
    cols = len(rows[0])
    if any(len(row) != cols for row in rows):
        raise ValueError(f"Malformed table: {block}")
    if cols == 2:
        widths = [CONTENT_WIDTH * .35, CONTENT_WIDTH * .65]
    elif cols == 3:
        widths = [CONTENT_WIDTH * .25, CONTENT_WIDTH * .36, CONTENT_WIDTH * .39]
    else:
        widths = [CONTENT_WIDTH / cols] * cols
    cells = [[Paragraph(inline(col), styles["CellHeaderGuide" if i == 0 else "CellGuide"])
              for col in row] for i, row in enumerate(rows)]
    result = Table(cells, colWidths=widths, repeatRows=1, hAlign="LEFT", spaceBefore=5, spaceAfter=12)
    result.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, -1), (-1, -1), .4, colors.HexColor("#D6E1E8")),
    ]))
    return result


def content(markdown):
    lines = markdown.splitlines()
    story = []
    index, chapter_index = 0, 0
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if line.startswith("```"):
            code = []
            index += 1
            while index < len(lines) and not lines[index].startswith("```"):
                code.append(lines[index])
                index += 1
            if index == len(lines):
                raise ValueError("Unclosed code fence")
            if any(len(row.expandtabs(4)) > 108 for row in code):
                raise ValueError("Code line exceeds 108 columns: " + max(code, key=len))
            story.append(CodeBlock("\n".join(code), styles["CodeGuide"]))
            index += 1
            continue
        if line.startswith("| "):
            block = []
            while index < len(lines) and lines[index].startswith("|"):
                block.append(lines[index])
                index += 1
            story.append(table(block))
            continue
        if line.startswith("# "):
            chapter_index += 1
            if story:
                story.append(CondPageBreak(350))
                story.append(Spacer(1, 12))
            paragraph = Paragraph(inline(line[2:]), styles["ChapterGuide"])
            paragraph.chapter_index = chapter_index
            story.append(paragraph)
        elif line.startswith("## "):
            next_line = next((v for v in lines[index + 1:] if v.strip()), "")
            if next_line.startswith("| "):
                story.append(CondPageBreak(115))
                story.append(Paragraph(inline(line[3:]), styles["TableHeading"]))
            else:
                story.append(Paragraph(inline(line[3:]), styles["SubGuide"]))
        elif line.startswith("### "):
            story.append(Paragraph(inline(line[4:]), styles["MinorGuide"]))
        elif line.startswith("> "):
            quote = [line[2:]]
            while index + 1 < len(lines) and lines[index + 1].startswith("> "):
                index += 1
                quote.append(lines[index][2:])
            story.append(callout(inline(" ".join(quote))))
        elif re.match(r"^(?:- |\d+\. )", line):
            prefix, body = re.split(r" ", line, maxsplit=1)
            prefix = "•" if prefix == "-" else prefix
            story.append(Paragraph(inline(prefix + " " + body), styles["BulletGuide"]))
        else:
            paragraph = [line]
            while index + 1 < len(lines) and lines[index + 1].strip() and not re.match(
                    r"^(#|```|\||>|- |\d+\. )", lines[index + 1]):
                index += 1
                paragraph.append(lines[index])
            story.append(Paragraph(inline(" ".join(paragraph)), styles["BodyGuide"]))
        index += 1
    return story


def build():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    doc = GuideDoc(OUTPUT)
    cover_title = ParagraphStyle("CoverTitle", fontName=BOLD, fontSize=27, leading=34,
                                textColor=NAVY, spaceAfter=18)
    cover_sub = ParagraphStyle("CoverSub", parent=styles["BodyGuide"], fontSize=13, leading=20)
    story = [Spacer(1, 64 * mm),
             Paragraph("De la instalación<br/>al informe reproducible", cover_title),
             Paragraph("Una metodología paso a paso para investigar programas públicos de bug bounty "
                       "con alcance autorizado.", cover_sub), Spacer(1, 10 * mm),
             Paragraph("Instalación en Kali y WSL · Scope y URL · Enumeración · Burp, curl, "
                       "subfinder, httpx, Nuclei y Dalfox · Validación manual · Triaje y envío", styles["BodyGuide"]),
             Spacer(1, 13 * mm),
             Paragraph("<b>Basada en el código de BBHunter 0.1.0</b><br/>Revisión local y consulta "
                       "de documentación oficial: 24 de noviembre de 2026.", styles["BodyGuide"]),
             Spacer(1, 10 * mm),
             callout("Trabaja con cuentas y datos de prueba. El resultado del escáner es una hipótesis. "
                     "Un informe se envía cuando el impacto está demostrado y otra persona puede reproducirlo. "
                     "La decisión de aceptación y recompensa corresponde al programa."),
             PageBreak(), Paragraph("Índice", styles["ContentsHeading"])]
    toc = TableOfContents()
    toc.levelStyles = [styles["ContentsGuide"]]
    story.extend([toc, PageBreak()])
    story.extend(content(SOURCE.read_text(encoding="utf-8")))
    doc.multiBuild(story)
    shutil.copy2(OUTPUT, ROOT / "GUIA_BBHunter.pdf")
    print(f"PDF: {OUTPUT}")
    print(f"Pages: {doc.page}")
    for title, page in doc.chapter_pages.items():
        print(f"{page:3}  {title}")


if __name__ == "__main__":
    build()
