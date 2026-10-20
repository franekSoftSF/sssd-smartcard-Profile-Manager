#!/usr/bin/env python3
"""Render docs/windows-smartcard-ssh.md to docs/windows-smartcard-ssh.pdf.

The Markdown file is the source of truth; the PDF is a build artefact that is
committed so that it can be handed to someone who will not clone the
repository. Re-run this after editing the Markdown::

    python packaging/build-windows-guide.py

Needs ReportLab, and nothing else::

    python -m pip install reportlab

This deliberately implements only the Markdown subset the guide uses -- ATX
headings, paragraphs, fenced code blocks, bullet lists, pipe tables, thematic
breaks, and inline ``code``/``**bold**``/autolinks. Anything else is passed
through as text rather than silently dropped, so an unsupported construct shows
up in the output instead of disappearing.
"""

from __future__ import annotations

import html
import pathlib
import re
import sys

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        ListFlowable,
        ListItem,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
except ImportError:  # pragma: no cover - build-time dependency
    sys.stderr.write(
        "reportlab is required to build the PDF.\n"
        "    python -m pip install reportlab\n"
    )
    raise SystemExit(2)

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "windows-smartcard-ssh.md"
TARGET = ROOT / "docs" / "windows-smartcard-ssh.pdf"

MONO = "Courier"
BODY_FONT = "Helvetica"
BOLD_FONT = "Helvetica-Bold"


def build_styles():
    sheet = getSampleStyleSheet()
    s = {}
    s["title"] = ParagraphStyle(
        "GuideTitle", parent=sheet["Title"], fontName=BOLD_FONT,
        fontSize=19, leading=23, spaceAfter=4, alignment=TA_LEFT,
    )
    s["h1"] = ParagraphStyle(
        "GuideH1", parent=sheet["Heading1"], fontName=BOLD_FONT,
        fontSize=14, leading=17, spaceBefore=14, spaceAfter=5,
        textColor=colors.HexColor("#1a1a1a"),
    )
    s["h2"] = ParagraphStyle(
        "GuideH2", parent=sheet["Heading2"], fontName=BOLD_FONT,
        fontSize=11.5, leading=14, spaceBefore=10, spaceAfter=4,
        textColor=colors.HexColor("#333333"),
    )
    s["h3"] = ParagraphStyle(
        "GuideH3", parent=sheet["Heading3"], fontName=BOLD_FONT,
        fontSize=10, leading=13, spaceBefore=8, spaceAfter=3,
        textColor=colors.HexColor("#333333"),
    )
    s["body"] = ParagraphStyle(
        "GuideBody", parent=sheet["BodyText"], fontName=BODY_FONT,
        fontSize=9, leading=12.6, spaceBefore=0, spaceAfter=6,
    )
    s["bullet"] = ParagraphStyle(
        "GuideBullet", parent=s["body"], spaceAfter=2.5,
    )
    s["code"] = ParagraphStyle(
        "GuideCode", parent=sheet["BodyText"], fontName=MONO,
        fontSize=7.8, leading=10, leftIndent=6, spaceBefore=1, spaceAfter=1,
        textColor=colors.HexColor("#101010"),
    )
    s["cell"] = ParagraphStyle(
        "GuideCell", parent=s["body"], fontSize=8.2, leading=10.6, spaceAfter=0,
    )
    s["cellhead"] = ParagraphStyle(
        "GuideCellHead", parent=s["cell"], fontName=BOLD_FONT,
    )
    return s


def inline(text: str) -> str:
    """Convert the inline Markdown the guide uses into ReportLab markup."""
    # Autolinks first, before escaping, so the URL survives intact.
    placeholders: list[str] = []

    def stash(markup: str) -> str:
        placeholders.append(markup)
        return "\x00%d\x00" % (len(placeholders) - 1)

    def do_link(m: re.Match) -> str:
        url = m.group(1)
        return stash(
            '<font name="%s" size="7.6" color="#0b4fa8">%s</font>'
            % (MONO, html.escape(url))
        )

    text = re.sub(r"<(https?://[^>\s]+)>", do_link, text)

    def do_code(m: re.Match) -> str:
        return stash(
            '<font name="%s" size="8.1" backColor="#f0f0f0">%s</font>'
            % (MONO, html.escape(m.group(1)))
        )

    text = re.sub(r"`([^`]+)`", do_code, text)

    def do_bold(m: re.Match) -> str:
        return stash("<b>%s</b>" % html.escape(m.group(1)))

    text = re.sub(r"\*\*([^*]+)\*\*", do_bold, text)

    def do_italic(m: re.Match) -> str:
        return stash("<i>%s</i>" % html.escape(m.group(1)))

    text = re.sub(r"(?<!\*)\*([^*\s][^*]*)\*(?!\*)", do_italic, text)

    text = html.escape(text)

    def restore(m: re.Match) -> str:
        return placeholders[int(m.group(1))]

    # Placeholders nest -- a **bold** span can contain a stashed `code` span --
    # so substitute repeatedly until none are left rather than once.
    for _ in range(10):
        new = re.sub(r"\x00(\d+)\x00", restore, text)
        if new == text:
            break
        text = new
    return text


def code_block(lines: list[str], styles) -> Table:
    body = [
        [Paragraph(
            '<font name="%s">%s</font>'
            % (MONO, html.escape(ln).replace(" ", "&nbsp;") or "&nbsp;"),
            styles["code"],
        )]
        for ln in lines
    ]
    table = Table(body, colWidths=[165 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f4f4")),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 0.6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0.6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def pipe_table(rows: list[list[str]], styles) -> Table:
    head, *rest = rows
    ncols = max(len(r) for r in rows)
    width = 165 * mm
    first = width * (0.36 if ncols == 2 else 1.0 / ncols)
    widths = [first] + [(width - first) / (ncols - 1)] * (ncols - 1) if ncols > 1 else [width]

    data = [[Paragraph(inline(c), styles["cellhead"]) for c in head]]
    for r in rest:
        padded = r + [""] * (ncols - len(r))
        data.append([Paragraph(inline(c), styles["cell"]) for c in padded])

    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def convert(text: str, styles) -> list:
    story: list = []
    lines = text.splitlines()
    i = 0
    first_heading = True

    # An ordered list whose items contain fenced code blocks is emitted as
    # several ListFlowables, because a fence ends the list. Without carrying the
    # number across, every fragment restarts at 1. This tracks where the next
    # fragment should resume; any heading or thematic break starts a new list.
    next_number = 1

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # fenced code block
        if stripped.startswith("```"):
            i += 1
            block: list[str] = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            story.append(Spacer(1, 3))
            story.append(code_block(block, styles))
            story.append(Spacer(1, 7))
            continue

        # pipe table
        if stripped.startswith("|") and i + 1 < len(lines) and re.match(
            r"^\|[\s:|-]+\|$", lines[i + 1].strip()
        ):
            def cells(raw: str) -> list[str]:
                return [c.strip() for c in raw.strip().strip("|").split("|")]

            rows = [cells(stripped)]
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(cells(lines[i].strip()))
                i += 1
            story.append(Spacer(1, 3))
            story.append(pipe_table(rows, styles))
            story.append(Spacer(1, 8))
            continue

        # thematic break
        if re.match(r"^-{3,}$", stripped):
            next_number = 1
            story.append(Spacer(1, 4))
            story.append(HRFlowable(
                width="100%", thickness=0.5, color=colors.HexColor("#bbbbbb"),
                spaceBefore=1, spaceAfter=6,
            ))
            i += 1
            continue

        # headings
        m = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if m:
            next_number = 1
            level = len(m.group(1))
            body = m.group(2)
            if level == 1 and first_heading:
                story.append(Paragraph(inline(body), styles["title"]))
                first_heading = False
            elif level == 1:
                story.append(PageBreak())
                story.append(Paragraph(inline(body), styles["h1"]))
            else:
                story.append(Paragraph(
                    inline(body), styles["h%d" % min(level, 3)]
                ))
            i += 1
            continue

        # lists: "- item" / "* item" unordered, "1. item" ordered. One level of
        # indented continuation lines is folded into the item; a fenced code
        # block ends the list so that the fence is rendered as a block rather
        # than flattened into the bullet text.
        bullet_re = r"^[-*]\s+"
        number_re = r"^\d+\.\s+"
        is_bullet = re.match(bullet_re, stripped) is not None
        is_number = re.match(number_re, stripped) is not None
        if is_bullet or is_number:
            marker_re = bullet_re if is_bullet else number_re
            items = []
            while i < len(lines):
                cur = lines[i].strip()
                if not re.match(marker_re, cur):
                    break
                chunk = [re.sub(marker_re, "", cur)]
                i += 1
                while i < len(lines):
                    nxt = lines[i]
                    if nxt.strip().startswith("```"):
                        break
                    if nxt.strip() == "":
                        nxt2 = lines[i + 1] if i + 1 < len(lines) else ""
                        if (nxt2.startswith("  ")
                                and not nxt2.strip().startswith("```")
                                and not re.match(r"^\s*(?:[-*]|\d+\.)\s+", nxt2)):
                            i += 1
                            continue
                        break
                    if (nxt.startswith("  ")
                            and not re.match(r"^\s*(?:[-*]|\d+\.)\s+", nxt)):
                        chunk.append(nxt.strip())
                        i += 1
                        continue
                    break
                items.append(ListItem(
                    Paragraph(inline(" ".join(c for c in chunk if c)),
                              styles["bullet"]),
                    leftIndent=14,
                ))
            story.append(ListFlowable(
                items,
                bulletType="bullet" if is_bullet else "1",
                bulletFontName=BODY_FONT,
                bulletFontSize=7 if is_bullet else 9,
                start="circle" if is_bullet else next_number,
                leftIndent=12, bulletOffsetY=-1 if is_bullet else 0,
                spaceBefore=1, spaceAfter=6,
            ))
            if not is_bullet:
                next_number += len(items)
            continue

        if stripped == "":
            i += 1
            continue

        # paragraph: gather until a blank line or a construct starts
        para = [stripped]
        i += 1
        while i < len(lines):
            nxt = lines[i].strip()
            if (nxt == "" or nxt.startswith("```") or nxt.startswith("|")
                    or nxt.startswith("#") or re.match(r"^[-*]\s+", nxt)
                    or re.match(r"^\d+\.\s+", nxt)
                    or re.match(r"^-{3,}$", nxt)):
                break
            para.append(nxt)
            i += 1
        story.append(Paragraph(inline(" ".join(para)), styles["body"]))

    return story


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont(BODY_FONT, 7.5)
    canvas.setFillColor(colors.HexColor("#777777"))
    canvas.drawString(
        20 * mm, 12 * mm,
        "SSSD Smart Card Profile Manager - SSH from Windows with a PIV smart card",
    )
    canvas.drawRightString(190 * mm, 12 * mm, "page %d" % doc.page)
    canvas.restoreState()


def main() -> int:
    if not SOURCE.is_file():
        sys.stderr.write("missing source: %s\n" % SOURCE)
        return 1

    styles = build_styles()
    story = convert(SOURCE.read_text(encoding="utf-8"), styles)

    doc = SimpleDocTemplate(
        str(TARGET), pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=20 * mm,
        title="SSH from Windows with a PIV smart card",
        author="SSSD Smart Card Profile Manager",
        subject="Windows client setup for smart card SSH login",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print("wrote %s" % TARGET.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
