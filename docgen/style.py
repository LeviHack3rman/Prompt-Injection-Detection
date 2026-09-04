"""WordprocessingML builders that reproduce the exact formatting of Chapters One to Three.

Every pattern here was measured from word/document.xml of the existing dissertation rather
than guessed, so appended chapters are indistinguishable in style from the ones already
written. In particular:

  body        NormalWeb, spacing before=0 after=160, justified, runs at sz 28 (14 pt)
  Heading 1   "CHAPTER FOUR" at sz 44 (22 pt), centred by style, page break before
  subtitle    a separate centred bold sz 28 (14 pt) NormalWeb line, e.g. "SYSTEM IMPLEMENTATION"
  Heading 2   sz 32 (16 pt) bold, numbered literally as "4.1<SP><NBSP><SP>Title"
  Heading 3   sz 28 (14 pt) bold (the style is redefined; it is unused and mis-set in the original)
  captions    one justified NormalWeb paragraph: bold 9 pt label run + plain 9 pt text run
  tables      no table style; per-cell BFBFBF 0.75 pt borders, D9E2F3 header shading, 9 pt cells

Heading numbering is typed literally, exactly as the existing document does it: the source
uses no Word list numbering anywhere (numbering.xml is orphaned).
"""
from __future__ import annotations

from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

W = nsdecls("w")

# The separator between a heading number and its title in the source document is
# SPACE + NO-BREAK SPACE + SPACE. Reproduced byte for byte.
NBSP = " "
SEP = f" {NBSP} "


def esc(t: str) -> str:
    return (str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _t(text: str) -> str:
    """A w:t element, preserving significant leading/trailing whitespace."""
    space = ' xml:space="preserve"' if text != text.strip() else ""
    return f"<w:t{space}>{esc(text)}</w:t>"


def run(text: str, sz: int = 28, bold: bool = False, italic: bool = False,
        color: str = "000000") -> str:
    rpr = ""
    if bold:
        rpr += "<w:b/><w:bCs/>"
    if italic:
        rpr += "<w:i/><w:iCs/>"
    rpr += f'<w:color w:val="{color}"/><w:sz w:val="{sz}"/><w:szCs w:val="{sz}"/>'
    return f"<w:r><w:rPr>{rpr}</w:rPr>{_t(text)}</w:r>"


def _p(ppr: str, runs: str) -> "etree._Element":
    return parse_xml(f"<w:p {W}><w:pPr>{ppr}</w:pPr>{runs}</w:p>")


def _normalweb_ppr(before: int = 0, after: int = 160, jc: str = "both",
                   extra: str = "") -> str:
    return ('<w:pStyle w:val="NormalWeb"/>'
            f'<w:spacing w:before="{before}" w:beforeAutospacing="0" '
            f'w:after="{after}" w:afterAutospacing="0"/>'
            f'<w:jc w:val="{jc}"/>{extra}'
            '<w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr>')


# --------------------------------------------------------------------------------------
# Paragraph builders
# --------------------------------------------------------------------------------------
def body(text: str, after: int = 160):
    """An ordinary justified body paragraph at 14 pt."""
    return _p(_normalweb_ppr(after=after), run(text))


def bullet(text: str, after: int = 80):
    """A body paragraph indented as a list item, matching the source document's approach
    of faking list indentation with paragraph indents rather than Word numbering."""
    ppr = _normalweb_ppr(after=after,
                         extra='<w:ind w:left="720" w:hanging="360"/>')
    return _p(ppr, run("•\t" + text))


def chapter_heading(text: str):
    """Heading 1 at 22 pt, e.g. "CHAPTER FOUR". Starts a new page."""
    ppr = ('<w:pStyle w:val="Heading1"/>'
           '<w:pageBreakBefore/>'
           '<w:spacing w:before="480" w:after="120"/>'
           '<w:rPr><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr>')
    return _p(ppr, f'<w:r><w:rPr><w:sz w:val="44"/><w:szCs w:val="44"/></w:rPr>{_t(text)}</w:r>')


def chapter_subtitle(text: str):
    """The centred bold 14 pt line under a chapter heading, e.g. "SYSTEM IMPLEMENTATION"."""
    return _p(_normalweb_ppr(after=200, jc="center"), run(text, sz=28, bold=True))


def heading1(text: str, page_break: bool = True):
    """A front/back-matter Heading 1 such as REFERENCES."""
    ppr = ('<w:pStyle w:val="Heading1"/>'
           + ("<w:pageBreakBefore/>" if page_break else "")
           + '<w:spacing w:before="480" w:after="120"/>'
             '<w:rPr><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr>')
    return _p(ppr, f'<w:r><w:rPr><w:sz w:val="44"/><w:szCs w:val="44"/></w:rPr>{_t(text)}</w:r>')


def heading2(number: str, title: str):
    """Heading 2 at 16 pt, numbered literally as the source document does."""
    ppr = ('<w:pStyle w:val="Heading2"/><w:spacing w:before="360"/><w:jc w:val="both"/>'
           '<w:rPr><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr>')
    return _p(ppr, f'<w:r><w:rPr><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr>'
                   f'{_t(number + SEP + title)}</w:r>')


def heading3(number: str, title: str):
    """Heading 3 at 14 pt bold. The style itself is redefined in build_document.py."""
    ppr = ('<w:pStyle w:val="Heading3"/><w:spacing w:before="280" w:after="80"/>'
           '<w:jc w:val="both"/>'
           '<w:rPr><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr>')
    return _p(ppr, f'<w:r><w:rPr><w:b/><w:bCs/><w:color w:val="000000"/>'
                   f'<w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr>'
                   f'{_t(number + SEP + title)}</w:r>')


def caption(label: str, text: str, before: int = 0, after: int = 80):
    """A figure or table caption: bold 9 pt label run, then a plain 9 pt text run."""
    return _p(_normalweb_ppr(before=before, after=after),
              run(label, sz=18, bold=True) + run(text, sz=18))


def code_line(text: str, after: int = 40):
    """A monospaced line, used for commands and file paths."""
    ppr = _normalweb_ppr(after=after, jc="left",
                         extra='<w:ind w:left="360"/>')
    rpr = ('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>'
           '<w:color w:val="000000"/><w:sz w:val="20"/><w:szCs w:val="20"/>')
    return _p(ppr, f"<w:r><w:rPr>{rpr}</w:rPr>{_t(text)}</w:r>")


def reference(text: str):
    """A reference-list entry with a hanging indent."""
    ppr = _normalweb_ppr(after=120, jc="both",
                         extra='<w:ind w:left="720" w:hanging="720"/>')
    return _p(ppr, run(text))


def empty():
    return parse_xml(f'<w:p {W}><w:pPr><w:jc w:val="both"/>'
                     f'<w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr></w:pPr></w:p>')


# --------------------------------------------------------------------------------------
# Tables
# --------------------------------------------------------------------------------------
_BORDERS = "".join(
    f'<w:{side} w:val="single" w:sz="6" w:space="0" w:color="BFBFBF"/>'
    for side in ("top", "left", "bottom", "right"))


def _cell(text: str, header: bool, width: int) -> str:
    shd = '<w:shd w:val="clear" w:color="auto" w:fill="D9E2F3"/>' if header else ""
    para = (f'<w:p><w:pPr><w:pStyle w:val="NormalWeb"/>'
            f'<w:spacing w:before="0" w:beforeAutospacing="0" w:after="0" '
            f'w:afterAutospacing="0"/><w:jc w:val="both"/>'
            f'<w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr></w:pPr>'
            f'{run(text, sz=18, bold=header)}</w:p>')
    return (f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>'
            f'<w:tcBorders>{_BORDERS}</w:tcBorders>{shd}'
            f'<w:tcMar><w:top w:w="60" w:type="dxa"/><w:left w:w="100" w:type="dxa"/>'
            f'<w:bottom w:w="60" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tcMar>'
            f'</w:tcPr>{para}</w:tc>')


def table(headers: list[str], rows: list[list[str]], widths: list[int] | None = None):
    """A table formatted exactly as those in Chapters Two and Three.

    Total width is 9010 twips, which is the text column for A4 with one-inch margins.
    """
    n = len(headers)
    if not widths:
        widths = [9010 // n] * n
    grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)

    trs = ['<w:tr><w:trPr><w:trHeight w:val="360"/><w:tblHeader/></w:trPr>'
           + "".join(_cell(h, True, w) for h, w in zip(headers, widths)) + "</w:tr>"]
    for r in rows:
        cells = [str(c) if c is not None else "" for c in r]
        cells += [""] * (n - len(cells))
        trs.append("<w:tr>" + "".join(_cell(c, False, w)
                                      for c, w in zip(cells[:n], widths)) + "</w:tr>")

    return parse_xml(
        f'<w:tbl {W}><w:tblPr><w:tblW w:w="0" w:type="auto"/>'
        f'<w:tblCellMar><w:top w:w="15" w:type="dxa"/><w:left w:w="15" w:type="dxa"/>'
        f'<w:bottom w:w="15" w:type="dxa"/><w:right w:w="15" w:type="dxa"/></w:tblCellMar>'
        f'<w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="1" '
        f'w:lastColumn="0" w:noHBand="0" w:noVBand="1"/></w:tblPr>'
        f'<w:tblGrid>{grid}</w:tblGrid>{"".join(trs)}</w:tbl>')
