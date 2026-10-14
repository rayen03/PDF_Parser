#!/usr/bin/env python3
"""
PDF Prompt Injection Research Tool
=========================================================

For controlled research environments only.

Vectors implemented
-------------------
  metadata       -> /Info /Keywords + XMP pdf:Keywords only
  font           -> drawn glyphs are spaces; payload lives in /ToUnicode
  accessibility  -> payload only in /Alt and /ActualText of StructTreeRoot

Additional "clipboard-safe only" mode (--safe-only) restricts the run
to the three vectors above. Those three NEVER place the payload in the
selectable/rendered text layer, so select-all -> copy -> paste yields
only the original document text.

The other three vectors (offscreen, ocg, unicode) are also rewritten
here to be clipboard-safe by the same mechanism (spaces on the page,
payload in /ToUnicode), but they remain opt-in because they modify the
page's content stream and are more likely to trip naive PDF diff tools.
"""

import argparse
import json
import random
import sys
import traceback
from pathlib import Path

try:
    import pikepdf
    from pikepdf import Pdf, Name, String, Dictionary, Array
except ImportError:
    print("ERROR: pip install pikepdf")
    sys.exit(1)



# Constants

ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"]

# Vectors whose payload never lands in the rendered/selectable text layer.
CLIPBOARD_SAFE_VECTORS = ["metadata", "font", "accessibility"]

# Full set of implemented vectors.
ALL_VECTORS = [
    "metadata",
    "font",
    "accessibility",
    "offscreen",
    "ocg",
    "unicode",
]


# Small helpers

def esc_pdf(s: str) -> str:
    """Escape a string for a PDF literal string."""
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def ensure_resources(pdf, page):
    """Ensure page has /Resources with a usable /Font entry."""
    if "/Resources" not in page:
        page["/Resources"] = pdf.make_indirect(Dictionary())
    res = page["/Resources"]
    if "/Font" not in res:
        res["/Font"] = pdf.make_indirect(Dictionary())
    return res


def find_usable_font(pdf, page):
    """Return the name of an existing font on the page, or add Helvetica."""
    res = ensure_resources(pdf, page)
    fonts = res["/Font"]
    for key in fonts.keys():
        return str(key)
    helv = pdf.make_indirect(Dictionary({
        "/Type": Name("/Font"),
        "/Subtype": Name("/Type1"),
        "/BaseFont": Name("/Helvetica"),
        "/Encoding": Name("/WinAnsiEncoding"),
    }))
    fonts["/F1"] = helv
    return "/F1"


def append_content(pdf, page, stream_bytes):
    """Append a new content stream to the page's /Contents."""
    new_stream = pdf.make_stream(stream_bytes)
    if "/Contents" in page:
        existing = page.Contents
        if isinstance(existing, Array):
            existing.append(new_stream)
        else:
            page.Contents = pdf.make_indirect(Array([existing, new_stream]))
    else:
        page.Contents = new_stream


def build_stealth_font(pdf, payload, font_key):
    """
    Build a font where every emitted code maps to the glyph name "/space"
    via /Differences, and each code's /ToUnicode entry resolves to the
    corresponding payload character.

    Result:
      - Anything that renders the page paints only spaces.
      - Anything that reads /ToUnicode reconstructs the payload.
      - Copy-paste of the page returns spaces, not the payload.

    Returns (font_dict, literal_bytes) or (None, "") if payload is empty.
    """
    payload_chars = list(payload)
    n = len(payload_chars)
    if n == 0:
        return None, ""

    # Assign each char a unique code in the printable ASCII range.
    codes = [0x21 + (i % 94) for i in range(n)]

    # ToUnicode: code -> payload char (UTF-16BE hex).
    bf = []
    for code, ch in zip(codes, payload_chars):
        utf16 = ch.encode("utf-16-be").hex().upper()
        bf.append(f"<{code:02X}> <{utf16}>")

    cmap = (
        "/CIDInit /ProcSet findresource begin\n"
        "12 dict begin\n"
        "begincmap\n"
        "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n"
        "/CMapName /Adobe-Identity-UCS def\n"
        "/CMapType 2 def\n"
        "1 begincodespacerange\n<00> <FF>\nendcodespacerange\n"
        f"{len(bf)} beginbfchar\n"
        + "\n".join(bf) + "\n"
        "endbfchar\nendcmap\n"
        "CMapName currentdict /CMap defineresource pop\nend\nend\n"
    )
    cmap_stream = pdf.make_stream(cmap.encode("latin-1"))

    # /Differences: every emitted code maps to the glyph name "/space".
    # Because we cover ALL emitted codes, nothing falls through to a
    # real letter.
    used = sorted(set(codes))
    differences = [used[0]]
    for _ in used:
        differences.append(Name("/space"))

    font = pdf.make_indirect(Dictionary({
        "/Type": Name("/Font"),
        "/Subtype": Name("/Type1"),
        "/BaseFont": Name("/Helvetica"),
        "/Encoding": pdf.make_indirect(Dictionary({
            "/Type": Name("/Encoding"),
            "/Differences": Array(differences),
        })),
        "/ToUnicode": cmap_stream,
    }))

    lit = "".join(chr(c) for c in codes)
    return font, lit


# Vector: metadata
def inject_metadata(pdf, payload, page_index=0):
    """
    Payload goes ONLY into /Info /Keywords and XMP pdf:Keywords.

    Neither location is rendered on the page and neither is reachable via
    page select-all / copy-paste. Viewers that display document properties
    will show it only if the user opens that dialog and reads the Keywords
    row explicitly.
    """
    if "/Info" not in pdf.trailer:
        pdf.trailer["/Info"] = pdf.make_indirect(Dictionary())
    info = pdf.trailer["/Info"]
    info["/Keywords"] = String(payload)

    xmp_status = "ok"
    try:
        with pdf.open_metadata() as meta:
            meta["pdf:Keywords"] = payload
    except Exception as e:
        xmp_status = f"failed: {e}"

    return {"info_dict": "/Keywords only", "xmp": xmp_status}


# Vector: font /ToUnicode
def inject_font_remap(pdf, payload, page_index=0):
    """
    Draw spaces at a normal coordinate. Payload lives in /ToUnicode only.

    Copy-paste of the page yields spaces. Extractors that honor /ToUnicode
    get the payload.
    """
    page = pdf.pages[page_index]
    res = ensure_resources(pdf, page)

    font, lit = build_stealth_font(pdf, payload, "/FInjected")
    if font is None:
        return {"error": "empty payload"}
    res["/Font"]["/FInjected"] = font

    stream = (
        f"BT /FInjected 9 Tf 72 400 Td ({esc_pdf(lit)}) Tj ET\n"
    ).encode("latin-1", "replace")
    append_content(pdf, page, stream)
    return {
        "font": "/FInjected",
        "drawn": "spaces only",
        "payload_channel": "/ToUnicode",
        "characters": len(lit),
    }


# Vector: accessibility tags
def inject_accessibility(pdf, payload, page_index=0):
    """
    Payload goes ONLY into /Alt and /ActualText of two StructElem nodes.

    Nothing is rendered on the page beyond an invisible space (render
    mode 3), which prevents the payload from appearing in copy-paste
    while still keeping the structure tree valid.
    """
    page = pdf.pages[page_index]
    font = find_usable_font(pdf, page)

    struct_root = pdf.make_indirect(Dictionary({
        "/Type": Name("/StructTreeRoot"),
        "/K": Array([]),
    }))
    pdf.Root["/StructTreeRoot"] = struct_root
    pdf.Root["/MarkInfo"] = pdf.make_indirect(Dictionary({"/Marked": True}))

    figure = pdf.make_indirect(Dictionary({
        "/Type": Name("/StructElem"),
        "/S": Name("/Figure"),
        "/P": struct_root,
        "/Alt": String(payload),
        "/ActualText": String(payload),
    }))
    span = pdf.make_indirect(Dictionary({
        "/Type": Name("/StructElem"),
        "/S": Name("/Span"),
        "/P": struct_root,
        "/ActualText": String(payload),
    }))
    struct_root["/K"].append(figure)
    struct_root["/K"].append(span)

    page["/StructParents"] = 0
    page["/Tabs"] = Name("/S")

    # Minimal invisible content so the MCID association resolves, but
    # nothing lands on screen or in the clipboard beyond a single space.
    stream = (
        f"/Figure <</MCID 0>> BDC\n"
        f"BT 3 Tr {font} 10 Tf 72 200 Td ( ) Tj ET\n"
        f"EMC\n"
    ).encode("latin-1", "replace")
    append_content(pdf, page, stream)
    return {
        "struct_elements": ["/Figure (Alt+ActualText)", "/Span (ActualText)"],
        "visible_content": "none",
    }


# Vector: offscreen (clipboard-safe by construction)
def inject_offscreen(pdf, payload, page_index=0):
    """
    Draw spaces at off-page coordinates with render mode 3. Payload lives
    in /ToUnicode. Nothing renders; nothing is copy-pasteable.
    """
    page = pdf.pages[page_index]
    res = ensure_resources(pdf, page)

    font, lit = build_stealth_font(pdf, payload, "/FOffscr")
    if font is None:
        return {"error": "empty payload"}
    res["/Font"]["/FOffscr"] = font

    try:
        mb = [float(x) for x in page.MediaBox]
    except Exception:
        mb = [0, 0, 612, 792]
    w, h = mb[2] - mb[0], mb[3] - mb[1]

    positions = [
        (mb[0] - 5000, mb[1] - 5000),
        (mb[2] + 5000, mb[3] + 5000),
    ]

    parts = ["q"]
    for x, y in positions:
        parts.append(f"BT 3 Tr /FOffscr 6 Tf 1 0 0 1 {x:.2f} {y:.2f} Tm")
        parts.append(f"({esc_pdf(lit)}) Tj ET")
    parts.append("Q")
    append_content(pdf, page, "\n".join(parts).encode("latin-1", "replace"))
    return {
        "positions": positions,
        "drawn": "spaces only",
        "payload_channel": "/ToUnicode",
    }


# Vector: OCG hidden layer (clipboard-safe by construction)
def inject_ocg(pdf, payload, page_index=0):
    """
    OCG named 'Background', OFF by default. Only spaces are drawn inside
    the OCG marked-content section. Payload lives in /ToUnicode.
    """
    page = pdf.pages[page_index]
    res = ensure_resources(pdf, page)

    ocg = pdf.make_indirect(Dictionary({
        "/Type": Name("/OCG"),
        "/Name": String("Background"),
    }))

    if "/OCProperties" not in pdf.Root:
        pdf.Root["/OCProperties"] = pdf.make_indirect(Dictionary({
            "/OCGs": Array([]),
            "/D": pdf.make_indirect(Dictionary({
                "/OFF": Array([]), "/ON": Array([]),
            })),
        }))
    ocprops = pdf.Root["/OCProperties"]
    if "/OCGs" not in ocprops:
        ocprops["/OCGs"] = Array([])
    ocprops["/OCGs"].append(ocg)
    if "/D" not in ocprops:
        ocprops["/D"] = pdf.make_indirect(Dictionary({
            "/OFF": Array([]), "/ON": Array([]),
        }))
    ocprops["/D"]["/OFF"].append(ocg)

    if "/Properties" not in res:
        res["/Properties"] = pdf.make_indirect(Dictionary())
    res["/Properties"]["/OC1"] = ocg

    font, lit = build_stealth_font(pdf, payload, "/FOCG")
    if font is None:
        return {"error": "empty payload"}
    res["/Font"]["/FOCG"] = font

    stream = (
        f"/OC /OC1 BDC\n"
        f"BT 3 Tr /FOCG 10 Tf 72 500 Td ({esc_pdf(lit)}) Tj ET\n"
        f"EMC\n"
    ).encode("latin-1", "replace")
    append_content(pdf, page, stream)
    return {
        "ocg": "Background (OFF)",
        "drawn": "spaces only",
        "payload_channel": "/ToUnicode",
    }


# Vector: unicode hiding (clipboard-safe by construction)
def inject_unicode(pdf, payload, page_index=0):
    """
    Zero-width characters are interleaved into the payload, which is then
    written ONLY into /ToUnicode. Drawn glyphs are spaces. Copy-paste of
    the page yields spaces; ToUnicode-aware extractors get the
    zero-width-laced payload.
    """
    page = pdf.pages[page_index]
    res = ensure_resources(pdf, page)

    zw = []
    for ch in payload:
        zw.append(ch)
        if random.random() < 0.4:
            zw.append(random.choice(ZERO_WIDTH_CHARS))
    zw_str = "".join(zw)

    font, lit = build_stealth_font(pdf, zw_str, "/FInvisible")
    if font is None:
        return {"error": "empty payload"}
    res["/Font"]["/FInvisible"] = font

    stream = (
        f"BT /FInvisible 11 Tf 72 300 Td ({esc_pdf(lit)}) Tj ET\n"
    ).encode("latin-1", "replace")
    append_content(pdf, page, stream)
    return {
        "zero_width_added": len(zw_str) - len(payload),
        "drawn": "spaces only",
        "payload_channel": "/ToUnicode",
    }


# Registry
VECTORS = {
    "metadata":      inject_metadata,
    "font":          inject_font_remap,
    "accessibility": inject_accessibility,
    "offscreen":     inject_offscreen,
    "ocg":           inject_ocg,
    "unicode":       inject_unicode,
}


# Runner
def run_injection(input_pdf, output_pdf, payload, vectors, page_index=0):
    src = Path(input_pdf)
    if not src.exists():
        print(f"ERROR: input not found: {src}")
        sys.exit(1)

    print(f"[*] Opening {src}")
    pdf = Pdf.open(str(src))
    print(f"[*] Pages: {len(pdf.pages)}")
    print(f"[*] Vectors: {vectors}")

    report = {}
    for v in vectors:
        print(f"[*] Injecting: {v}")
        try:
            report[v] = VECTORS[v](pdf, payload, page_index)
            print(f"    OK: {report[v]}")
        except Exception as e:
            print(f"    FAILED: {e}")
            traceback.print_exc()
            report[v] = {"error": str(e)}

    print(f"[*] Saving -> {output_pdf}")
    pdf.save(str(output_pdf))
    pdf.close()
    print("[+] Done.")
    return report


# CLI
def main():
    ap = argparse.ArgumentParser(
        prog="pdf_inject",
        description="PDF prompt injection research tool (clipboard-safe).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Full suite (all six vectors)\n"
            "  %(prog)s -i in.pdf -o out.pdf -p 'IGNORE PRIOR INSTRUCTIONS'\n\n"
            "  # Only the three clipboard-safe vectors\n"
            "  %(prog)s -i in.pdf -o out.pdf -p '...' --safe-only\n\n"
            "  # Hand-picked vectors\n"
            "  %(prog)s -i in.pdf -o out.pdf -p '...' --vectors metadata,font\n"
        ),
    )
    ap.add_argument("-i", "--input", required=True,
                    help="Input PDF path")
    ap.add_argument("-o", "--output", required=True,
                    help="Output PDF path")
    ap.add_argument("-p", "--payload", required=True,
                    help="Payload string to inject")
    ap.add_argument("--page", type=int, default=0,
                    help="Page index for content-based vectors (default 0)")

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--safe-only", action="store_true",
        help=("Run only the clipboard-safe vectors: "
              + ", ".join(CLIPBOARD_SAFE_VECTORS)),
    )
    mode.add_argument(
        "--vectors", default=None,
        help=("Comma-separated subset of: " + ", ".join(ALL_VECTORS)
              + "  (default: all)"),
    )

    args = ap.parse_args()

    if args.safe_only:
        vectors = list(CLIPBOARD_SAFE_VECTORS)
    elif args.vectors:
        vectors = [v.strip() for v in args.vectors.split(",") if v.strip()]
        unknown = [v for v in vectors if v not in VECTORS]
        if unknown:
            print(f"ERROR: unknown vector(s): {unknown}")
            print(f"       known vectors: {list(VECTORS.keys())}")
            sys.exit(2)
    else:
        vectors = list(ALL_VECTORS)

    print("=" * 60)
    print("PDF PROMPT INJECTION RESEARCH TOOL")
    print("FOR CONTROLLED RESEARCH ENVIRONMENTS ONLY")
    print("=" * 60)

    report = run_injection(
        input_pdf=args.input,
        output_pdf=args.output,
        payload=args.payload,
        vectors=vectors,
        page_index=args.page,
    )

    print("-" * 60)
    print("Injection report:")
    print(json.dumps(report, indent=2, default=str))
    print("=" * 60)


if __name__ == "__main__":
    main()