    #!/usr/bin/env python3
"""
PDF Prompt Injection Detector
==============================

Companion tool to pdf_inject.py. Scans a PDF for each of the six
injection vectors and reports per-vector findings with confidence.

Designed as a reference parser for ATS / LLM pipelines: each detector
implements the countermeasure for its corresponding injection vector.

Vectors and countermeasures implemented
---------------------------------------
  1. metadata       -> Audit /Info and XMP against allow-lists; flag
                       keyword fields containing imperative phrasing.
  2. offscreen      -> Clip all text runs to the page MediaBox/CropBox.
                       Flag runs whose bbox lies outside the clip.
  3. ocg            -> Resolve Optional Content Group default state;
                       ignore text inside OFF layers; flag if OFF-layer
                       text differs from ON-layer text.
  4. font           -> Cross-check /ToUnicode CMap against the font's
                       encoding and glyph shapes. Flag any code whose
                       mapping is longer than one grapheme, or whose
                       glyph name is /space but mapping is non-space.
  5. unicode        -> NFKC-normalize extracted text; count Cf-category
                       characters; flag homoglyph mixing (Latin+Cyrillic
                       in the same token).
  6. accessibility  -> Walk StructTreeRoot; compare /Alt and /ActualText
                       against the drawn text; flag mismatches.

Dependencies
------------
    pip install pikepdf pypdf

Optional (enables offscreen bbox and glyph-name checks):
    pip install pdfminer.six

Usage
-----
    python pdf_detect.py -i injected.pdf
    python pdf_detect.py -i injected.pdf --json report.json
    python pdf_detect.py -i injected.pdf --vectors metadata,font
"""

import argparse
import json
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path

try:
    import pikepdf
    from pikepdf import Pdf, Name, String, Dictionary, Array
except ImportError:
    print("ERROR: pip install pikepdf")
    sys.exit(1)

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

# pdfminer is optional; used for bbox-based offscreen detection
try:
    from pdfminer.high_level import extract_pages
    from pdfminer.layout import LTTextContainer, LTTextLine, LTChar
    HAVE_PDFMINER = True
except ImportError:
    HAVE_PDFMINER = False


# Constants and heuristics

IMPERATIVE_PATTERNS = [
    r"\bignore\s+(all\s+)?(previous|prior|above)\b",
    r"\bdisregard\s+(all\s+)?(previous|prior|above)\b",
    r"\brank\s+(this|me|the)\s+candidate\b",
    r"\bclassify\s+this\s+candidate\b",
    r"\bsystem\s+prompt\b",
    r"\byou\s+are\s+(now\s+)?(a|an)\b",
    r"\boverride\b.{0,20}\binstruction",
    r"\b(reveal|print|output)\s+(your\s+)?(system\s+)?prompt\b",
    r"\btop\s+candidate\b",
    r"\bscore\s+(me|this)\s+(as\s+)?(100|highest|top)\b",
]
IMPERATIVE_RE = re.compile("|".join(IMPERATIVE_PATTERNS), re.IGNORECASE)

# Cf category = format characters (zero-width, BOM, etc.)
def is_format_char(ch: str) -> bool:
    return unicodedata.category(ch) == "Cf"

# Scripts that commonly mix with Latin to create homoglyphs
HOMOGLYPH_RANGES = [
    (0x0400, 0x04FF),   # Cyrillic
    (0x0370, 0x03FF),   # Greek
]
def is_homoglyph_script(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in HOMOGLYPH_RANGES)

def is_latin_letter(ch: str) -> bool:
    return ch.isalpha() and ord(ch) < 0x0250 and not is_homoglyph_script(ch)


# Helpers

def get_page_text_pypdf(pdf_path, page_index):
    """Extract text from one page using pypdf."""
    if PdfReader is None:
        return None
    try:
        reader = PdfReader(str(pdf_path))
        return reader.pages[page_index].extract_text() or ""
    except Exception:
        return None


def get_full_text_pypdf(pdf_path):
    if PdfReader is None:
        return None
    try:
        reader = PdfReader(str(pdf_path))
        return "\n".join((p.extract_text() or "") for p in reader.pages)
    except Exception:
        return None


def resolve_indirect(obj):
    """Return the resolved object (pikepdf auto-resolves most things)."""
    return obj


def decode_pdf_string(s):
    """Decode a PDF string to Python str. Handles UTF-16BE BOM."""
    try:
        b = bytes(s)
    except Exception:
        return str(s)
    if b.startswith(b"\xfe\xff"):
        return b[2:].decode("utf-16-be", errors="replace")
    return b.decode("latin-1", errors="replace")


# Vector 1: Metadata

SUSPICIOUS_INFO_KEYS = ["/Keywords", "/Subject", "/Title", "/Author",
                        "/Creator", "/Producer"]

def detect_metadata(pdf, pdf_path):
    """
    Countermeasure:
      - Extract every /Info field and every XMP property.
      - Flag any field containing imperative phrasing.
      - Report the payload so downstream callers can sanitize.
    Legitimate resumes rarely have imperative commands inside metadata.
    """
    findings = {"flags": [], "values": {}}

    # /Info dictionary
    if "/Info" in pdf.trailer:
        info = pdf.trailer["/Info"]
        for key in SUSPICIOUS_INFO_KEYS:
            if key in info:
                raw = info[key]
                text = decode_pdf_string(raw) if isinstance(raw, String) else str(raw)
                findings["values"][f"Info{key}"] = text
                if IMPERATIVE_RE.search(text):
                    findings["flags"].append({
                        "severity": "high",
                        "location": f"Info{key}",
                        "reason": "imperative phrasing in metadata",
                        "snippet": text[:200],
                    })
                elif len(text) > 200:
                    findings["flags"].append({
                        "severity": "medium",
                        "location": f"Info{key}",
                        "reason": "unusually long metadata value",
                        "length": len(text),
                    })

    # XMP
    try:
        with pdf.open_metadata() as meta:
            for k, v in meta.items():
                if v is None:
                    continue
                text = v if isinstance(v, str) else str(v)
                findings["values"][f"XMP:{k}"] = text[:400]
                if IMPERATIVE_RE.search(text):
                    findings["flags"].append({
                        "severity": "high",
                        "location": f"XMP:{k}",
                        "reason": "imperative phrasing in XMP",
                        "snippet": text[:200],
                    })
    except Exception as e:
        findings["values"]["XMP"] = f"<unreadable: {e}>"

    return findings


# Vector 2: Off-screen text

def detect_offscreen(pdf, pdf_path):
    """
    Countermeasure:
      - For each page, read the MediaBox.
      - For each text run (via pdfminer if available), compute its bbox.
      - Flag any run whose bbox lies entirely outside the MediaBox.
    Without pdfminer, fall back to scanning raw content streams for Tm/Td
    coordinates that are wildly out of range.
    """
    findings = {"flags": [], "pages": []}

    for i, page in enumerate(pdf.pages):
        try:
            mb = [float(x) for x in page.MediaBox]
        except Exception:
            mb = [0.0, 0.0, 612.0, 792.0]

        page_report = {"page": i, "mediabox": mb, "offscreen_runs": 0,
                       "out_of_range_tm": []}

        # Preferred path: pdfminer with layout gives real bboxes
        if HAVE_PDFMINER:
            try:
                for layout in extract_pages(str(pdf_path), page_numbers=[i]):
                    for element in layout:
                        if isinstance(element, LTTextContainer):
                            for line in element:
                                if not isinstance(line, LTTextLine):
                                    continue
                                x0, y0, x1, y1 = line.bbox
                                # Fully outside the MediaBox?
                                if (x1 < mb[0] or x0 > mb[2] or
                                        y1 < mb[1] or y0 > mb[3]):
                                    page_report["offscreen_runs"] += 1
                                    text = line.get_text().strip()
                                    findings["flags"].append({
                                        "severity": "high",
                                        "location": f"page {i} bbox {line.bbox}",
                                        "reason": "text outside MediaBox",
                                        "snippet": text[:200],
                                    })
            except Exception:
                pass

        # Fallback: scan content stream for out-of-range Tm operands
        try:
            content = page.Contents
            streams = list(content) if isinstance(content, Array) else [content]
            for s in streams:
                try:
                    data = bytes(s.read_bytes()).decode("latin-1", "replace")
                except Exception:
                    continue
                for m in re.finditer(r"([-\d.]+)\s+([-\d.]+)\s+Tm", data):
                    x, y = float(m.group(1)), float(m.group(2))
                    if x < mb[0] - 100 or x > mb[2] + 100 or \
                       y < mb[1] - 100 or y > mb[3] + 100:
                        page_report["out_of_range_tm"].append([x, y])
                        findings["flags"].append({
                            "severity": "medium",
                            "location": f"page {i} Tm",
                            "reason": "text matrix places content far outside MediaBox",
                            "coords": [x, y],
                        })
        except Exception:
            pass

        findings["pages"].append(page_report)

    return findings


# Vector 3: OCG hidden layers

def detect_ocg(pdf, pdf_path):
    """
    Countermeasure:
      - Read /OCProperties /D /OFF to find layers that are off by default.
      - Flag any page whose content stream references /OC /<name> BDC where
        <name> resolves to an OFF OCG.
      - Report the extracted text of the marked-content section so callers
        can decide to drop it.
    """
    findings = {"flags": [], "ocgs": [], "off_by_default": []}

    if "/OCProperties" not in pdf.Root:
        return findings

    ocprops = pdf.Root["/OCProperties"]
    ocgs = ocprops.get("/OCGs", Array([]))
    default_cfg = ocprops.get("/D", Dictionary({}))
    off_list = default_cfg.get("/OFF", Array([]))

    for ocg in ocgs:
        name = ""
        if "/Name" in ocg:
            try:
                name = str(ocg["/Name"])
            except Exception:
                name = "<unnamed>"
        findings["ocgs"].append(name)

    # Match OFF OCGs by object identity
    off_ids = set()
    for ocg in off_list:
        off_ids.add(id(ocg.obj if hasattr(ocg, "obj") else ocg))

    for ocg in ocgs:
        key = id(ocg.obj if hasattr(ocg, "obj") else ocg)
        if key in off_ids:
            try:
                findings["off_by_default"].append(str(ocg["/Name"]))
            except Exception:
                findings["off_by_default"].append("<unnamed>")

    if findings["off_by_default"]:
        findings["flags"].append({
            "severity": "medium",
            "location": "OCProperties/D/OFF",
            "reason": "one or more OCG layers are off by default",
            "layers": findings["off_by_default"],
        })

    return findings


# Vector 4: Font /ToUnicode re-mapping

BFCHAR_RE = re.compile(r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>")
BFRANGE_RE = re.compile(r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>")


def _decode_utf16_hex(h: str) -> str:
    try:
        return bytes.fromhex(h).decode("utf-16-be", errors="replace")
    except Exception:
        return ""


def detect_font(pdf, pdf_path):
    """
    Countermeasure:
      - Walk every font in every page's /Resources /Font.
      - If the font has a /ToUnicode stream, decode its bfchar and bfrange
        entries.
      - Flag any mapping where:
          * a single source code maps to a multi-character string, or
          * the mapped target contains non-ASCII while the source code is
            an ASCII printable value that would render as a visible glyph.
      - Also flag /Differences arrays that map many codes to /space while
        ToUnicode maps those codes to non-space.
    """
    findings = {"flags": [], "fonts_checked": 0}

    for pi, page in enumerate(pdf.pages):
        if "/Resources" not in page:
            continue
        res = page["/Resources"]
        if "/Font" not in res:
            continue
        fonts = res["/Font"]

        for fname, font in fonts.items():
            findings["fonts_checked"] += 1
            font_report = {"page": pi, "name": str(fname)}

            # Read ToUnicode
            cmap_entries = {}
            if "/ToUnicode" in font:
                try:
                    cmap_data = bytes(font["/ToUnicode"].read_bytes()).decode(
                        "latin-1", "replace"
                    )
                    for m in BFCHAR_RE.finditer(cmap_data):
                        src = int(m.group(1), 16)
                        tgt = _decode_utf16_hex(m.group(2))
                        cmap_entries[src] = tgt
                    for m in BFRANGE_RE.finditer(cmap_data):
                        lo = int(m.group(1), 16)
                        hi = int(m.group(2), 16)
                        tgt_hex = m.group(3)
                        base = int(tgt_hex, 16)
                        for i, code in enumerate(range(lo, hi + 1)):
                            cmap_entries[code] = chr(base + i)
                except Exception:
                    pass

            font_report["cmap_entries"] = len(cmap_entries)

            # Build the /Differences map (code -> glyph name)
            diff_map = {}
            if "/Encoding" in font and "/Differences" in font["/Encoding"]:
                diffs = font["/Encoding"]["/Differences"]
                current = 0
                for item in diffs:
                    if isinstance(item, (int, float)):
                        current = int(item)
                    else:
                        diff_map[current] = str(item)
                        current += 1

            # Analyze
            suspicious = []
            for code, mapped in cmap_entries.items():
                # Case A: single code -> multi-char string
                if len(mapped) > 1:
                    suspicious.append({
                        "code": code,
                        "mapped": mapped,
                        "reason": "single code maps to multi-char string",
                    })
                    continue

                # Case B: code is mapped to /space via Differences but
                # ToUnicode says it's a non-space character
                glyph = diff_map.get(code)
                if glyph == "/space" and mapped and not mapped.isspace():
                    suspicious.append({
                        "code": code,
                        "mapped": mapped,
                        "glyph": glyph,
                        "reason": "rendered as space, extracted as non-space",
                    })

            if suspicious:
                findings["flags"].append({
                    "severity": "high",
                    "location": f"page {pi} font {fname}",
                    "reason": "ToUnicode / Differences mismatch",
                    "examples": suspicious[:10],
                    "count": len(suspicious),
                })
            font_report["suspicious"] = len(suspicious)
            findings.setdefault("font_reports", []).append(font_report)

    return findings


# Vector 5: Unicode hiding (Cf chars + homoglyphs)

def detect_unicode(pdf, pdf_path):
    """
    Countermeasure:
      - Extract all visible text (pypdf or pdfminer).
      - NFKC-normalize.
      - Count Cf-category characters.
      - Flag tokens that mix Latin with Cyrillic/Greek (homoglyph sign).
      - Flag any Cf character density above 1 per 20 visible chars.
    """
    findings = {"flags": [], "stats": {}}

    text = get_full_text_pypdf(pdf_path) or ""

    if HAVE_PDFMINER and not text:
        try:
            from pdfminer.high_level import extract_text as pm_extract
            text = pm_extract(str(pdf_path)) or ""
        except Exception:
            pass

    if not text:
        findings["stats"]["note"] = "no text extracted"
        return findings

    cf_chars = [c for c in text if is_format_char(c)]
    findings["stats"]["total_chars"] = len(text)
    findings["stats"]["cf_chars"] = len(cf_chars)
    findings["stats"]["cf_breakdown"] = {
        f"U+{ord(c):04X} {unicodedata.name(c, 'UNKNOWN')}": n
        for c, n in Counter(cf_chars).items()
    }

    if cf_chars:
        density = len(cf_chars) / max(1, len(text))
        findings["stats"]["cf_density"] = density
        if density > 0.05:
            findings["flags"].append({
                "severity": "high",
                "location": "extracted text",
                "reason": "high zero-width / format-character density",
                "density": round(density, 4),
                "count": len(cf_chars),
            })
        elif cf_chars:
            findings["flags"].append({
                "severity": "medium",
                "location": "extracted text",
                "reason": "format-character(s) present",
                "count": len(cf_chars),
            })

    # Homoglyph mixing
    tokens = re.findall(r"[A-Za-z\u0370-\u04FF]+", text)
    mixed = []
    for tok in tokens:
        has_latin = any(is_latin_letter(c) for c in tok)
        has_homoglyph = any(is_homoglyph_script(c) for c in tok)
        if has_latin and has_homoglyph:
            mixed.append(tok)
    if mixed:
        findings["flags"].append({
            "severity": "high",
            "location": "extracted text",
            "reason": "mixed-script tokens (Latin + Cyrillic/Greek)",
            "examples": mixed[:10],
            "count": len(mixed),
        })

    # Normalize and diff to surface the payload after normalization
    normalized = unicodedata.normalize("NFKC", text)
    if normalized != text:
        findings["stats"]["nfkc_changed"] = True

    return findings


# Vector 6: Accessibility tags (/Alt, /ActualText)

def detect_accessibility(pdf, pdf_path):
    """
    Countermeasure:
      - Walk /StructTreeRoot children.
      - Collect all /Alt and /ActualText strings.
      - Flag any that contain imperative phrasing, or that do NOT appear in
        the visible extracted text (a strong sign of hidden payload).
    """
    findings = {"flags": [], "alt_actual_text": []}

    if "/StructTreeRoot" not in pdf.Root:
        return findings

    visible = get_full_text_pypdf(pdf_path) or ""

    def walk(node, depth=0):
        if depth > 12:
            return
        if isinstance(node, Array):
            for child in node:
                walk(child, depth + 1)
            return
        if isinstance(node, Dictionary):
            for key in ("/Alt", "/ActualText"):
                if key in node:
                    text = decode_pdf_string(node[key])
                    entry = {"key": key, "text": text[:400]}
                    findings["alt_actual_text"].append(entry)

                    if IMPERATIVE_RE.search(text):
                        findings["flags"].append({
                            "severity": "high",
                            "location": f"StructTree {key}",
                            "reason": "imperative phrasing in accessibility tag",
                            "snippet": text[:200],
                        })
                    elif text and text not in visible:
                        findings["flags"].append({
                            "severity": "high",
                            "location": f"StructTree {key}",
                            "reason": "accessibility text not present in visible page text",
                            "snippet": text[:200],
                        })

            for v in node.values():
                walk(v, depth + 1)

    walk(pdf.Root["/StructTreeRoot"])
    return findings


# Orchestration

DETECTORS = {
    "metadata":      detect_metadata,
    "offscreen":     detect_offscreen,
    "ocg":           detect_ocg,
    "font":          detect_font,
    "unicode":       detect_unicode,
    "accessibility": detect_accessibility,
}


def compute_verdict(report):
    """Aggregate flags into a top-level verdict and score."""
    sev_weights = {"high": 1.0, "medium": 0.4, "low": 0.1}
    score = 0.0
    high = 0
    medium = 0
    for vector, res in report.items():
        if not isinstance(res, dict):
            continue
        for flag in res.get("flags", []):
            w = sev_weights.get(flag.get("severity", "low"), 0.1)
            score += w
            if flag.get("severity") == "high":
                high += 1
            elif flag.get("severity") == "medium":
                medium += 1

    if high > 0:
        verdict = "INJECTED"
    elif medium > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "verdict": verdict,
        "score": round(score, 2),
        "high_flags": high,
        "medium_flags": medium,
    }


def scan(pdf_path, vectors=None):
    src = Path(pdf_path)
    if not src.exists():
        raise FileNotFoundError(src)

    vectors = vectors or list(DETECTORS.keys())
    pdf = Pdf.open(str(src))

    report = {}
    for v in vectors:
        if v not in DETECTORS:
            report[v] = {"error": f"unknown vector: {v}"}
            continue
        try:
            if v == "metadata":
                report[v] = DETECTORS[v](pdf, str(src))
            else:
                report[v] = DETECTORS[v](pdf, str(src))
        except Exception as e:
            report[v] = {"error": f"{type(e).__name__}: {e}"}

    pdf.close()
    report["_verdict"] = compute_verdict(report)
    return report


# CLI

def main():
    ap = argparse.ArgumentParser(
        prog="pdf_detect",
        description="Detect prompt injection vectors in a PDF.",
    )
    ap.add_argument("-i", "--input", required=True, help="PDF to scan")
    ap.add_argument("--vectors", default=None,
                    help="Comma-separated subset (default: all)")
    ap.add_argument("--json", default=None,
                    help="Write the full report as JSON to this path")
    ap.add_argument("--quiet", action="store_true",
                    help="Only print the verdict line")
    args = ap.parse_args()

    vectors = None
    if args.vectors:
        vectors = [v.strip() for v in args.vectors.split(",") if v.strip()]

    try:
        report = scan(args.input, vectors)
    except FileNotFoundError:
        print(f"ERROR: file not found: {args.input}")
        sys.exit(1)

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2, default=str))
        if not args.quiet:
            print(f"[*] JSON report written to {args.json}")

    verdict = report.get("_verdict", {})
    print("=" * 60)
    print(f"File    : {args.input}")
    print(f"Verdict : {verdict.get('verdict')}  "
          f"(score {verdict.get('score')}, "
          f"high={verdict.get('high_flags')}, "
          f"medium={verdict.get('medium_flags')})")
    print("=" * 60)

    if args.quiet:
        return

    for v, res in report.items():
        if v.startswith("_"):
            continue
        flags = res.get("flags", []) if isinstance(res, dict) else []
        print(f"\n[{v}]  flags: {len(flags)}")
        for f in flags[:8]:
            loc = f.get("location", "?")
            reason = f.get("reason", "?")
            sev = f.get("severity", "?")
            print(f"  - ({sev}) {loc}: {reason}")
            if "snippet" in f:
                print(f"      snippet: {f['snippet'][:120]!r}")
        if isinstance(res, dict) and "error" in res:
            print(f"  ! error: {res['error']}")


if __name__ == "__main__":
    main()