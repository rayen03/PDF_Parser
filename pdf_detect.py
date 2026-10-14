#!/usr/bin/env python3
"""
PDF Prompt Injection Detector
=============================

Scans PDF files for adversarial prompt injection vectors, hidden text channels,
and steganographic anomalies across structural layers.

Detects:
  1. Metadata Injection (/Info dictionary & XMP metadata packets)
  2. Stealth Font Remapping (/ToUnicode divergence vs /Differences spaces)
  3. Accessibility Tree Exploitation (StructTreeRoot /Alt & /ActualText)
  4. Off-Screen / Hidden Content (Coordinates beyond MediaBox or render mode 3 Tr)
  5. Inactive Optional Content Groups (OCG / Layers configured OFF by default)
  6. Unicode Steganography (Zero-width characters & non-printable codepoints)
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import pikepdf
    from pikepdf import Array, Dictionary, Name, Pdf, Stream, String
except ImportError:
    print("ERROR: pikepdf is required. Run: pip install pikepdf")
    sys.exit(1)

# Zero-width / hidden unicode characters
ZERO_WIDTH_CHARS = {
    "\u200b": "Zero Width Space (U+200B)",
    "\u200c": "Zero Width Non-Joiner (U+200C)",
    "\u200d": "Zero Width Joiner (U+200D)",
    "\u2060": "Word Joiner (U+2060)",
    "\ufeff": "Zero Width No-Break Space (U+FEFF)",
}

PROMPT_INJECTION_KEYWORDS = [
    r"ignore\s+(all\s+)?prior\s+instructions",
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"system\s*prompt",
    r"system\s*message",
    r"top\s+candidate",
    r"rank\s+this\s+candidate",
    r"disregard",
    r"you\s+are\s+now",
    r"override",
    r"jailbreak",
]


def match_injection_heuristic(text: str) -> List[str]:
    """Check text against known prompt injection heuristic patterns."""
    hits = []
    if not text:
        return hits
    for pat in PROMPT_INJECTION_KEYWORDS:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(pat)
    return hits


# ---------------------------------------------------------------------------
# Detector 1: Metadata (/Info and XMP)
# ---------------------------------------------------------------------------
def detect_metadata(pdf: Pdf) -> Dict[str, Any]:
    findings = []
    suspicious_entries = {}

    # 1. /Info Trailer Dictionary
    if "/Info" in pdf.trailer:
        info = pdf.trailer["/Info"]
        for key, val in info.items():
            key_str = str(key)
            val_str = str(val)
            kw_hits = match_injection_heuristic(val_str)
            if kw_hits:
                findings.append(f"Heuristic injection match in /Info {key_str}: {kw_hits}")
                suspicious_entries[f"Info:{key_str}"] = val_str
            elif key_str == "/Keywords" and len(val_str.strip()) > 0:
                suspicious_entries[f"Info:{key_str}"] = val_str

    # 2. XMP Metadata
    try:
        with pdf.open_metadata() as meta:
            for k, v in meta.items():
                v_str = str(v)
                kw_hits = match_injection_heuristic(v_str)
                if kw_hits:
                    findings.append(f"Heuristic injection match in XMP [{k}]: {kw_hits}")
                    suspicious_entries[f"XMP:{k}"] = v_str
                elif "Keywords" in k and len(v_str.strip()) > 0:
                    suspicious_entries[f"XMP:{k}"] = v_str
    except Exception:
        pass

    detected = len(suspicious_entries) > 0
    return {
        "detected": detected,
        "confidence": "HIGH" if findings else ("MEDIUM" if detected else "NONE"),
        "findings": findings,
        "payloads": suspicious_entries,
    }


# ---------------------------------------------------------------------------
# Detector 2: Stealth Font & /ToUnicode Remapping
# ---------------------------------------------------------------------------
def parse_tounicode_cmap(stream_data: bytes) -> Dict[int, str]:
    """Parse a simple CIDInit /ToUnicode CMap into {code: unicode_char}."""
    mapping = {}
    try:
        text = stream_data.decode("latin-1", errors="ignore")
    except Exception:
        return mapping

    # Find bfchar entries: <01> <0041>
    bfchar_blocks = re.findall(r"beginbfchar(.*?)endbfchar", text, re.DOTALL)
    for block in bfchar_blocks:
        pairs = re.findall(r"<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>", block)
        for code_hex, utf16_hex in pairs:
            try:
                code = int(code_hex, 16)
                decoded_char = bytes.fromhex(utf16_hex).decode("utf-16-be", errors="ignore")
                mapping[code] = decoded_char
            except Exception:
                continue

    # Find bfrange entries: <01> <05> <0041>
    bfrange_blocks = re.findall(r"beginbfrange(.*?)endbfrange", text, re.DOTALL)
    for block in bfrange_blocks:
        ranges = re.findall(r"<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>", block)
        for start_hex, end_hex, val_hex in ranges:
            try:
                start_code = int(start_hex, 16)
                end_code = int(end_hex, 16)
                base_val = int(val_hex, 16)
                for idx, c in enumerate(range(start_code, end_code + 1)):
                    decoded_char = (base_val + idx).to_bytes(2, "big").decode("utf-16-be", errors="ignore")
                    mapping[c] = decoded_char
            except Exception:
                continue

    return mapping


def detect_font_remapping(pdf: Pdf) -> Dict[str, Any]:
    findings = []
    extracted_payloads = []

    for page_idx, page in enumerate(pdf.pages):
        if "/Resources" not in page or "/Font" not in page["/Resources"]:
            continue
        fonts = page["/Resources"]["/Font"]
        for font_name, font_obj in fonts.items():
            if not isinstance(font_obj, Dictionary):
                continue

            # Check if font defines /ToUnicode
            if "/ToUnicode" in font_obj:
                try:
                    tounicode_stream = font_obj["/ToUnicode"].read_bytes()
                    mapping = parse_tounicode_cmap(tounicode_stream)
                except Exception:
                    mapping = {}

                # Check /Encoding /Differences
                is_space_mapped = False
                if "/Encoding" in font_obj and isinstance(font_obj["/Encoding"], Dictionary):
                    enc = font_obj["/Encoding"]
                    if "/Differences" in enc:
                        diffs = enc["/Differences"]
                        space_count = sum(1 for item in diffs if str(item) == "/space")
                        if space_count > 3:
                            is_space_mapped = True

                # Check divergence: ToUnicode produces text while font is mapped to spaces
                reconstructed_text = "".join(mapping.values()) if mapping else ""
                kw_hits = match_injection_heuristic(reconstructed_text)

                if is_space_mapped and reconstructed_text.strip():
                    findings.append(
                        f"Page {page_idx} font {font_name}: Stealth font detected. "
                        f"Differences map to /space, but /ToUnicode decodes to: '{reconstructed_text[:80]}...'"
                    )
                    extracted_payloads.append(reconstructed_text)
                elif kw_hits:
                    findings.append(
                        f"Page {page_idx} font {font_name}: /ToUnicode contains prompt injection signature: {kw_hits}"
                    )
                    extracted_payloads.append(reconstructed_text)

    detected = len(extracted_payloads) > 0
    return {
        "detected": detected,
        "confidence": "HIGH" if detected else "NONE",
        "findings": findings,
        "extracted_payloads": extracted_payloads,
    }


# ---------------------------------------------------------------------------
# Detector 3: Accessibility Structure Tree (/StructTreeRoot)
# ---------------------------------------------------------------------------
def detect_accessibility(pdf: Pdf) -> Dict[str, Any]:
    findings = []
    extracted_payloads = []

    if "/StructTreeRoot" not in pdf.Root:
        return {"detected": False, "confidence": "NONE", "findings": [], "extracted_payloads": []}

    struct_root = pdf.Root["/StructTreeRoot"]

    def walk_element(elem):
        if not isinstance(elem, Dictionary):
            return

        for tag in ["/Alt", "/ActualText"]:
            if tag in elem:
                val = str(elem[tag])
                kw_hits = match_injection_heuristic(val)
                s_type = str(elem.get("/S", "Unknown"))
                if kw_hits:
                    findings.append(
                        f"Structural element {s_type} has {tag} with prompt injection heuristic: {kw_hits}"
                    )
                    extracted_payloads.append(val)
                elif len(val.strip()) > 30 and not val.strip().isalpha():
                    # Unusually long non-prose metadata in Alt/ActualText
                    findings.append(f"Structural element {s_type} has suspicious {tag} payload: '{val[:80]}...'")
                    extracted_payloads.append(val)

        if "/K" in elem:
            children = elem["/K"]
            if isinstance(children, Array):
                for child in children:
                    walk_element(child)
            elif isinstance(children, Dictionary):
                walk_element(children)

    if "/K" in struct_root:
        k_content = struct_root["/K"]
        if isinstance(k_content, Array):
            for item in k_content:
                walk_element(item)
        elif isinstance(k_content, Dictionary):
            walk_element(k_content)

    detected = len(extracted_payloads) > 0
    return {
        "detected": detected,
        "confidence": "HIGH" if any("heuristic" in f for f in findings) else ("MEDIUM" if detected else "NONE"),
        "findings": findings,
        "extracted_payloads": extracted_payloads,
    }


# ---------------------------------------------------------------------------
# Detector 4: Offscreen / Invisible Content Streams
# ---------------------------------------------------------------------------
def detect_offscreen(pdf: Pdf) -> Dict[str, Any]:
    findings = []
    suspicious_blocks = []

    for page_idx, page in enumerate(pdf.pages):
        try:
            mb = [float(x) for x in page.MediaBox]
        except Exception:
            mb = [0, 0, 612, 792]

        min_x, min_y, max_x, max_y = mb[0], mb[1], mb[2], mb[3]

        # Extract content streams
        raw_streams = []
        if "/Contents" in page:
            c = page["/Contents"]
            if isinstance(c, Array):
                for stream in c:
                    try:
                        raw_streams.append(stream.read_bytes().decode("latin-1", errors="ignore"))
                    except Exception:
                        pass
            elif isinstance(c, Stream):
                try:
                    raw_streams.append(c.read_bytes().decode("latin-1", errors="ignore"))
                except Exception:
                    pass

        content_str = "\n".join(raw_streams)

        # Check render mode 3 Tr (invisible text)
        if re.search(r"\b3\s+Tr\b", content_str):
            findings.append(f"Page {page_idx}: Found render mode '3 Tr' (invisible text operator)")
            suspicious_blocks.append(f"Page {page_idx}: 3 Tr invisible text")

        # Check matrix or coordinates Tm / Td with offscreen positions
        tm_matches = re.findall(
            r"([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+Tm", content_str
        )
        for _, _, _, _, tx, ty in tm_matches:
            try:
                x, y = float(tx), float(ty)
                if x < (min_x - 500) or x > (max_x + 500) or y < (min_y - 500) or y > (max_y + 500):
                    findings.append(
                        f"Page {page_idx}: Text placed far outside MediaBox at coordinate ({x:.1f}, {y:.1f})"
                    )
                    suspicious_blocks.append(f"Page {page_idx}: offscreen ({x:.1f}, {y:.1f})")
                    break
            except ValueError:
                continue

    detected = len(suspicious_blocks) > 0
    return {
        "detected": detected,
        "confidence": "HIGH" if detected else "NONE",
        "findings": findings,
        "anomalies": suspicious_blocks,
    }


# ---------------------------------------------------------------------------
# Detector 5: Optional Content Groups (OCG Hidden Layers)
# ---------------------------------------------------------------------------
def detect_ocg(pdf: Pdf) -> Dict[str, Any]:
    findings = []
    off_layers = []

    if "/OCProperties" in pdf.Root:
        ocprops = pdf.Root["/OCProperties"]
        if "/D" in ocprops and isinstance(ocprops["/D"], Dictionary):
            d_dict = ocprops["/D"]
            if "/OFF" in d_dict and isinstance(d_dict["/OFF"], Array):
                for layer_ref in d_dict["/OFF"]:
                    if isinstance(layer_ref, Dictionary) and "/Name" in layer_ref:
                        layer_name = str(layer_ref["/Name"])
                        off_layers.append(layer_name)
                        findings.append(f"Hidden layer configured OFF by default: '{layer_name}'")

    # Check page content streams for /OC markings
    for page_idx, page in enumerate(pdf.pages):
        if "/Contents" in page:
            raw = ""
            if isinstance(page["/Contents"], Array):
                for s in page["/Contents"]:
                    raw += s.read_bytes().decode("latin-1", errors="ignore")
            elif isinstance(page["/Contents"], Stream):
                raw += page["/Contents"].read_bytes().decode("latin-1", errors="ignore")

            if "/OC" in raw:
                findings.append(f"Page {page_idx}: Contains marked content referencing Optional Content Groups (/OC)")

    detected = len(off_layers) > 0
    return {
        "detected": detected,
        "confidence": "HIGH" if off_layers else "NONE",
        "findings": findings,
        "off_layers": off_layers,
    }


# ---------------------------------------------------------------------------
# Detector 6: Unicode Steganography
# ---------------------------------------------------------------------------
def detect_unicode_steganography(pdf: Pdf) -> Dict[str, Any]:
    findings = []
    zw_hits = {}

    def scan_for_zw(source_name: str, text: str):
        if not text:
            return
        found_chars = []
        for ch, name in ZERO_WIDTH_CHARS.items():
            count = text.count(ch)
            if count > 0:
                found_chars.append(f"{name} x{count}")
        if found_chars:
            findings.append(f"{source_name}: Contains zero-width characters: {', '.join(found_chars)}")
            zw_hits[source_name] = found_chars

    # 1. Check metadata
    if "/Info" in pdf.trailer:
        for k, v in pdf.trailer["/Info"].items():
            scan_for_zw(f"Info:{k}", str(v))

    # 2. Check ToUnicode streams
    for page_idx, page in enumerate(pdf.pages):
        if "/Resources" in page and "/Font" in page["/Resources"]:
            for font_name, font_obj in page["/Resources"]["/Font"].items():
                if isinstance(font_obj, Dictionary) and "/ToUnicode" in font_obj:
                    try:
                        stream_bytes = font_obj["/ToUnicode"].read_bytes()
                        mapping = parse_tounicode_cmap(stream_bytes)
                        full_mapped = "".join(mapping.values())
                        scan_for_zw(f"Page {page_idx} Font {font_name} /ToUnicode", full_mapped)
                    except Exception:
                        pass

    # 3. Check StructTreeRoot
    if "/StructTreeRoot" in pdf.Root:
        def walk_zw(elem):
            if not isinstance(elem, Dictionary):
                return
            for tag in ["/Alt", "/ActualText"]:
                if tag in elem:
                    scan_for_zw(f"StructElem {tag}", str(elem[tag]))
            if "/K" in elem:
                k = elem["/K"]
                if isinstance(k, Array):
                    for c in k:
                        walk_zw(c)
                elif isinstance(k, Dictionary):
                    walk_zw(k)

        walk_zw(pdf.Root["/StructTreeRoot"])

    detected = len(zw_hits) > 0
    return {
        "detected": detected,
        "confidence": "HIGH" if detected else "NONE",
        "findings": findings,
        "occurrences": zw_hits,
    }


# ---------------------------------------------------------------------------
# Main Scan Pipeline
# ---------------------------------------------------------------------------
def scan_pdf(filepath: str) -> Dict[str, Any]:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    pdf = Pdf.open(str(path))

    results = {
        "target": str(path),
        "page_count": len(pdf.pages),
        "vectors": {
            "metadata": detect_metadata(pdf),
            "font": detect_font_remapping(pdf),
            "accessibility": detect_accessibility(pdf),
            "offscreen": detect_offscreen(pdf),
            "ocg": detect_ocg(pdf),
            "unicode": detect_unicode_steganography(pdf),
        },
    }

    pdf.close()

    # Aggregate evaluation
    detected_vectors = [v for v, res in results["vectors"].items() if res["detected"]]
    total_findings = sum(len(res["findings"]) for res in results["vectors"].values())

    results["summary"] = {
        "clean": len(detected_vectors) == 0,
        "detected_vectors": detected_vectors,
        "detected_count": len(detected_vectors),
        "total_anomalies": total_findings,
        "threat_level": "CRITICAL" if len(detected_vectors) >= 3 else ("SUSPICIOUS" if detected_vectors else "CLEAN"),
    }

    return results


def print_cli_report(results: Dict[str, Any]):
    print("=" * 65)
    print("PDF PROMPT INJECTION SCAN REPORT")
    print("=" * 65)
    print(f"Target:       {results['target']}")
    print(f"Page Count:   {results['page_count']}")
    summary = results["summary"]
    print(f"Threat Level: {summary['threat_level']}")
    print(f"Injections:   {summary['detected_count']} vector(s) identified")
    print("-" * 65)

    for vector, details in results["vectors"].items():
        status = "[!] DETECTED" if details["detected"] else "[+] CLEAN"
        conf = f"[{details['confidence']}]" if details["detected"] else ""
        print(f"[{vector.upper()}] {status} {conf}")
        for finding in details.get("findings", []):
            safe_finding = finding.encode(sys.stdout.encoding or "utf-8", errors="backslashreplace").decode(
                sys.stdout.encoding or "utf-8", errors="ignore"
            )
            print(f"   - {safe_finding}")

    print("=" * 65)


def main():
    ap = argparse.ArgumentParser(
        prog="pdf_detect",
        description="Scan PDF files for prompt injection vectors and steganographic anomalies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-i", "--input", required=True, help="Path to PDF file to scan")
    ap.add_argument("-o", "--output", default=None, help="Save JSON detection report to path")
    ap.add_argument("--json", action="store_true", help="Print only JSON report to stdout")
    args = ap.parse_args()

    try:
        report = scan_pdf(args.input)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report written to {out_path}")

    if args.json:
        print(json.dumps(report, indent=2))
    elif not args.output or not args.json:
        print_cli_report(report)


if __name__ == "__main__":
    main()
