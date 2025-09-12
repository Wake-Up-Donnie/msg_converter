#!/bin/zsh
set -euo pipefail

# Local test for .msg -> .eml -> PDF using backend/lambda_function.py helpers
# It will:
#  - Install Playwright Chromium (needed for proper HTML rendering)
#  - Convert the specified .msg to EML bytes
#  - Run the same rich extractor used in Lambda (images + HTML cleanup)
#  - Render a PDF with the updated CSS spacing and image inlining
#  - Save debug artifacts under converted_files/debug/

MSG_DEFAULT="[External] RE_ Notice of Availability for the Draft EIR for the Starlight Solar Project (PDS2022-MUP-22-010) (2).msg"
MSG_PATH="${1:-$MSG_DEFAULT}"

if [[ ! -f "$MSG_PATH" ]]; then
  echo "❌ MSG file not found: $MSG_PATH"
  echo "Usage: $0 \"/path/to/file.msg\""
  exit 1
fi

echo "📦 Ensuring Playwright Chromium is installed..."
python3 -m playwright install chromium >/dev/null 2>&1 || true

echo "🔧 Converting MSG locally: $MSG_PATH"
python3 - << 'PY'
import sys, os, re, json, email
from email.policy import default
sys.path.insert(0, 'backend')
from lambda_function import convert_msg_bytes_to_eml_bytes, extract_body_and_images_from_email, convert_eml_to_pdf

base_dir = os.getcwd()
dbg_dir = os.path.join(base_dir, 'converted_files', 'debug')
os.makedirs(dbg_dir, exist_ok=True)

msg_path = os.environ.get('MSG_PATH', '')
if not msg_path:
    msg_path = "[External] RE_ Notice of Availability for the Draft EIR for the Starlight Solar Project (PDS2022-MUP-22-010) (2).msg"

summary = {"cwd": base_dir, "msg_path": msg_path, "msg_exists": os.path.exists(msg_path)}

try:
    with open(msg_path, 'rb') as f:
        msg_bytes = f.read()

    # .msg -> .eml bytes
    eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)
    eml_path = os.path.join(dbg_dir, 'debug_msg.eml')
    with open(eml_path, 'wb') as f:
        f.write(eml_bytes)
    summary["eml_path"] = eml_path
    summary["eml_size"] = len(eml_bytes)

    # Parse + extract (images + cleaning + VML/CSS url fixes happen here)
    msg = email.message_from_bytes(eml_bytes, policy=default)
    body, images, attachments = extract_body_and_images_from_email(msg)
    summary["body_len"] = len(body)
    summary["images_keys"] = len(images)
    summary["has_data_urls_in_body"] = ("data:image" in body)

    # Snapshot HTML
    html_doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><style>
body {{ font-family: Arial, sans-serif; line-height: 1.35; }}
p {{ margin: 0 0 8px; }} li {{ margin: 0 0 4px; }}
img {{ max-width:100%; height:auto; display:block; margin:8px 0; }}
</style></head><body>{body}</body></html>"""
    html_path = os.path.join(dbg_dir, 'debug_msg.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_doc)
    summary["html_path"] = html_path

    # Render PDF
    pdf_path = os.path.join(dbg_dir, 'output.pdf')
    ok = convert_eml_to_pdf(eml_bytes, pdf_path)
    summary["pdf_ok"] = bool(ok)
    summary["pdf_exists"] = os.path.exists(pdf_path)
    summary["pdf_path"] = pdf_path
    summary["pdf_size"] = os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0
    if os.path.exists(pdf_path):
        with open(pdf_path, 'rb') as pf:
            data = pf.read()
        summary["pdf_image_objects"] = int(data.count(b'/Image'))

    # Short preview for logging
    preview = re.sub(r'<[^>]+>', '', body or '')
    summary["body_preview"] = preview[:300]

except Exception as e:
    summary["error"] = str(e)

sum_path = os.path.join(dbg_dir, 'debug_summary.json')
with open(sum_path, 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2)

print(json.dumps(summary, indent=2))
PY
