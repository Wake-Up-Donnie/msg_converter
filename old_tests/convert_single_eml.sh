#!/bin/zsh
# Purpose: Convert a single .eml file through the running API (local or CloudFront) and download the PDF.
# Usage:
#   ./convert_single_eml.sh /absolute/path/to/email.eml [password] [api_base_url]
# Examples:
#   ./convert_single_eml.sh test_eml/"FW_ Starlight Comment from JCSG.eml" mysecretpassword https://d347djbmbuiexy.cloudfront.net/api
#   ./convert_single_eml.sh test1.eml               # (if auth not required locally)

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 /path/to/file.eml [password] [api_base_url]" >&2
  exit 1
fi

FILE="$1"
PASS="${2:-${APP_PASSWORD:-}}"
# Default base prefers CloudFront style if env CF_API_BASE set, otherwise CloudFront
BASE="${3:-${CF_API_BASE:-}}"
if [ -z "$BASE" ]; then
  # Default to CloudFront API for AWS testing
  BASE="https://d2a79jfkoxjkg0.cloudfront.net/api"
fi

# Normalize base (strip trailing /)
BASE=${BASE%/}

# Decide endpoint form: if base already ends with /api use directly, else append /convert properly
if [[ "$BASE" == *"/api" ]]; then
  CONVERT_URL="$BASE/convert"
  DOWNLOAD_PREFIX="$BASE/download"
else
  # Local style (no /api) endpoints
  CONVERT_URL="$BASE/convert"
  DOWNLOAD_PREFIX="$BASE/download"
fi

if [ ! -f "$FILE" ]; then
  echo "File not found: $FILE" >&2
  exit 1
fi

if [[ "${FILE:l}" != *.eml ]]; then
  echo "Warning: File does not have .eml extension (continuing)" >&2
fi

echo "📧 Converting: $FILE"
echo "🔗 API: $CONVERT_URL"
if [ -n "$PASS" ]; then
  echo "🔐 Using password auth"
else
  echo "ℹ️  No password supplied (assuming endpoint does not require auth)"
fi

TMP_RESP=$(mktemp)
AUTH_QS=""
HEADERS=()
if [ -n "$PASS" ]; then
  AUTH_QS="?auth=$PASS"
  HEADERS+=( -H "X-App-Password: $PASS" -H "Authorization: Bearer $PASS" )
fi

echo "🚀 Uploading file..."
if ! curl -sS -D /dev/stderr "${HEADERS[@]}" \
  -F "file=@${FILE}" \
  "$CONVERT_URL$AUTH_QS" -o "$TMP_RESP"; then
  echo "❌ Upload/convert request failed" >&2
  cat "$TMP_RESP" >&2 || true
  rm -f "$TMP_RESP"
  exit 1
fi

echo "🧾 Raw response:" >&2
cat "$TMP_RESP" >&2

# Extract session_id and filename robustly
SESSION_ID=""
PDF_FILE=""
if command -v jq >/dev/null 2>&1; then
  SESSION_ID=$(jq -r '.session_id // empty' "$TMP_RESP")
  PDF_FILE=$(jq -r '.filename // .results[0].pdf_filename // empty' "$TMP_RESP")
else
  # Fallback parsing (best effort)
  SESSION_ID=$(grep -oE '"session_id"\s*:\s*"[^"]+"' "$TMP_RESP" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
  PDF_FILE=$(grep -oE '"filename"\s*:\s*"[^"]+"' "$TMP_RESP" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
fi

if [ -z "$SESSION_ID" ] || [ -z "$PDF_FILE" ]; then
  echo "❌ Could not extract session_id or filename from response" >&2
  rm -f "$TMP_RESP"
  exit 1
fi

echo "✅ Parsed session_id=$SESSION_ID filename=$PDF_FILE"

# URL encode filename (prefer Python; fix argument passing bug)
if command -v python3 >/dev/null 2>&1; then
  ENC_FILE=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1], safe=''))" "$PDF_FILE") || {
    echo "⚠️  Python URL encoding failed, falling back to basic encoding" >&2
    ENC_FILE=${PDF_FILE// /%20}
  }
else
  ENC_FILE=${PDF_FILE// /%20}
fi

DL_URL="$DOWNLOAD_PREFIX/$SESSION_ID/$ENC_FILE"
if [ -n "$PASS" ]; then
  if [[ "$DL_URL" == *"?"* ]]; then
    DL_URL="$DL_URL&auth=$PASS"
  else
    DL_URL="$DL_URL?auth=$PASS"
  fi
fi

OUT_FILE="converted_${PDF_FILE}"
echo "⬇️  Downloading PDF -> $OUT_FILE"
if ! curl -sS -L -D /dev/stderr "$DL_URL" -o "$OUT_FILE"; then
  echo "❌ Download failed" >&2
  rm -f "$TMP_RESP"
  exit 1
fi

SIZE=$(wc -c < "$OUT_FILE" | tr -d ' ')
echo "📦 PDF size: ${SIZE} bytes"
echo -n "🔍 Magic bytes: "; head -c 5 "$OUT_FILE"; echo

if [ "$SIZE" -lt 1024 ]; then
  echo "⚠️  PDF is unusually small; may be fallback or error content." >&2
fi

echo "🎉 Done. PDF saved as $OUT_FILE"
rm -f "$TMP_RESP"
