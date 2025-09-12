#!/bin/zsh
set -euo pipefail

# Convenience wrapper to test the large "FW_ Starlight Comment from JCSG.eml" file
# Usage:
#   ./test_starlight_eml.sh                    # uses default CloudFront base (or CF_API_BASE)
#   CF_API_BASE=https://yourdist.cloudfront.net/api ./test_starlight_eml.sh
#   ./test_starlight_eml.sh http://localhost:5002   # test against local server (no /api path)
#
# Optional env: APP_PASSWORD (or pass inside convert_single_eml.sh)

FILE_PATH="test_eml/FW_ Starlight Comment from JCSG.eml"
if [ ! -f "$FILE_PATH" ]; then
  echo "❌ Expected file not found: $FILE_PATH" >&2
  exit 1
fi

BASE_OVERRIDE="${1:-}"  # allow first arg to override base
PASS="${APP_PASSWORD:-mysecretpassword}"  # fall back to known password if set in prod

if [ -n "$BASE_OVERRIDE" ]; then
  BASE="$BASE_OVERRIDE"
else
  BASE="${CF_API_BASE:-https://d2a79jfkoxjkg0.cloudfront.net/api}"  # default prod CF
fi

echo "🔧 Using base: $BASE"
echo "📄 Testing file: $FILE_PATH"

chmod +x convert_single_eml.sh 2>/dev/null || true
./convert_single_eml.sh "$FILE_PATH" "$PASS" "$BASE"
