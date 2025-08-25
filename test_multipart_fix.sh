#!/bin/bash

echo "Testing multipart file upload fix..."
echo "=================================="

# Use one of our test EML files
EML_FILE="test1.eml"

if [ ! -f "$EML_FILE" ]; then
    echo "Error: Test file $EML_FILE not found"
    exit 1
fi

echo "Testing with file: $EML_FILE"
echo "File size: $(wc -c < "$EML_FILE") bytes"
echo ""

# Test the CloudFront API endpoint
API_URL="https://d347djbmbuiexy.cloudfront.net/api/convert"
PASSWORD="mysecretpassword"

echo "Testing CloudFront API endpoint: $API_URL"
echo "Using password authentication..."
echo ""

# Make the curl request with proper multipart form data
curl -X POST \
  -H "X-App-Password: $PASSWORD" \
  -H "Authorization: Bearer $PASSWORD" \
  -F "file=@$EML_FILE" \
  "$API_URL?auth=$PASSWORD" \
  --verbose \
  --show-error \
  --fail-with-body

echo ""
echo ""
echo "Test completed. Check the response above for any 'No file provided' errors."
